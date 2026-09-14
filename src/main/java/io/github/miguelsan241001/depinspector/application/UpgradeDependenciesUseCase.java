package io.github.miguelsan241001.depinspector.application;

import io.github.miguelsan241001.depinspector.adapter.scanner.JavaSourceUsageAdapter;
import io.github.miguelsan241001.depinspector.domain.model.*;
import io.github.miguelsan241001.depinspector.domain.port.*;
import io.github.miguelsan241001.depinspector.domain.service.UpgradeDecisionService;
import io.github.miguelsan241001.depinspector.model.CompatibilityStatus;
import io.github.miguelsan241001.depinspector.model.UpgradeRecommendation;
import io.github.miguelsan241001.depinspector.service.*;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.logging.Log;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Orchestrates the upgrade workflow: analyse → decide → apply (or dry-run).
 */
public class UpgradeDependenciesUseCase {

    private final DependencySource depSource;
    private final VulnerabilitySource vulnSource;
    private final VersionSource versionSource;
    private final CompatibilitySource compatSource;
    private final JavaSourceUsageAdapter usageAdapter;
    private final PomModifier pomModifier;
    private final InteractiveConsole console;
    private final UpgradeDecisionService upgradeDecision;
    private final Log log;

    public UpgradeDependenciesUseCase(DependencySource depSource,
                                       VulnerabilitySource vulnSource,
                                       VersionSource versionSource,
                                       CompatibilitySource compatSource,
                                       JavaSourceUsageAdapter usageAdapter,
                                       PomModifier pomModifier,
                                       InteractiveConsole console,
                                       Log log) {
        this.depSource       = depSource;
        this.vulnSource      = vulnSource;
        this.versionSource   = versionSource;
        this.compatSource    = compatSource;
        this.usageAdapter    = usageAdapter;
        this.pomModifier     = pomModifier;
        this.console         = console;
        this.upgradeDecision = new UpgradeDecisionService(versionSource, vulnSource);
        this.log             = log;
    }

    /**
     * Runs the upgrade workflow and returns a summary report.
     *
     * @param ctx      upgrade parameters
     * @param pomFile  the project's pom.xml to modify (if not dry-run)
     */
    public DependencyAnalysisReport execute(UpgradeContext ctx, java.io.File pomFile)
            throws MojoExecutionException, java.io.IOException {

        DependencyGraph graph = depSource.buildGraph();
        List<Dependency> allDeps = graph.getAllDependencies().stream()
                .map(DependencyNode::getDependency)
                .collect(Collectors.toList());

        log.info("Querying OSV.dev for " + allDeps.size() + " dependencies...");
        Map<Dependency, List<Vulnerability>> vulnMap = vulnSource.findVulnerabilities(allDeps);

        // Resolve upgrade recommendations
        Map<Dependency, UpgradeRecommendation> recommendations = new LinkedHashMap<>();
        List<Dependency> vulnerable = new ArrayList<>();

        for (Map.Entry<Dependency, List<Vulnerability>> entry : vulnMap.entrySet()) {
            if (entry.getValue().isEmpty()) continue;
            Dependency dep = entry.getKey();
            vulnerable.add(dep);

            UpgradeRecommendation rec = upgradeDecision.resolve(dep);
            if (rec != null && rec.isAutomaticUpgrade() && rec.getTargetVersion() != null) {
                Dependency target = dep.withVersion(rec.getTargetVersion());
                CompatibilityStatus status = compatSource.check(dep, target);
                rec.setCompatibilityStatus(status);
            }
            if (rec != null) recommendations.put(dep, rec);
        }

        // Filter by artifact if specified
        String filter = ctx.getArtifactFilter();
        if (filter != null && !filter.isBlank()) {
            String[] parts = filter.split(":");
            if (parts.length == 2) {
                final String fg = parts[0], fa = parts[1];
                vulnerable = vulnerable.stream()
                        .filter(d -> fg.equals(d.getGroupId()) && fa.equals(d.getArtifactId()))
                        .collect(Collectors.toList());
            } else {
                log.warn("Invalid artifact filter: " + filter + " — expected groupId:artifactId");
            }
        }

        if (vulnerable.isEmpty()) {
            log.info("No vulnerable dependencies found — nothing to upgrade.");
            return buildReport(graph, vulnMap, recommendations, ctx);
        }

        // Separate auto vs interactive
        List<Dependency> autoUpgrade   = new ArrayList<>();
        List<Dependency> interactiveList = new ArrayList<>();
        for (Dependency dep : vulnerable) {
            UpgradeRecommendation rec = recommendations.get(dep);
            boolean highRisk = rec != null && (
                    rec.getStrategy() == UpgradeRecommendation.Strategy.UPGRADE_MAJOR ||
                    rec.getStrategy() == UpgradeRecommendation.Strategy.ALTERNATIVE_LIB);
            if (ctx.isInteractive() || highRisk) interactiveList.add(dep);
            else if (rec != null && rec.isAutomaticUpgrade() && rec.getTargetVersion() != null) autoUpgrade.add(dep);
        }

        if (ctx.isDryRun()) {
            log.info("Dry run — proposed automatic upgrades:");
            for (Dependency dep : autoUpgrade) {
                UpgradeRecommendation rec = recommendations.get(dep);
                log.info("  " + dep.coordinates() + " -> " + rec.getTargetVersion() +
                        " [" + rec.getStrategy() + "] compat=" + rec.getCompatibilityStatus());
            }
            if (!interactiveList.isEmpty()) {
                log.info("Dry run — would prompt for " + interactiveList.size() + " high-risk dep(s).");
            }
            return buildReport(graph, vulnMap, recommendations, ctx);
        }

        // Apply automatic upgrades
        int applied = 0, excluded = 0, skipped = 0;
        boolean backedUp = false;
        if (!autoUpgrade.isEmpty()) {
            pomModifier.backup(pomFile, ctx.getOutputDirectory());
            backedUp = true;
            List<UpgradeRecommendation> recs = autoUpgrade.stream()
                    .map(recommendations::get).collect(Collectors.toList());
            applied += pomModifier.apply(pomFile, recs);
        }

        // Interactive / high-risk deps
        if (!interactiveList.isEmpty() && console != null) {
            try {
                int idx = 1;
                for (Dependency dep : interactiveList) {
                    io.github.miguelsan241001.depinspector.model.AnalysisResult legacyResult =
                            buildLegacyResult(dep, vulnMap.get(dep), recommendations.get(dep));
                    boolean canExclude = dep.getType() == DependencyType.TRANSITIVE;
                    InteractiveDecision decision = console.ask(legacyResult, idx++, interactiveList.size(), canExclude);

                    switch (decision) {
                        case UPGRADE: {
                            UpgradeRecommendation rec = recommendations.get(dep);
                            if (rec != null && rec.getTargetVersion() != null) {
                                if (!backedUp) { pomModifier.backup(pomFile, ctx.getOutputDirectory()); backedUp = true; }
                                int cnt = pomModifier.apply(pomFile, Collections.singletonList(rec));
                                applied += cnt;
                                if (cnt == 0) log.warn("Could not apply upgrade for " + dep.coordinates());
                            } else { skipped++; }
                            break;
                        }
                        case EXCLUDE: {
                            if (!backedUp) { pomModifier.backup(pomFile, ctx.getOutputDirectory()); backedUp = true; }
                            io.github.miguelsan241001.depinspector.model.DependencyInfo depInfo = toDependencyInfo(dep);
                            boolean ok = pomModifier.applyExclusions(pomFile, depInfo, depInfo.getTransitiveOrigin());
                            if (ok) excluded++; else { log.warn("Could not apply exclusion for " + dep.coordinates()); skipped++; }
                            break;
                        }
                        default: skipped++; log.info("Skipped: " + dep.coordinates()); break;
                    }
                }
            } finally {
                if (console != null) console.close();
            }
        }

        long manual = vulnerable.stream()
                .filter(d -> { UpgradeRecommendation r = recommendations.get(d); return r != null && !r.isAutomaticUpgrade(); })
                .filter(d -> !interactiveList.contains(d))
                .count();

        log.info("============================================");
        log.info("Upgrade Summary");
        log.info("  Applied upgrades: " + applied);
        log.info("  Exclusions added: " + excluded);
        log.info("  Skipped:          " + skipped);
        log.info("  Require manual:   " + manual);
        log.info("============================================");

        return buildReport(graph, vulnMap, recommendations, ctx);
    }

    private DependencyAnalysisReport buildReport(DependencyGraph graph,
                                                   Map<Dependency, List<Vulnerability>> vulnMap,
                                                   Map<Dependency, UpgradeRecommendation> recs,
                                                   UpgradeContext ctx) {
        return DependencyAnalysisReport.builder()
                .graph(graph)
                .vulnerabilities(vulnMap)
                .recommendations(recs)
                .build();
    }

    private io.github.miguelsan241001.depinspector.model.AnalysisResult buildLegacyResult(
            Dependency dep,
            List<Vulnerability> vulns,
            UpgradeRecommendation rec) {
        io.github.miguelsan241001.depinspector.model.AnalysisResult r =
                new io.github.miguelsan241001.depinspector.model.AnalysisResult(toDependencyInfo(dep));
        if (vulns != null) {
            List<io.github.miguelsan241001.depinspector.model.VulnerabilityInfo> legacyVulns = new ArrayList<>();
            for (Vulnerability v : vulns) {
                io.github.miguelsan241001.depinspector.model.VulnerabilityInfo vi =
                        new io.github.miguelsan241001.depinspector.model.VulnerabilityInfo();
                vi.setId(v.getId());
                vi.setSummary(v.getSummary());
                vi.setCvssScore(v.getCvssScore());
                vi.setSeverity(io.github.miguelsan241001.depinspector.model.VulnerabilityInfo.Severity
                        .valueOf(v.getSeverity().name()));
                vi.setAliases(v.getAliases());
                legacyVulns.add(vi);
            }
            r.setVulnerabilities(legacyVulns);
        }
        r.setRecommendation(rec);
        return r;
    }

    private io.github.miguelsan241001.depinspector.model.DependencyInfo toDependencyInfo(Dependency dep) {
        io.github.miguelsan241001.depinspector.model.DependencyInfo info =
                new io.github.miguelsan241001.depinspector.model.DependencyInfo(
                        dep.getGroupId(), dep.getArtifactId(), dep.getVersion(), dep.getScope(),
                        io.github.miguelsan241001.depinspector.model.DependencyInfo.DependencyType
                                .valueOf(dep.getType().name()));
        return info;
    }
}
