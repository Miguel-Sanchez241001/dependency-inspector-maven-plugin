package io.github.miguelsan241001.depinspector.application;

import io.github.miguelsan241001.depinspector.adapter.scanner.JavaSourceUsageAdapter;
import io.github.miguelsan241001.depinspector.domain.model.*;
import io.github.miguelsan241001.depinspector.domain.port.*;
import io.github.miguelsan241001.depinspector.domain.service.ImpactCalculator;
import io.github.miguelsan241001.depinspector.domain.service.UpgradeDecisionService;
import io.github.miguelsan241001.depinspector.model.CompatibilityStatus;
import io.github.miguelsan241001.depinspector.model.ScopeIssue;
import io.github.miguelsan241001.depinspector.model.UpgradeRecommendation;
import io.github.miguelsan241001.depinspector.service.ScopeAnalyzer;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.logging.Log;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Orchestrates a full dependency analysis: build graph → find vulns →
 * resolve upgrades → check compatibility → scan usages → calculate impact.
 *
 * <p>All framework dependencies are hidden behind ports; this class
 * is pure application logic.</p>
 */
public class AnalyzeDependenciesUseCase {

    private final DependencySource depSource;
    private final VulnerabilitySource vulnSource;
    private final VersionSource versionSource;
    private final CompatibilitySource compatSource;
    private final JavaSourceUsageAdapter usageAdapter;
    private final ScopeAnalyzer scopeAnalyzer;
    private final ImpactCalculator impactCalculator;
    private final UpgradeDecisionService upgradeDecision;
    private final Log log;

    public AnalyzeDependenciesUseCase(DependencySource depSource,
                                       VulnerabilitySource vulnSource,
                                       VersionSource versionSource,
                                       CompatibilitySource compatSource,
                                       JavaSourceUsageAdapter usageAdapter,
                                       ScopeAnalyzer scopeAnalyzer,
                                       Log log) {
        this.depSource        = depSource;
        this.vulnSource       = vulnSource;
        this.versionSource    = versionSource;
        this.compatSource     = compatSource;
        this.usageAdapter     = usageAdapter;
        this.scopeAnalyzer    = scopeAnalyzer;
        this.impactCalculator = new ImpactCalculator();
        this.upgradeDecision  = new UpgradeDecisionService(versionSource, vulnSource);
        this.log              = log;
    }

    public DependencyAnalysisReport execute(AnalysisContext ctx) throws MojoExecutionException {
        // 1. Build dependency graph
        DependencyGraph graph = depSource.buildGraph();
        List<Dependency> allDeps = graph.getAllDependencies().stream()
                .map(DependencyNode::getDependency)
                .collect(Collectors.toList());

        // 2. Apply exclusions
        Set<String> excluded = ctx.getExcludeArtifacts();
        List<Dependency> toAnalyze = allDeps.stream()
                .filter(d -> !excluded.contains(d.ga()))
                .collect(Collectors.toList());

        if (!excluded.isEmpty()) {
            log.info("Excluding " + (allDeps.size() - toAnalyze.size()) +
                    " artifact(s) per excludeArtifacts config.");
        }

        // 3. Query vulnerabilities
        log.info("Querying OSV.dev for " + toAnalyze.size() + " dependencies...");
        Map<Dependency, List<Vulnerability>> vulnMap = vulnSource.findVulnerabilities(toAnalyze);

        // 4. Apply minCvss filter
        double minCvss = ctx.getMinCvss();
        if (minCvss > 0) {
            vulnMap = vulnMap.entrySet().stream()
                    .collect(Collectors.toMap(
                            Map.Entry::getKey,
                            e -> e.getValue().stream()
                                    .filter(v -> !v.hasCvssScore() || v.getCvssScore() >= minCvss)
                                    .collect(Collectors.toList()),
                            (a, b) -> a,
                            LinkedHashMap::new));
        }

        // 5. Resolve upgrades + compatibility for vulnerable deps
        Map<Dependency, UpgradeRecommendation> recommendations = new LinkedHashMap<>();
        for (Map.Entry<Dependency, List<Vulnerability>> entry : vulnMap.entrySet()) {
            if (entry.getValue().isEmpty()) continue;
            Dependency dep = entry.getKey();

            UpgradeRecommendation rec = upgradeDecision.resolve(dep);
            if (rec != null && rec.isAutomaticUpgrade() && rec.getTargetVersion() != null) {
                Dependency target = dep.withVersion(rec.getTargetVersion());
                CompatibilityStatus status = compatSource.check(dep, target);
                rec.setCompatibilityStatus(status);
            }
            if (rec != null) recommendations.put(dep, rec);
        }

        // 6. Scan usages
        Map<Dependency, List<Usage>> usageMap = new LinkedHashMap<>();
        for (Dependency dep : toAnalyze) {
            List<Usage> depUsages = usageAdapter.findUsages(dep);
            if (!depUsages.isEmpty()) usageMap.put(dep, depUsages);
        }

        // 7. Calculate impact for vulnerable deps
        Map<Dependency, Impact> impactMap = new LinkedHashMap<>();
        for (Dependency dep : getVulnerableDeps(vulnMap)) {
            Optional<DependencyNode> nodeOpt =
                    graph.findByCoordinates(dep.getGroupId(), dep.getArtifactId());
            if (nodeOpt.isPresent()) {
                List<Usage> depUsages = usageMap.getOrDefault(dep, Collections.emptyList());
                Impact impact = impactCalculator.calculate(nodeOpt.get(), graph, depUsages);
                impactMap.put(dep, impact);
            }
        }

        // 8. Detect scope issues (using old model for compat with ScopeAnalyzer)
        List<io.github.miguelsan241001.depinspector.model.DependencyInfo> depInfos =
                toAnalyze.stream().map(this::toDependencyInfo).collect(Collectors.toList());
        List<ScopeIssue> scopeIssues = scopeAnalyzer.analyze(depInfos);
        if (!scopeIssues.isEmpty()) {
            log.warn(scopeIssues.size() + " scope issue(s) detected.");
        }

        return DependencyAnalysisReport.builder()
                .projectArtifactId(ctx.getProjectArtifactId())
                .projectVersion(ctx.getProjectVersion())
                .graph(graph)
                .vulnerabilities(vulnMap)
                .impacts(impactMap)
                .recommendations(recommendations)
                .usages(usageMap)
                .scopeIssues(scopeIssues)
                .build();
    }

    private List<Dependency> getVulnerableDeps(Map<Dependency, List<Vulnerability>> vulnMap) {
        return vulnMap.entrySet().stream()
                .filter(e -> !e.getValue().isEmpty())
                .map(Map.Entry::getKey)
                .collect(Collectors.toList());
    }

    private io.github.miguelsan241001.depinspector.model.DependencyInfo toDependencyInfo(Dependency dep) {
        io.github.miguelsan241001.depinspector.model.DependencyInfo info =
                new io.github.miguelsan241001.depinspector.model.DependencyInfo(
                        dep.getGroupId(), dep.getArtifactId(), dep.getVersion(), dep.getScope(),
                        io.github.miguelsan241001.depinspector.model.DependencyInfo.DependencyType
                                .valueOf(dep.getType().name()));
        if (dep.getResolvedJar() != null) info.setJarFile(dep.getResolvedJar());
        return info;
    }
}
