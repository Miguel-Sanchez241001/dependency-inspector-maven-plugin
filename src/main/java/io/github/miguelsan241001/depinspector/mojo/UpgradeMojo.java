package io.github.miguelsan241001.depinspector.mojo;

import io.github.miguelsan241001.depinspector.model.*;
import io.github.miguelsan241001.depinspector.model.CompatibilityStatus;
import io.github.miguelsan241001.depinspector.report.HtmlReportGenerator;
import io.github.miguelsan241001.depinspector.service.*;
import io.github.miguelsan241001.depinspector.util.HttpClientFactory;
import okhttp3.OkHttpClient;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.*;
import org.apache.maven.project.MavenProject;
import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.repository.RemoteRepository;

import java.io.File;
import java.util.*;
import java.util.stream.Collectors;

@Mojo(
    name = "upgrade",
    requiresProject = true,
    requiresDependencyResolution = ResolutionScope.TEST
)
public class UpgradeMojo extends AbstractMojo {

    @Parameter(defaultValue = "${project}", readonly = true, required = true)
    private MavenProject project;

    @Component
    private RepositorySystem repoSystem;

    @Parameter(defaultValue = "${repositorySystemSession}", readonly = true)
    private RepositorySystemSession repoSession;

    @Parameter(defaultValue = "${project.remoteProjectRepositories}", readonly = true)
    private List<RemoteRepository> remoteRepositories;

    @Parameter(property = "skipSslVerification", defaultValue = "false")
    private boolean skipSslVerification;

    @Parameter(property = "outputDirectory", defaultValue = "${project.build.directory}/dependency-inspector")
    private File outputDirectory;

    @Parameter(property = "dryRun", defaultValue = "false")
    private boolean dryRun;

    @Parameter(property = "artifact")
    private String artifact; // optional: "groupId:artifactId"

    @Parameter(property = "interactive", defaultValue = "false")
    private boolean interactive;

    @Override
    public void execute() {
        try {
            doExecute();
        } catch (MojoExecutionException e) {
            getLog().error(e.getMessage());
        } catch (Exception e) {
            getLog().error("Unexpected error during upgrade: " + e.getMessage(), e);
        }
    }

    void doExecute() throws Exception {
        getLog().info("Starting dependency upgrade" + (dryRun ? " (DRY RUN)" : "") +
                      (interactive ? " (INTERACTIVE)" : "") + "...");

        OkHttpClient httpClient = HttpClientFactory.create(skipSslVerification);
        OsvClient osvClient = new OsvClient(httpClient, getLog());
        VersionResolver versionResolver = new VersionResolver(httpClient, osvClient, getLog());
        CompatibilityChecker compatChecker = new CompatibilityChecker(
                repoSystem, repoSession, remoteRepositories, getLog());
        HtmlReportGenerator reportGenerator = new HtmlReportGenerator(getLog());
        PomModifier pomModifier = new PomModifier(getLog());

        // 1. Run full analysis
        DependencyCollector collector = new DependencyCollector(project, getLog());
        List<DependencyInfo> dependencies = collector.collect();

        getLog().info("Querying OSV.dev for " + dependencies.size() + " dependencies...");
        Map<DependencyInfo, List<VulnerabilityInfo>> osvResults = osvClient.queryBatch(dependencies);

        List<AnalysisResult> results = new ArrayList<>();
        for (DependencyInfo dep : dependencies) {
            List<VulnerabilityInfo> vulns = osvResults.getOrDefault(dep, Collections.emptyList());
            AnalysisResult result = new AnalysisResult(dep);
            result.setVulnerabilities(vulns);

            if (!vulns.isEmpty()) {
                UpgradeRecommendation rec = versionResolver.resolve(dep);
                if (rec != null && rec.isAutomaticUpgrade() && rec.getTargetVersion() != null) {
                    CompatibilityStatus status = compatChecker.checkCompatibility(
                            dep.getGroupId(), dep.getArtifactId(),
                            dep.getVersion(), rec.getTargetVersion());
                    rec.setCompatibilityStatus(status);
                }
                result.setRecommendation(rec);
            }
            results.add(result);
        }

        // 2. Scan usages
        UsageScanner usageScanner = new UsageScanner(project.getBasedir(), getLog());
        usageScanner.scan(results);

        // 3. Filter vulnerable deps with some action available
        List<AnalysisResult> vulnerable = results.stream()
                .filter(AnalysisResult::isVulnerable)
                .collect(Collectors.toList());

        // 4. Filter by artifact if specified
        if (artifact != null && !artifact.isBlank()) {
            String[] parts = artifact.split(":");
            if (parts.length == 2) {
                final String fg = parts[0], fa = parts[1];
                vulnerable = vulnerable.stream()
                        .filter(r -> fg.equals(r.getDependency().getGroupId()) &&
                                     fa.equals(r.getDependency().getArtifactId()))
                        .collect(Collectors.toList());
            } else {
                getLog().warn("Invalid artifact filter: expected groupId:artifactId, got: " + artifact);
            }
        }

        if (vulnerable.isEmpty()) {
            getLog().info("No vulnerable dependencies found — nothing to upgrade.");
            return;
        }

        // 5. Determine which deps need interactive prompt
        // Interactive mode: ask for ALL
        // Non-interactive: ask only for HIGH_RISK (UPGRADE_MAJOR, ALTERNATIVE_LIB)
        List<AnalysisResult> toAsk = new ArrayList<>();
        List<AnalysisResult> autoUpgrade = new ArrayList<>();

        for (AnalysisResult r : vulnerable) {
            UpgradeRecommendation rec = r.getRecommendation();
            boolean isHighRisk = rec != null && (
                    rec.getStrategy() == UpgradeRecommendation.Strategy.UPGRADE_MAJOR ||
                    rec.getStrategy() == UpgradeRecommendation.Strategy.ALTERNATIVE_LIB);

            if (interactive || isHighRisk) {
                toAsk.add(r);
            } else if (rec != null && rec.isAutomaticUpgrade() && rec.getTargetVersion() != null) {
                autoUpgrade.add(r);
            }
        }

        // 6. Dry run: print proposed actions
        if (dryRun) {
            getLog().info("Dry run — proposed automatic upgrades:");
            for (AnalysisResult r : autoUpgrade) {
                UpgradeRecommendation rec = r.getRecommendation();
                getLog().info("  " + r.getDependency().getCoordinates() +
                        " -> " + rec.getTargetVersion() +
                        " [" + rec.getStrategy() + "]" +
                        " compat=" + rec.getCompatibilityStatus());
            }
            if (!toAsk.isEmpty()) {
                getLog().info("Dry run — would prompt for " + toAsk.size() + " high-risk dep(s):");
                for (AnalysisResult r : toAsk) {
                    getLog().info("  " + r.getDependency().getCoordinates());
                }
            }
            return;
        }

        // 7. Apply automatic upgrades (PATCH/MINOR, non-interactive)
        int applied = 0;
        int excluded = 0;
        int skipped = 0;

        if (!autoUpgrade.isEmpty()) {
            File pomFile = project.getFile();
            if (applied == 0) pomModifier.backup(pomFile, outputDirectory);
            List<UpgradeRecommendation> recs = autoUpgrade.stream()
                    .map(AnalysisResult::getRecommendation)
                    .collect(Collectors.toList());
            applied += pomModifier.apply(pomFile, recs);
        }

        // 8. Handle interactive / high-risk deps
        if (!toAsk.isEmpty()) {
            File pomFile = project.getFile();
            boolean backedUp = applied > 0; // backup may already exist

            InteractiveConsole console = new InteractiveConsole(getLog());
            try {
                int idx = 1;
                for (AnalysisResult r : toAsk) {
                    DependencyInfo dep = r.getDependency();
                    boolean canExclude = dep.getTransitiveOrigin() != null ||
                            dep.getType() == DependencyInfo.DependencyType.TRANSITIVE;

                    InteractiveDecision decision = console.ask(r, idx++, toAsk.size(), canExclude);

                    switch (decision) {
                        case UPGRADE:
                            UpgradeRecommendation rec = r.getRecommendation();
                            if (rec != null && rec.getTargetVersion() != null) {
                                if (!backedUp) {
                                    pomModifier.backup(pomFile, outputDirectory);
                                    backedUp = true;
                                }
                                int cnt = pomModifier.apply(pomFile, List.of(rec));
                                applied += cnt;
                                if (cnt == 0) {
                                    getLog().warn("Could not apply upgrade for " + dep.getCoordinates() +
                                            " — may need manual update");
                                }
                            } else {
                                getLog().warn("No target version available for " + dep.getCoordinates() +
                                        " — skipping upgrade");
                                skipped++;
                            }
                            break;

                        case EXCLUDE:
                            if (!backedUp) {
                                pomModifier.backup(pomFile, outputDirectory);
                                backedUp = true;
                            }
                            boolean ok = pomModifier.applyExclusions(pomFile, dep, dep.getTransitiveOrigin());
                            if (ok) excluded++;
                            else {
                                getLog().warn("Could not apply exclusion for " + dep.getCoordinates());
                                skipped++;
                            }
                            break;

                        case SKIP:
                        default:
                            skipped++;
                            getLog().info("Skipped: " + dep.getCoordinates());
                            break;
                    }
                }
            } finally {
                console.close();
            }
        }

        // 9. Generate updated report
        AnalysisReport report = new AnalysisReport(
                project.getArtifactId(), project.getVersion(), results);
        reportGenerator.generate(report, outputDirectory);

        long manual = vulnerable.stream()
                .filter(r -> r.getRecommendation() != null && !r.getRecommendation().isAutomaticUpgrade())
                .filter(r -> !toAsk.contains(r))
                .count();

        getLog().info("============================================");
        getLog().info("Upgrade Summary");
        getLog().info("  Applied upgrades:   " + applied);
        getLog().info("  Exclusions added:   " + excluded);
        getLog().info("  Skipped:            " + skipped);
        getLog().info("  Require manual:     " + manual);
        if (applied > 0 || excluded > 0) {
            getLog().info("  POM backup at:    " + new File(outputDirectory, "pom.xml.bak").getAbsolutePath());
        }
        getLog().info("============================================");
    }
}
