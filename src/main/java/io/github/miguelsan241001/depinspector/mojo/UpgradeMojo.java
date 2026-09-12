package io.github.miguelsan241001.depinspector.mojo;

import io.github.miguelsan241001.depinspector.model.*;
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
        getLog().info("Starting dependency upgrade" + (dryRun ? " (DRY RUN)" : "") + "...");

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
                    boolean breaking = compatChecker.hasBreakingChanges(
                            dep.getGroupId(), dep.getArtifactId(),
                            dep.getVersion(), rec.getTargetVersion());
                    rec.setHasBreakingChanges(breaking);
                }
                result.setRecommendation(rec);
            }
            results.add(result);
        }

        // 2. Filter to automatic upgrades only
        List<UpgradeRecommendation> upgrades = results.stream()
                .filter(AnalysisResult::isVulnerable)
                .map(AnalysisResult::getRecommendation)
                .filter(r -> r != null && r.isAutomaticUpgrade() && r.getTargetVersion() != null)
                .collect(Collectors.toList());

        // 3. Filter by artifact if specified
        if (artifact != null && !artifact.isBlank()) {
            String[] parts = artifact.split(":");
            if (parts.length == 2) {
                final String filterGroup = parts[0];
                final String filterArtifact = parts[1];
                upgrades = upgrades.stream()
                        .filter(r -> filterGroup.equals(r.getDependency().getGroupId()) &&
                                     filterArtifact.equals(r.getDependency().getArtifactId()))
                        .collect(Collectors.toList());
            } else {
                getLog().warn("Invalid artifact filter format. Expected groupId:artifactId, got: " + artifact);
            }
        }

        if (upgrades.isEmpty()) {
            getLog().info("No automatic upgrades available.");
            return;
        }

        // 4. Dry run: print and exit
        if (dryRun) {
            getLog().info("Dry run - proposed upgrades:");
            for (UpgradeRecommendation rec : upgrades) {
                getLog().info("  " + rec.getDependency().getCoordinates() +
                        " -> " + rec.getTargetVersion() +
                        " [" + rec.getStrategy().name() + "]" +
                        (rec.isHasBreakingChanges() ? " (WARNING: breaking changes)" : ""));
            }
            return;
        }

        // 5. Apply upgrades
        File pomFile = project.getFile();
        pomModifier.backup(pomFile, outputDirectory);

        int applied = pomModifier.apply(pomFile, upgrades);

        long manual = results.stream()
                .filter(AnalysisResult::isVulnerable)
                .filter(r -> r.getRecommendation() != null && !r.getRecommendation().isAutomaticUpgrade())
                .count();

        // 6. Generate updated report
        AnalysisReport report = new AnalysisReport(
                project.getArtifactId(), project.getVersion(), results);
        reportGenerator.generate(report, outputDirectory);

        getLog().info("============================================");
        getLog().info("Upgrade Summary");
        getLog().info("  Applied:          " + applied);
        getLog().info("  Require manual:   " + manual);
        getLog().info("  POM backup at:    " + new File(outputDirectory, "pom.xml.bak").getAbsolutePath());
        getLog().info("============================================");
    }
}
