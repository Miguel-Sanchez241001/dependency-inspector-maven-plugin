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

@Mojo(
    name = "analyze",
    defaultPhase = LifecyclePhase.VERIFY,
    requiresProject = true,
    requiresDependencyResolution = ResolutionScope.TEST
)
public class AnalyzeMojo extends AbstractMojo {

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

    @Override
    public void execute() {
        try {
            doExecute();
        } catch (MojoExecutionException e) {
            getLog().error(e.getMessage());
        } catch (Exception e) {
            getLog().error("Unexpected error during dependency analysis: " + e.getMessage(), e);
        }
    }

    AnalysisReport doExecute() throws Exception {
        getLog().info("Starting dependency analysis...");

        OkHttpClient httpClient = HttpClientFactory.create(skipSslVerification);
        OsvClient osvClient = new OsvClient(httpClient, getLog());
        VersionResolver versionResolver = new VersionResolver(httpClient, osvClient, getLog());
        CompatibilityChecker compatChecker = new CompatibilityChecker(
                repoSystem, repoSession, remoteRepositories, getLog());
        HtmlReportGenerator reportGenerator = new HtmlReportGenerator(getLog());

        // 1. Collect dependencies
        DependencyCollector collector = new DependencyCollector(project, getLog());
        List<DependencyInfo> dependencies = collector.collect();

        // 2. Query OSV for vulnerabilities (in batch)
        getLog().info("Querying OSV.dev for " + dependencies.size() + " dependencies...");
        Map<DependencyInfo, List<VulnerabilityInfo>> osvResults = osvClient.queryBatch(dependencies);

        // 3. Build analysis results
        List<AnalysisResult> results = new ArrayList<>();
        for (DependencyInfo dep : dependencies) {
            List<VulnerabilityInfo> vulns = osvResults.getOrDefault(dep, Collections.emptyList());

            AnalysisResult result = new AnalysisResult(dep);
            result.setVulnerabilities(vulns);

            if (!vulns.isEmpty()) {
                // 4. Find safe upgrade version
                UpgradeRecommendation rec = versionResolver.resolve(dep);

                // 5. Check breaking changes for automatic upgrades
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

        // 6. Build report
        AnalysisReport report = new AnalysisReport(
                project.getArtifactId(), project.getVersion(), results);

        // 7. Generate HTML report
        File reportFile = reportGenerator.generate(report, outputDirectory);

        // 8. Log summary
        getLog().info("============================================");
        getLog().info("Dependency Inspector Analysis Complete");
        getLog().info("  Vulnerable: " + report.countVulnerable());
        getLog().info("  Clean:      " + report.countClean());
        getLog().info("  Skipped:    " + report.countSkipped());
        getLog().info("  Report:     " + reportFile.getAbsolutePath());
        getLog().info("============================================");

        return report;
    }
}
