package io.github.miguelsan241001.depinspector.mojo;

import io.github.miguelsan241001.depinspector.adapter.compatibility.JapicmpCompatibilityAdapter;
import io.github.miguelsan241001.depinspector.adapter.maven.MavenDependencyAdapter;
import io.github.miguelsan241001.depinspector.adapter.osv.OsvVulnerabilityAdapter;
import io.github.miguelsan241001.depinspector.adapter.report.HtmlReportWriter;
import io.github.miguelsan241001.depinspector.adapter.scanner.JavaSourceUsageAdapter;
import io.github.miguelsan241001.depinspector.adapter.version.MavenCentralVersionAdapter;
import io.github.miguelsan241001.depinspector.application.DependencyAnalysisReport;
import io.github.miguelsan241001.depinspector.application.UpgradeContext;
import io.github.miguelsan241001.depinspector.application.UpgradeDependenciesUseCase;
import io.github.miguelsan241001.depinspector.service.InteractiveConsole;
import io.github.miguelsan241001.depinspector.service.OsvClient;
import io.github.miguelsan241001.depinspector.service.PomModifier;
import io.github.miguelsan241001.depinspector.service.VersionResolver;
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
import java.util.List;

/**
 * Applies safe upgrades to {@code pom.xml} for vulnerable dependencies.
 *
 * @since 1.0.0
 */
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
    private String artifact;

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
        getLog().info("Starting dependency upgrade" +
                (dryRun ? " (DRY RUN)" : "") +
                (interactive ? " (INTERACTIVE)" : "") + "...");

        OkHttpClient httpClient  = HttpClientFactory.create(skipSslVerification);
        OsvClient osvClient      = new OsvClient(httpClient, getLog());

        OsvVulnerabilityAdapter vulnAdapter  = new OsvVulnerabilityAdapter(osvClient);
        MavenCentralVersionAdapter verAdapter = new MavenCentralVersionAdapter(
                httpClient, osvClient, vulnAdapter, getLog());
        JapicmpCompatibilityAdapter compatAdapter = new JapicmpCompatibilityAdapter(
                repoSystem, repoSession, remoteRepositories, getLog());
        MavenDependencyAdapter depAdapter    = new MavenDependencyAdapter(project, getLog());
        JavaSourceUsageAdapter usageAdapter  = new JavaSourceUsageAdapter(project.getBasedir(), getLog());
        PomModifier pomModifier              = new PomModifier(getLog());
        InteractiveConsole console           = interactive ? new InteractiveConsole(getLog()) : null;

        UpgradeContext ctx = UpgradeContext.builder()
                .outputDirectory(outputDirectory)
                .dryRun(dryRun)
                .artifactFilter(artifact)
                .interactive(interactive)
                .build();

        UpgradeDependenciesUseCase useCase = new UpgradeDependenciesUseCase(
                depAdapter, vulnAdapter, verAdapter, compatAdapter,
                usageAdapter, pomModifier, console, getLog());

        DependencyAnalysisReport report = useCase.execute(ctx, project.getFile());

        // Generate HTML report with final state
        new HtmlReportWriter(getLog()).write(report, outputDirectory);
    }
}
