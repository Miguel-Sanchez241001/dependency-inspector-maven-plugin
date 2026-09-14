package io.github.miguelsan241001.depinspector.mojo;

import io.github.miguelsan241001.depinspector.adapter.compatibility.JapicmpCompatibilityAdapter;
import io.github.miguelsan241001.depinspector.adapter.maven.MavenDependencyAdapter;
import io.github.miguelsan241001.depinspector.adapter.osv.OsvVulnerabilityAdapter;
import io.github.miguelsan241001.depinspector.adapter.report.*;
import io.github.miguelsan241001.depinspector.adapter.scanner.JavaSourceUsageAdapter;
import io.github.miguelsan241001.depinspector.adapter.version.MavenCentralVersionAdapter;
import io.github.miguelsan241001.depinspector.application.AnalysisContext;
import io.github.miguelsan241001.depinspector.application.AnalyzeDependenciesUseCase;
import io.github.miguelsan241001.depinspector.application.DependencyAnalysisReport;
import io.github.miguelsan241001.depinspector.domain.model.Dependency;
import io.github.miguelsan241001.depinspector.domain.model.Vulnerability;
import io.github.miguelsan241001.depinspector.domain.port.ReportSink;
import io.github.miguelsan241001.depinspector.model.VulnerabilityInfo;
import io.github.miguelsan241001.depinspector.service.OsvClient;
import io.github.miguelsan241001.depinspector.service.ScopeAnalyzer;
import io.github.miguelsan241001.depinspector.service.VersionResolver;
import io.github.miguelsan241001.depinspector.util.HttpClientFactory;
import okhttp3.OkHttpClient;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.*;
import org.apache.maven.project.MavenProject;
import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.repository.RemoteRepository;

import java.io.File;
import java.util.*;

/**
 * Audits the current project's dependencies for known CVEs using OSV.dev.
 * Generates an HTML report (and optionally JSON/SARIF) in the output directory.
 *
 * @since 1.0.0
 */
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

    /**
     * Skip TLS certificate verification for HTTPS calls to OSV.dev and Maven Central.
     * <strong>Warning:</strong> enabling this makes results untrustworthy.
     *
     * @since 1.0.0
     */
    @Parameter(property = "skipSslVerification", defaultValue = "false")
    private boolean skipSslVerification;

    /**
     * Directory where the report files are written.
     *
     * @since 1.0.0
     */
    @Parameter(property = "outputDirectory", defaultValue = "${project.build.directory}/dependency-inspector")
    private File outputDirectory;

    /**
     * Comma-separated list of output formats: {@code html}, {@code json}, {@code sarif}.
     *
     * @since 1.1.0
     */
    @Parameter(property = "outputFormats", defaultValue = "html")
    private String outputFormats;

    /**
     * Fail the build if any vulnerability has a CVSS score &ge; this value.
     * Set to {@code -1} (default) to disable.
     *
     * @since 1.1.0
     */
    @Parameter(property = "failOnCvss", defaultValue = "-1")
    private double failOnCvss;

    /**
     * Fail the build if any vulnerability has severity &ge; this level.
     * Accepted values: {@code CRITICAL}, {@code HIGH}, {@code MEDIUM}, {@code LOW}.
     *
     * @since 1.1.0
     */
    @Parameter(property = "failOnSeverity")
    private String failOnSeverity;

    /**
     * Comma-separated {@code groupId:artifactId} pairs to exclude from analysis.
     *
     * @since 1.1.0
     */
    @Parameter(property = "excludeArtifacts")
    private String excludeArtifacts;

    /**
     * Minimum CVSS score to include in the report. Set to {@code -1} to show all.
     *
     * @since 1.1.0
     */
    @Parameter(property = "minCvss", defaultValue = "-1")
    private double minCvss;

    @Override
    public void execute() throws MojoFailureException {
        try {
            doExecute();
        } catch (MojoFailureException e) {
            throw e;
        } catch (MojoExecutionException e) {
            getLog().error(e.getMessage());
        } catch (Exception e) {
            getLog().error("Unexpected error during dependency analysis: " + e.getMessage(), e);
        }
    }

    DependencyAnalysisReport doExecute() throws Exception {
        if (skipSslVerification) {
            getLog().warn("############################################################");
            getLog().warn("  WARNING: skipSslVerification=true — Do NOT use in CI/prod.");
            getLog().warn("############################################################");
        }
        getLog().info("Starting dependency analysis...");

        // Build infrastructure
        OkHttpClient httpClient  = HttpClientFactory.create(skipSslVerification);
        OsvClient osvClient      = new OsvClient(httpClient, getLog());

        OsvVulnerabilityAdapter vulnAdapter  = new OsvVulnerabilityAdapter(osvClient);
        MavenCentralVersionAdapter verAdapter = new MavenCentralVersionAdapter(
                httpClient, osvClient, vulnAdapter, getLog());
        JapicmpCompatibilityAdapter compatAdapter = new JapicmpCompatibilityAdapter(
                repoSystem, repoSession, remoteRepositories, getLog());
        MavenDependencyAdapter depAdapter    = new MavenDependencyAdapter(project, getLog());
        JavaSourceUsageAdapter usageAdapter  = new JavaSourceUsageAdapter(project.getBasedir(), getLog());
        ScopeAnalyzer scopeAnalyzer          = new ScopeAnalyzer(
                new VersionResolver(httpClient, osvClient, getLog()), getLog());

        // Build context
        AnalysisContext ctx = AnalysisContext.builder()
                .projectArtifactId(project.getArtifactId())
                .projectVersion(project.getVersion())
                .outputDirectory(outputDirectory)
                .outputFormats(parseFormats())
                .failOnCvss(failOnCvss)
                .failOnSeverity(failOnSeverity)
                .excludeArtifacts(parseExcluded())
                .minCvss(minCvss)
                .build();

        // Execute use case
        AnalyzeDependenciesUseCase useCase = new AnalyzeDependenciesUseCase(
                depAdapter, vulnAdapter, verAdapter, compatAdapter,
                usageAdapter, scopeAnalyzer, getLog());
        DependencyAnalysisReport report = useCase.execute(ctx);

        // Write reports
        Set<String> formats = ctx.getOutputFormats();
        File lastFile = null;
        if (formats.contains("html")) {
            lastFile = new HtmlReportWriter(getLog()).write(report, outputDirectory);
        }
        if (formats.contains("json")) {
            lastFile = new JsonReportWriter(getLog()).write(report, outputDirectory);
        }
        if (formats.contains("sarif")) {
            lastFile = new SarifReportWriter(getLog()).write(report, outputDirectory);
        }

        // Summary
        getLog().info("============================================");
        getLog().info("Dependency Inspector Analysis Complete");
        getLog().info("  Vulnerable:   " + report.countVulnerable());
        getLog().info("  Scope issues: " + report.getScopeIssues().size());
        getLog().info("  Clean:        " + report.countClean());
        if (lastFile != null) getLog().info("  Report:       " + lastFile.getAbsolutePath());
        getLog().info("  Output dir:   " + outputDirectory.getAbsolutePath());
        getLog().info("============================================");

        // Quality gate — runs AFTER report is generated
        checkQualityGate(report);

        return report;
    }

    private void checkQualityGate(DependencyAnalysisReport report) throws MojoFailureException {
        VulnerabilityInfo.Severity threshold = parseSeverityThreshold();

        for (Map.Entry<Dependency, List<Vulnerability>> entry : report.getVulnerabilities().entrySet()) {
            for (Vulnerability vuln : entry.getValue()) {
                if (failOnCvss > 0 && vuln.hasCvssScore() && vuln.getCvssScore() >= failOnCvss) {
                    throw new MojoFailureException(
                            "Build failed: " + vuln.getId() + " in " + entry.getKey().coordinates() +
                            " has CVSS " + String.format("%.1f", vuln.getCvssScore()) +
                            " >= failOnCvss=" + failOnCvss +
                            ". See report at " + outputDirectory.getAbsolutePath());
                }
                if (threshold != null) {
                    VulnerabilityInfo.Severity depSev =
                            VulnerabilityInfo.Severity.valueOf(vuln.getSeverity().name());
                    if (depSev.ordinal() <= threshold.ordinal()) {
                        throw new MojoFailureException(
                                "Build failed: " + vuln.getId() + " in " + entry.getKey().coordinates() +
                                " has severity " + vuln.getSeverity() +
                                " >= failOnSeverity=" + failOnSeverity +
                                ". See report at " + outputDirectory.getAbsolutePath());
                    }
                }
            }
        }
    }

    private Set<String> parseExcluded() {
        if (excludeArtifacts == null || excludeArtifacts.isBlank()) return Collections.emptySet();
        Set<String> result = new HashSet<>();
        for (String coord : excludeArtifacts.split(",")) {
            String t = coord.trim();
            if (!t.isEmpty()) result.add(t);
        }
        return result;
    }

    private Set<String> parseFormats() {
        Set<String> result = new HashSet<>();
        if (outputFormats == null || outputFormats.isBlank()) { result.add("html"); return result; }
        for (String f : outputFormats.split(",")) result.add(f.trim().toLowerCase());
        return result;
    }

    private VulnerabilityInfo.Severity parseSeverityThreshold() {
        if (failOnSeverity == null || failOnSeverity.isBlank()) return null;
        try {
            return VulnerabilityInfo.Severity.valueOf(failOnSeverity.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            getLog().warn("Unknown failOnSeverity: '" + failOnSeverity + "'. Quality gate disabled.");
            return null;
        }
    }
}
