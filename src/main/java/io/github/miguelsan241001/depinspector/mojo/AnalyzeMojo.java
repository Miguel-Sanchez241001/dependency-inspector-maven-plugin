package io.github.miguelsan241001.depinspector.mojo;

import io.github.miguelsan241001.depinspector.model.*;
import io.github.miguelsan241001.depinspector.model.CompatibilityStatus;
import io.github.miguelsan241001.depinspector.report.HtmlReportGenerator;
import io.github.miguelsan241001.depinspector.report.ReportExporter;
import io.github.miguelsan241001.depinspector.service.*;
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
import java.util.stream.Collectors;

/**
 * Audits the current project's dependencies for known CVEs using OSV.dev.
 * Generates an HTML report (and optionally JSON/SARIF) in the output directory.
 * <p>
 * This goal never fails the build unless {@code failOnCvss} or {@code failOnSeverity}
 * is explicitly configured.
 * </p>
 */
@Mojo(
    name = "analyze",
    defaultPhase = LifecyclePhase.VERIFY,
    requiresProject = true,
    requiresDependencyResolution = ResolutionScope.TEST
)
public class AnalyzeMojo extends AbstractMojo {

    /** The Maven project being analyzed. */
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
     * <strong>Warning:</strong> enabling this makes results untrustworthy and should
     * never be used in CI or production environments.
     *
     * @since 1.0.0
     */
    @Parameter(property = "skipSslVerification", defaultValue = "false")
    private boolean skipSslVerification;

    /**
     * Directory where the report files are written.
     * Defaults to {@code ${project.build.directory}/dependency-inspector}.
     *
     * @since 1.0.0
     */
    @Parameter(property = "outputDirectory", defaultValue = "${project.build.directory}/dependency-inspector")
    private File outputDirectory;

    /**
     * Comma-separated list of output formats to generate.
     * Supported values: {@code html}, {@code json}, {@code sarif}.
     * Example: {@code -DoutputFormats=html,json,sarif}
     *
     * @since 1.1.0
     */
    @Parameter(property = "outputFormats", defaultValue = "html")
    private String outputFormats;

    /**
     * Fail the build if any vulnerability has a CVSS score equal to or above this value.
     * Set to {@code -1} (default) to disable.
     * Example: {@code -DfailOnCvss=7.0} fails on HIGH and CRITICAL.
     *
     * @since 1.1.0
     */
    @Parameter(property = "failOnCvss", defaultValue = "-1")
    private double failOnCvss;

    /**
     * Fail the build if any vulnerability has a severity equal to or above this level.
     * Accepted values (case-insensitive): {@code CRITICAL}, {@code HIGH}, {@code MEDIUM}, {@code LOW}.
     * Leave empty (default) to disable.
     * Example: {@code -DfailOnSeverity=HIGH}
     *
     * @since 1.1.0
     */
    @Parameter(property = "failOnSeverity")
    private String failOnSeverity;

    /**
     * Comma-separated list of {@code groupId:artifactId} coordinates to exclude from analysis.
     * Useful for suppressing known false positives.
     * Example: {@code -DexcludeArtifacts=com.example:legacy-lib,org.foo:bar}
     *
     * @since 1.1.0
     */
    @Parameter(property = "excludeArtifacts")
    private String excludeArtifacts;

    /**
     * Minimum CVSS score to include in the report.
     * Vulnerabilities below this score are still detected but hidden from the report.
     * Set to {@code -1} (default) to show all.
     * Example: {@code -DminCvss=4.0} hides LOW vulnerabilities.
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
            throw e; // propagate quality-gate failures
        } catch (MojoExecutionException e) {
            getLog().error(e.getMessage());
        } catch (Exception e) {
            getLog().error("Unexpected error during dependency analysis: " + e.getMessage(), e);
        }
    }

    AnalysisReport doExecute() throws Exception {
        if (skipSslVerification) {
            getLog().warn("############################################################");
            getLog().warn("  WARNING: skipSslVerification=true");
            getLog().warn("  TLS certificate checks are DISABLED. OSV.dev responses");
            getLog().warn("  cannot be trusted. Do NOT use this in CI or production.");
            getLog().warn("############################################################");
        }

        getLog().info("Starting dependency analysis...");

        Set<String> excluded = parseExcluded();

        OkHttpClient httpClient = HttpClientFactory.create(skipSslVerification);
        OsvClient osvClient = new OsvClient(httpClient, getLog());
        VersionResolver versionResolver = new VersionResolver(httpClient, osvClient, getLog());
        CompatibilityChecker compatChecker = new CompatibilityChecker(
                repoSystem, repoSession, remoteRepositories, getLog());
        HtmlReportGenerator reportGenerator = new HtmlReportGenerator(getLog());

        // 1. Collect and optionally filter dependencies
        DependencyCollector collector = new DependencyCollector(project, getLog());
        List<DependencyInfo> dependencies = collector.collect();

        List<DependencyInfo> toAnalyze = dependencies.stream()
                .filter(d -> !excluded.contains(d.getGroupId() + ":" + d.getArtifactId()))
                .collect(Collectors.toList());

        if (!excluded.isEmpty()) {
            int skippedCount = dependencies.size() - toAnalyze.size();
            getLog().info("Excluding " + skippedCount + " artifact(s) from analysis per excludeArtifacts config.");
        }

        // 2. Query OSV.dev
        getLog().info("Querying OSV.dev for " + toAnalyze.size() + " dependencies...");
        Map<DependencyInfo, List<VulnerabilityInfo>> osvResults = osvClient.queryBatch(toAnalyze);

        // 3. Build analysis results
        List<AnalysisResult> results = new ArrayList<>();
        for (DependencyInfo dep : toAnalyze) {
            List<VulnerabilityInfo> vulns = osvResults.getOrDefault(dep, Collections.emptyList());

            // Apply minCvss filter
            if (minCvss > 0) {
                vulns = vulns.stream()
                        .filter(v -> v.getCvssScore() < 0 || v.getCvssScore() >= minCvss)
                        .collect(Collectors.toList());
            }

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

        // 4. Detect scope issues
        ScopeAnalyzer scopeAnalyzer = new ScopeAnalyzer(versionResolver, getLog());
        List<ScopeIssue> scopeIssues = scopeAnalyzer.analyze(toAnalyze);
        if (!scopeIssues.isEmpty()) {
            getLog().warn(scopeIssues.size() + " scope issue(s) detected: test libraries reachable at compile/runtime scope.");
        }

        // 5. Scan usages
        UsageScanner usageScanner = new UsageScanner(project.getBasedir(), getLog());
        usageScanner.scan(results);

        // 6. Build report
        AnalysisReport report = new AnalysisReport(
                project.getArtifactId(), project.getVersion(), results);
        report.setScopeIssues(scopeIssues);

        // 7. Generate output files
        Set<String> formats = parseFormats();
        File reportFile = null;

        if (formats.contains("html")) {
            reportFile = reportGenerator.generate(report, outputDirectory);
        }
        if (formats.contains("json") || formats.contains("sarif")) {
            ReportExporter exporter = new ReportExporter(getLog());
            if (formats.contains("json")) {
                exporter.exportJson(report, outputDirectory);
            }
            if (formats.contains("sarif")) {
                exporter.exportSarif(report, outputDirectory);
            }
        }

        // 8. Log summary
        getLog().info("============================================");
        getLog().info("Dependency Inspector Analysis Complete");
        getLog().info("  Vulnerable:    " + report.countVulnerable());
        getLog().info("  Scope issues:  " + scopeIssues.size());
        getLog().info("  Clean:         " + report.countClean());
        getLog().info("  Skipped:       " + report.countSkipped());
        if (reportFile != null) {
            getLog().info("  Report:        " + reportFile.getAbsolutePath());
        }
        getLog().info("  Output dir:    " + outputDirectory.getAbsolutePath());
        getLog().info("============================================");

        // 9. Quality gate — runs after report is generated so results are always visible
        checkQualityGate(report);

        return report;
    }

    private void checkQualityGate(AnalysisReport report) throws MojoFailureException {
        VulnerabilityInfo.Severity severityThreshold = parseSeverityThreshold();

        for (AnalysisResult result : report.getVulnerableResults()) {
            for (VulnerabilityInfo vuln : result.getVulnerabilities()) {
                // failOnCvss check
                if (failOnCvss > 0 && vuln.getCvssScore() >= failOnCvss) {
                    throw new MojoFailureException(
                            "Build failed: " + vuln.getId() + " in " +
                            result.getDependency().getCoordinates() +
                            " has CVSS " + String.format("%.1f", vuln.getCvssScore()) +
                            " >= failOnCvss=" + failOnCvss +
                            ". See report at " + outputDirectory.getAbsolutePath());
                }
                // failOnSeverity check
                if (severityThreshold != null &&
                        vuln.getSeverity().ordinal() <= severityThreshold.ordinal()) {
                    throw new MojoFailureException(
                            "Build failed: " + vuln.getId() + " in " +
                            result.getDependency().getCoordinates() +
                            " has severity " + vuln.getSeverity() +
                            " >= failOnSeverity=" + failOnSeverity +
                            ". See report at " + outputDirectory.getAbsolutePath());
                }
            }
        }
    }

    private Set<String> parseExcluded() {
        if (excludeArtifacts == null || excludeArtifacts.isBlank()) return Collections.emptySet();
        Set<String> result = new HashSet<>();
        for (String coord : excludeArtifacts.split(",")) {
            String trimmed = coord.trim();
            if (!trimmed.isEmpty()) result.add(trimmed);
        }
        return result;
    }

    private Set<String> parseFormats() {
        Set<String> result = new HashSet<>();
        if (outputFormats == null || outputFormats.isBlank()) {
            result.add("html");
            return result;
        }
        for (String f : outputFormats.split(",")) {
            result.add(f.trim().toLowerCase());
        }
        return result;
    }

    /** Returns null if failOnSeverity is not set or invalid. */
    private VulnerabilityInfo.Severity parseSeverityThreshold() {
        if (failOnSeverity == null || failOnSeverity.isBlank()) return null;
        try {
            return VulnerabilityInfo.Severity.valueOf(failOnSeverity.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            getLog().warn("Unknown failOnSeverity value: '" + failOnSeverity +
                    "'. Expected one of: CRITICAL, HIGH, MEDIUM, LOW. Quality gate disabled.");
            return null;
        }
    }
}
