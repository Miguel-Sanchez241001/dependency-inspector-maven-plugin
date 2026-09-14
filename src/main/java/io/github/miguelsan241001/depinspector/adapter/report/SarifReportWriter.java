package io.github.miguelsan241001.depinspector.adapter.report;

import io.github.miguelsan241001.depinspector.application.DependencyAnalysisReport;
import io.github.miguelsan241001.depinspector.domain.model.Dependency;
import io.github.miguelsan241001.depinspector.domain.model.Vulnerability;
import io.github.miguelsan241001.depinspector.domain.port.ReportSink;
import io.github.miguelsan241001.depinspector.model.*;
import io.github.miguelsan241001.depinspector.report.ReportExporter;
import org.apache.maven.plugin.logging.Log;

import java.io.File;
import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Implements {@link ReportSink} for SARIF 2.1.0 reports by converting
 * {@link DependencyAnalysisReport} to the legacy model and delegating to
 * {@link ReportExporter}.
 */
public class SarifReportWriter implements ReportSink {

    private final ReportExporter exporter;

    public SarifReportWriter(Log log) {
        this.exporter = new ReportExporter(log);
    }

    @Override
    public File write(DependencyAnalysisReport report, File outputDir) throws IOException {
        AnalysisReport legacyReport = toLegacy(report);
        return exporter.exportSarif(legacyReport, outputDir);
    }

    private AnalysisReport toLegacy(DependencyAnalysisReport report) {
        List<AnalysisResult> results = new ArrayList<>();

        for (io.github.miguelsan241001.depinspector.domain.model.DependencyNode node
                : report.getGraph().getAllDependencies()) {
            Dependency dep = node.getDependency();
            AnalysisResult result = new AnalysisResult(toLegacyDep(dep));

            List<Vulnerability> vulns = report.getVulnerabilities()
                    .getOrDefault(dep, Collections.emptyList());
            result.setVulnerabilities(vulns.stream().map(this::toLegacyVuln).collect(Collectors.toList()));
            result.setRecommendation(report.getRecommendations().get(dep));
            results.add(result);
        }

        return new AnalysisReport(
                report.getProjectArtifactId(), report.getProjectVersion(), results);
    }

    private DependencyInfo toLegacyDep(Dependency dep) {
        return new DependencyInfo(
                dep.getGroupId(), dep.getArtifactId(), dep.getVersion(), dep.getScope(),
                DependencyInfo.DependencyType.valueOf(dep.getType().name()));
    }

    private VulnerabilityInfo toLegacyVuln(Vulnerability v) {
        VulnerabilityInfo vi = new VulnerabilityInfo();
        vi.setId(v.getId());
        vi.setSummary(v.getSummary());
        vi.setCvssScore(v.getCvssScore());
        vi.setSeverity(VulnerabilityInfo.Severity.valueOf(v.getSeverity().name()));
        vi.setAliases(v.getAliases());
        return vi;
    }
}
