package io.github.miguelsan241001.depinspector.model;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

public class AnalysisReport {

    private String projectArtifactId;
    private String projectVersion;
    private LocalDateTime generatedAt;
    private List<AnalysisResult> results;

    public AnalysisReport() {
        this.generatedAt = LocalDateTime.now();
    }

    public AnalysisReport(String projectArtifactId, String projectVersion, List<AnalysisResult> results) {
        this.projectArtifactId = projectArtifactId;
        this.projectVersion = projectVersion;
        this.results = results;
        this.generatedAt = LocalDateTime.now();
    }

    public long countVulnerable() {
        if (results == null) return 0;
        return results.stream().filter(AnalysisResult::isVulnerable).count();
    }

    public long countClean() {
        if (results == null) return 0;
        return results.stream()
                .filter(r -> !r.isVulnerable() && !r.isAnalysisSkipped())
                .count();
    }

    public long countSkipped() {
        if (results == null) return 0;
        return results.stream().filter(AnalysisResult::isAnalysisSkipped).count();
    }

    public List<AnalysisResult> getVulnerableResults() {
        if (results == null) return List.of();
        return results.stream().filter(AnalysisResult::isVulnerable).collect(Collectors.toList());
    }

    public String getProjectArtifactId() { return projectArtifactId; }
    public void setProjectArtifactId(String projectArtifactId) { this.projectArtifactId = projectArtifactId; }

    public String getProjectVersion() { return projectVersion; }
    public void setProjectVersion(String projectVersion) { this.projectVersion = projectVersion; }

    public LocalDateTime getGeneratedAt() { return generatedAt; }
    public void setGeneratedAt(LocalDateTime generatedAt) { this.generatedAt = generatedAt; }

    public List<AnalysisResult> getResults() { return results; }
    public void setResults(List<AnalysisResult> results) { this.results = results; }
}
