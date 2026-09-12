package io.github.miguelsan241001.depinspector.model;

import java.util.List;

public class AnalysisResult {

    private DependencyInfo dependency;
    private List<VulnerabilityInfo> vulnerabilities;
    private UpgradeRecommendation recommendation;
    private boolean analysisSkipped;
    private String skipReason;

    public AnalysisResult() {}

    public AnalysisResult(DependencyInfo dependency) {
        this.dependency = dependency;
    }

    public boolean isVulnerable() {
        return vulnerabilities != null && !vulnerabilities.isEmpty();
    }

    public DependencyInfo getDependency() { return dependency; }
    public void setDependency(DependencyInfo dependency) { this.dependency = dependency; }

    public List<VulnerabilityInfo> getVulnerabilities() { return vulnerabilities; }
    public void setVulnerabilities(List<VulnerabilityInfo> vulnerabilities) { this.vulnerabilities = vulnerabilities; }

    public UpgradeRecommendation getRecommendation() { return recommendation; }
    public void setRecommendation(UpgradeRecommendation recommendation) { this.recommendation = recommendation; }

    public boolean isAnalysisSkipped() { return analysisSkipped; }
    public void setAnalysisSkipped(boolean analysisSkipped) { this.analysisSkipped = analysisSkipped; }

    public String getSkipReason() { return skipReason; }
    public void setSkipReason(String skipReason) { this.skipReason = skipReason; }
}
