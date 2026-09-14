package io.github.miguelsan241001.depinspector.application;

import io.github.miguelsan241001.depinspector.domain.model.*;
import io.github.miguelsan241001.depinspector.model.ScopeIssue;
import io.github.miguelsan241001.depinspector.model.UpgradeRecommendation;

import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

/**
 * The result of a full dependency analysis, including the graph, vulnerabilities,
 * impacts, upgrade recommendations, and scope issues.
 */
public class DependencyAnalysisReport {

    private final String projectArtifactId;
    private final String projectVersion;
    private final LocalDateTime generatedAt;
    private final DependencyGraph graph;
    private final Map<Dependency, List<Vulnerability>> vulnerabilities;
    private final Map<Dependency, Impact> impacts;
    private final Map<Dependency, UpgradeRecommendation> recommendations;
    private final Map<Dependency, List<Usage>> usages;
    private final List<ScopeIssue> scopeIssues;

    private DependencyAnalysisReport(Builder b) {
        this.projectArtifactId = b.projectArtifactId;
        this.projectVersion    = b.projectVersion;
        this.generatedAt       = LocalDateTime.now();
        this.graph             = b.graph;
        this.vulnerabilities   = Collections.unmodifiableMap(b.vulnerabilities);
        this.impacts           = Collections.unmodifiableMap(b.impacts);
        this.recommendations   = Collections.unmodifiableMap(b.recommendations);
        this.usages            = Collections.unmodifiableMap(b.usages);
        this.scopeIssues       = Collections.unmodifiableList(b.scopeIssues);
    }

    public String getProjectArtifactId() { return projectArtifactId; }
    public String getProjectVersion()    { return projectVersion; }
    public LocalDateTime getGeneratedAt() { return generatedAt; }
    public DependencyGraph getGraph()    { return graph; }

    public Map<Dependency, List<Vulnerability>> getVulnerabilities() { return vulnerabilities; }
    public Map<Dependency, Impact> getImpacts()                      { return impacts; }
    public Map<Dependency, UpgradeRecommendation> getRecommendations() { return recommendations; }
    public Map<Dependency, List<Usage>> getUsages()                  { return usages; }
    public List<ScopeIssue> getScopeIssues()                         { return scopeIssues; }

    public List<Dependency> getVulnerableDeps() {
        return vulnerabilities.entrySet().stream()
                .filter(e -> !e.getValue().isEmpty())
                .map(Map.Entry::getKey)
                .collect(Collectors.toList());
    }

    public long countVulnerable() { return getVulnerableDeps().size(); }
    public long countClean()      { return graph.getAllDependencies().size() - countVulnerable(); }

    public static Builder builder() { return new Builder(); }

    public static class Builder {
        private String projectArtifactId = "";
        private String projectVersion    = "";
        private DependencyGraph graph    = new DependencyGraph();
        private Map<Dependency, List<Vulnerability>> vulnerabilities = new LinkedHashMap<>();
        private Map<Dependency, Impact> impacts                      = new LinkedHashMap<>();
        private Map<Dependency, UpgradeRecommendation> recommendations = new LinkedHashMap<>();
        private Map<Dependency, List<Usage>> usages                  = new LinkedHashMap<>();
        private List<ScopeIssue> scopeIssues                         = new ArrayList<>();

        public Builder projectArtifactId(String s)     { this.projectArtifactId = s; return this; }
        public Builder projectVersion(String s)        { this.projectVersion = s;    return this; }
        public Builder graph(DependencyGraph g)        { this.graph = g;             return this; }
        public Builder vulnerabilities(Map<Dependency, List<Vulnerability>> m) { this.vulnerabilities = m; return this; }
        public Builder impacts(Map<Dependency, Impact> m)                      { this.impacts = m;         return this; }
        public Builder recommendations(Map<Dependency, UpgradeRecommendation> m) { this.recommendations = m; return this; }
        public Builder usages(Map<Dependency, List<Usage>> m)                  { this.usages = m;          return this; }
        public Builder scopeIssues(List<ScopeIssue> l)                         { this.scopeIssues = l;     return this; }

        public DependencyAnalysisReport build() { return new DependencyAnalysisReport(this); }
    }
}
