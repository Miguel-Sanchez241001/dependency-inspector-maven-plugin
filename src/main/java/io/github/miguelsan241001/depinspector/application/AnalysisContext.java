package io.github.miguelsan241001.depinspector.application;

import java.io.File;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/** Parameters for a dependency analysis run (derived from mojo @Parameters). */
public class AnalysisContext {

    private final String projectArtifactId;
    private final String projectVersion;
    private final File outputDirectory;
    private final Set<String> outputFormats;      // "html", "json", "sarif"
    private final double failOnCvss;              // -1 = disabled
    private final String failOnSeverity;          // null = disabled
    private final Set<String> excludeArtifacts;   // "groupId:artifactId"
    private final double minCvss;                 // -1 = show all

    private AnalysisContext(Builder b) {
        this.projectArtifactId = b.projectArtifactId;
        this.projectVersion   = b.projectVersion;
        this.outputDirectory  = b.outputDirectory;
        this.outputFormats    = Collections.unmodifiableSet(b.outputFormats);
        this.failOnCvss       = b.failOnCvss;
        this.failOnSeverity   = b.failOnSeverity;
        this.excludeArtifacts = Collections.unmodifiableSet(b.excludeArtifacts);
        this.minCvss          = b.minCvss;
    }

    public String getProjectArtifactId()  { return projectArtifactId; }
    public String getProjectVersion()     { return projectVersion; }
    public File getOutputDirectory()      { return outputDirectory; }
    public Set<String> getOutputFormats() { return outputFormats; }
    public double getFailOnCvss()         { return failOnCvss; }
    public String getFailOnSeverity()     { return failOnSeverity; }
    public Set<String> getExcludeArtifacts() { return excludeArtifacts; }
    public double getMinCvss()            { return minCvss; }

    public static Builder builder() { return new Builder(); }

    public static class Builder {
        private String projectArtifactId = "";
        private String projectVersion    = "";
        private File outputDirectory;
        private Set<String> outputFormats    = new HashSet<>(Collections.singleton("html"));
        private double failOnCvss            = -1;
        private String failOnSeverity        = null;
        private Set<String> excludeArtifacts = new HashSet<>();
        private double minCvss               = -1;

        public Builder projectArtifactId(String s) { this.projectArtifactId = s; return this; }
        public Builder projectVersion(String s)    { this.projectVersion = s;    return this; }
        public Builder outputDirectory(File d)      { this.outputDirectory = d; return this; }
        public Builder outputFormats(Set<String> f) { this.outputFormats = f;   return this; }
        public Builder failOnCvss(double v)         { this.failOnCvss = v;      return this; }
        public Builder failOnSeverity(String s)     { this.failOnSeverity = s;  return this; }
        public Builder excludeArtifacts(Set<String> e) { this.excludeArtifacts = e; return this; }
        public Builder minCvss(double v)            { this.minCvss = v;         return this; }

        public AnalysisContext build() { return new AnalysisContext(this); }
    }
}
