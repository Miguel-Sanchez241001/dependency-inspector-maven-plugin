package io.github.miguelsan241001.depinspector.application;

import java.io.File;

/** Parameters for a dependency upgrade run (derived from mojo @Parameters). */
public class UpgradeContext {

    private final File outputDirectory;
    private final boolean dryRun;
    private final String artifactFilter;  // "groupId:artifactId" or null
    private final boolean interactive;

    private UpgradeContext(Builder b) {
        this.outputDirectory = b.outputDirectory;
        this.dryRun          = b.dryRun;
        this.artifactFilter  = b.artifactFilter;
        this.interactive     = b.interactive;
    }

    public File getOutputDirectory() { return outputDirectory; }
    public boolean isDryRun()        { return dryRun; }
    public String getArtifactFilter() { return artifactFilter; }
    public boolean isInteractive()   { return interactive; }

    public static Builder builder() { return new Builder(); }

    public static class Builder {
        private File outputDirectory;
        private boolean dryRun      = false;
        private String artifactFilter = null;
        private boolean interactive = false;

        public Builder outputDirectory(File d) { this.outputDirectory = d; return this; }
        public Builder dryRun(boolean v)       { this.dryRun = v;          return this; }
        public Builder artifactFilter(String s) { this.artifactFilter = s; return this; }
        public Builder interactive(boolean v)  { this.interactive = v;     return this; }

        public UpgradeContext build() { return new UpgradeContext(this); }
    }
}
