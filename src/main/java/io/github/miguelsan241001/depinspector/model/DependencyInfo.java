package io.github.miguelsan241001.depinspector.model;

import java.io.File;

public class DependencyInfo {

    public enum DependencyType {
        DIRECT, TRANSITIVE, PLUGIN
    }

    private String groupId;
    private String artifactId;
    private String version;
    private String scope;
    private DependencyType type;
    private String transitiveOrigin; // "groupId:artifactId" of the direct dep that brings it
    private File jarFile; // nullable

    public DependencyInfo() {}

    public DependencyInfo(String groupId, String artifactId, String version, String scope, DependencyType type) {
        this.groupId = groupId;
        this.artifactId = artifactId;
        this.version = version;
        this.scope = scope;
        this.type = type;
    }

    public String getCoordinates() {
        return groupId + ":" + artifactId + ":" + version;
    }

    public String getGroupId() { return groupId; }
    public void setGroupId(String groupId) { this.groupId = groupId; }

    public String getArtifactId() { return artifactId; }
    public void setArtifactId(String artifactId) { this.artifactId = artifactId; }

    public String getVersion() { return version; }
    public void setVersion(String version) { this.version = version; }

    public String getScope() { return scope; }
    public void setScope(String scope) { this.scope = scope; }

    public DependencyType getType() { return type; }
    public void setType(DependencyType type) { this.type = type; }

    public String getTransitiveOrigin() { return transitiveOrigin; }
    public void setTransitiveOrigin(String transitiveOrigin) { this.transitiveOrigin = transitiveOrigin; }

    public File getJarFile() { return jarFile; }
    public void setJarFile(File jarFile) { this.jarFile = jarFile; }

    @Override
    public String toString() {
        return getCoordinates() + " [" + type + "]";
    }
}
