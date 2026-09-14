package io.github.miguelsan241001.depinspector.domain.model;

import java.io.File;
import java.util.Objects;

/** Immutable representation of a Maven dependency. */
public final class Dependency {

    private final String groupId;
    private final String artifactId;
    private final String version;
    private final String scope;
    private final DependencyType type;
    private final File resolvedJar; // nullable

    public Dependency(String groupId, String artifactId, String version,
                      String scope, DependencyType type, File resolvedJar) {
        this.groupId = Objects.requireNonNull(groupId, "groupId");
        this.artifactId = Objects.requireNonNull(artifactId, "artifactId");
        this.version = Objects.requireNonNull(version, "version");
        this.scope = scope;
        this.type = type != null ? type : DependencyType.DIRECT;
        this.resolvedJar = resolvedJar;
    }

    public Dependency(String groupId, String artifactId, String version, String scope, DependencyType type) {
        this(groupId, artifactId, version, scope, type, null);
    }

    /** Returns "groupId:artifactId:version". */
    public String coordinates() {
        return groupId + ":" + artifactId + ":" + version;
    }

    /** Returns "groupId:artifactId" (without version). */
    public String ga() {
        return groupId + ":" + artifactId;
    }

    public boolean isTestScoped() {
        return "test".equalsIgnoreCase(scope);
    }

    public boolean isDirectlyDeclared() {
        return type == DependencyType.DIRECT;
    }

    /** Returns a copy of this dependency with a different version. */
    public Dependency withVersion(String newVersion) {
        return new Dependency(groupId, artifactId, newVersion, scope, type, resolvedJar);
    }

    public String getGroupId()    { return groupId; }
    public String getArtifactId() { return artifactId; }
    public String getVersion()    { return version; }
    public String getScope()      { return scope; }
    public DependencyType getType() { return type; }
    public File getResolvedJar()  { return resolvedJar; }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Dependency)) return false;
        Dependency d = (Dependency) o;
        return groupId.equals(d.groupId) && artifactId.equals(d.artifactId) && version.equals(d.version);
    }

    @Override
    public int hashCode() {
        return Objects.hash(groupId, artifactId, version);
    }

    @Override
    public String toString() {
        return coordinates() + " [" + type + "]";
    }
}
