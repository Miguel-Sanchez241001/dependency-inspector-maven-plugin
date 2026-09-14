package io.github.miguelsan241001.depinspector.domain.model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/** A node in the dependency graph, wrapping a {@link Dependency} with its graph connections. */
public final class DependencyNode {

    private final Dependency dependency;
    private final List<DependencyNode> parents  = new ArrayList<>();
    private final List<DependencyNode> children = new ArrayList<>();

    public DependencyNode(Dependency dependency) {
        this.dependency = Objects.requireNonNull(dependency, "dependency");
    }

    public Dependency getDependency() { return dependency; }

    public List<DependencyNode> getParents()  { return Collections.unmodifiableList(parents); }
    public List<DependencyNode> getChildren() { return Collections.unmodifiableList(children); }

    /** Package-private: only {@link DependencyGraph} should mutate the graph structure. */
    void addParent(DependencyNode parent) {
        if (!parents.contains(parent)) parents.add(parent);
    }

    void addChild(DependencyNode child) {
        if (!children.contains(child)) children.add(child);
    }

    public boolean isRoot() {
        return parents.isEmpty();
    }

    public boolean isLeaf() {
        return children.isEmpty();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof DependencyNode)) return false;
        return dependency.equals(((DependencyNode) o).dependency);
    }

    @Override
    public int hashCode() {
        return dependency.hashCode();
    }

    @Override
    public String toString() {
        return dependency.toString();
    }
}
