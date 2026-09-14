package io.github.miguelsan241001.depinspector.domain.model;

/** How a dependency appears in the project. */
public enum DependencyType {
    /** Declared directly in the project's own pom.xml. */
    DIRECT,
    /** Pulled in transitively through another dependency. */
    TRANSITIVE,
    /** A Maven build plugin (not a runtime dependency). */
    PLUGIN
}
