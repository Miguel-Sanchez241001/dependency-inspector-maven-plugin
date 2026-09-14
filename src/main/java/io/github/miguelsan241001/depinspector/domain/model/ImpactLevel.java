package io.github.miguelsan241001.depinspector.domain.model;

/**
 * Calculated impact level of a vulnerable dependency based on how it is used.
 * Ordered from highest to lowest impact.
 */
public enum ImpactLevel {
    /** Dependency is explicitly imported in non-test production code. */
    CRITICAL_EXPLICIT,
    /** Dependency is transitive in a non-test scope but not directly imported. */
    HIGH_TRANSITIVE,
    /** Dependency only appears in test-scoped paths. */
    LOW_TEST_ONLY,
    /** Dependency is not imported anywhere and appears unused. */
    NEGLIGIBLE_UNUSED
}
