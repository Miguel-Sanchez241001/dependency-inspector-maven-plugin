package io.github.miguelsan241001.depinspector.model;

/**
 * Result of a binary-compatibility check between two versions of a library.
 */
public enum CompatibilityStatus {

    /** japicmp ran successfully and found no binary-breaking changes. */
    COMPATIBLE,

    /** japicmp ran successfully and found at least one binary-breaking change. */
    BREAKING,

    /**
     * The comparison could not be completed (JAR not resolvable, optional classpath
     * entries missing, etc.). The upgrade may or may not be safe — manual review needed.
     */
    INCONCLUSIVE,

    /** Compatibility was not checked (e.g. no target version available). */
    NOT_CHECKED
}
