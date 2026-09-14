package io.github.miguelsan241001.depinspector.domain.model;

/** Severity level of a vulnerability. Ordered from most to least severe. */
public enum Severity {
    CRITICAL, HIGH, MEDIUM, LOW, NONE;

    /** Returns true if this severity is at least as severe as {@code threshold}. */
    public boolean isAtLeast(Severity threshold) {
        return this.ordinal() <= threshold.ordinal();
    }
}
