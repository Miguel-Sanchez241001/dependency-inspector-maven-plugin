package io.github.miguelsan241001.depinspector.domain.port;

import io.github.miguelsan241001.depinspector.domain.model.Dependency;
import io.github.miguelsan241001.depinspector.model.CompatibilityStatus;

/** Port for checking binary compatibility between two versions of a dependency. */
public interface CompatibilitySource {

    /**
     * Checks whether upgrading from {@code from} to {@code to} introduces
     * binary-incompatible changes.
     */
    CompatibilityStatus check(Dependency from, Dependency to);
}
