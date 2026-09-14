package io.github.miguelsan241001.depinspector.domain.port;

import io.github.miguelsan241001.depinspector.domain.model.Dependency;

import java.util.List;

/** Port for discovering available versions of a dependency. */
public interface VersionSource {

    /**
     * Returns all stable versions available for the given dependency,
     * sorted from newest to oldest. Excludes snapshots, alphas, betas, and RCs.
     */
    List<String> findAvailableVersions(Dependency dep);

    /** Returns true if the specified version of the dependency has known vulnerabilities. */
    boolean hasVulnerabilities(Dependency dep);
}
