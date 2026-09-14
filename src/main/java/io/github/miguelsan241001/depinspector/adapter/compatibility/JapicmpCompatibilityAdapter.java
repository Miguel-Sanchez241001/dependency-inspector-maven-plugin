package io.github.miguelsan241001.depinspector.adapter.compatibility;

import io.github.miguelsan241001.depinspector.domain.model.Dependency;
import io.github.miguelsan241001.depinspector.domain.port.CompatibilitySource;
import io.github.miguelsan241001.depinspector.model.CompatibilityStatus;
import io.github.miguelsan241001.depinspector.service.CompatibilityChecker;
import org.apache.maven.plugin.logging.Log;
import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.repository.RemoteRepository;

import java.util.List;

/**
 * Implements {@link CompatibilitySource} by delegating to the existing
 * {@link CompatibilityChecker} (japicmp-based binary comparison).
 */
public class JapicmpCompatibilityAdapter implements CompatibilitySource {

    private final CompatibilityChecker checker;

    public JapicmpCompatibilityAdapter(RepositorySystem repoSystem,
                                        RepositorySystemSession repoSession,
                                        List<RemoteRepository> remoteRepositories,
                                        Log log) {
        this.checker = new CompatibilityChecker(repoSystem, repoSession, remoteRepositories, log);
    }

    @Override
    public CompatibilityStatus check(Dependency from, Dependency to) {
        return checker.checkCompatibility(
                from.getGroupId(), from.getArtifactId(),
                from.getVersion(), to.getVersion());
    }
}
