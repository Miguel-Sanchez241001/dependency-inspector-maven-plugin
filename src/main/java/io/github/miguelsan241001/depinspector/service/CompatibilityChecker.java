package io.github.miguelsan241001.depinspector.service;

import io.github.miguelsan241001.depinspector.model.CompatibilityStatus;
import japicmp.cmp.JApiCmpArchive;
import japicmp.cmp.JarArchiveComparator;
import japicmp.cmp.JarArchiveComparatorOptions;

import japicmp.model.JApiClass;
import org.apache.maven.plugin.logging.Log;
import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.artifact.DefaultArtifact;
import org.eclipse.aether.repository.RemoteRepository;
import org.eclipse.aether.resolution.ArtifactRequest;
import org.eclipse.aether.resolution.ArtifactResolutionException;
import org.eclipse.aether.resolution.ArtifactResult;

import java.io.File;
import java.util.List;

public class CompatibilityChecker {

    private final RepositorySystem repoSystem;
    private final RepositorySystemSession repoSession;
    private final List<RemoteRepository> remoteRepositories;
    private final Log log;

    public CompatibilityChecker(RepositorySystem repoSystem,
                                 RepositorySystemSession repoSession,
                                 List<RemoteRepository> remoteRepositories,
                                 Log log) {
        this.repoSystem = repoSystem;
        this.repoSession = repoSession;
        this.remoteRepositories = remoteRepositories;
        this.log = log;
    }

    /**
     * Checks binary compatibility between {@code oldVersion} and {@code targetVersion}.
     *
     * @return {@link CompatibilityStatus#COMPATIBLE} if no breaking changes found,
     *         {@link CompatibilityStatus#BREAKING} if breaking changes detected,
     *         {@link CompatibilityStatus#INCONCLUSIVE} if JARs could not be resolved
     *         or the comparison failed for any reason.
     */
    public CompatibilityStatus checkCompatibility(String groupId, String artifactId,
                                                   String oldVersion, String targetVersion) {
        File oldJar = resolveArtifact(groupId, artifactId, oldVersion);
        File newJar = resolveArtifact(groupId, artifactId, targetVersion);

        if (oldJar == null || newJar == null) {
            log.warn("Could not resolve JARs for compatibility check: " +
                    groupId + ":" + artifactId + " " + oldVersion + " -> " + targetVersion +
                    ". Marking as INCONCLUSIVE.");
            return CompatibilityStatus.INCONCLUSIVE;
        }

        try {
            List<JApiClass> changes = doCompare(oldJar, oldVersion, newJar, targetVersion);
            boolean breaking = changes != null && changes.stream().anyMatch(c -> !c.isBinaryCompatible());
            return breaking ? CompatibilityStatus.BREAKING : CompatibilityStatus.COMPATIBLE;

        } catch (Exception e) {
            log.warn("japicmp comparison failed for " + groupId + ":" + artifactId +
                    " " + oldVersion + " -> " + targetVersion + ": " + e.getMessage() +
                    ". Marking as INCONCLUSIVE.");
            return CompatibilityStatus.INCONCLUSIVE;
        }
    }

    /**
     * Runs the japicmp binary comparison. Extracted as protected so tests can
     * override it without touching Aether or the filesystem.
     */
    protected List<JApiClass> doCompare(File oldJar, String oldVersion,
                                         File newJar, String newVersion) {
        JarArchiveComparatorOptions options = new JarArchiveComparatorOptions();
        options.setAccessModifier(japicmp.model.AccessModifier.PUBLIC);
        // Ignore missing optional classes — prevents NoClassDefFoundError for
        // optional deps (OSGi, Servlet API, DOM4J, etc.)
        options.getIgnoreMissingClasses().setIgnoreAllMissingClasses(true);

        JarArchiveComparator comparator = new JarArchiveComparator(options);
        return comparator.compare(
                java.util.Collections.singletonList(new JApiCmpArchive(oldJar, oldVersion)),
                java.util.Collections.singletonList(new JApiCmpArchive(newJar, newVersion)));
    }

    protected File resolveArtifact(String groupId, String artifactId, String version) {
        try {
            ArtifactRequest request = new ArtifactRequest();
            request.setArtifact(new DefaultArtifact(groupId, artifactId, "jar", version));
            request.setRepositories(remoteRepositories);

            ArtifactResult result = repoSystem.resolveArtifact(repoSession, request);
            return result.getArtifact().getFile();

        } catch (ArtifactResolutionException e) {
            log.warn("Could not resolve " + groupId + ":" + artifactId + ":" + version +
                    ". Check https://repo1.maven.org/maven2/" +
                    groupId.replace('.', '/') + "/" + artifactId + "/" + version);
            return null;
        }
    }
}
