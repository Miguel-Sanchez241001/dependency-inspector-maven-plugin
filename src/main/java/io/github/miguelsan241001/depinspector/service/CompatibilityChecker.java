package io.github.miguelsan241001.depinspector.service;

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

    public boolean hasBreakingChanges(String groupId, String artifactId, String oldVersion, String targetVersion) {
        File oldJar = resolveArtifact(groupId, artifactId, oldVersion);
        File newJar = resolveArtifact(groupId, artifactId, targetVersion);
        String newVersion = targetVersion;

        if (oldJar == null || newJar == null) {
            log.warn("Could not resolve JARs for compatibility check: " +
                    groupId + ":" + artifactId + " " + oldVersion + " -> " + newVersion +
                    ". Assuming no breaking changes (conservative).");
            return false;
        }

        try {
            JarArchiveComparatorOptions options = new JarArchiveComparatorOptions();
            options.setAccessModifier(japicmp.model.AccessModifier.PUBLIC);
            JarArchiveComparator comparator = new JarArchiveComparator(options);

            List<JApiClass> changes = comparator.compare(
                    java.util.Collections.singletonList(new JApiCmpArchive(oldJar, oldVersion)),
                    java.util.Collections.singletonList(new JApiCmpArchive(newJar, newVersion)));

            return changes.stream().anyMatch(c -> !c.isBinaryCompatible());

        } catch (Exception e) {
            log.warn("japicmp comparison failed for " + groupId + ":" + artifactId +
                    " " + oldVersion + " -> " + newVersion + ": " + e.getMessage());
            return false;
        }
    }

    private File resolveArtifact(String groupId, String artifactId, String version) {
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
