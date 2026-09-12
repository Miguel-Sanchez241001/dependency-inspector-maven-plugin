package io.github.miguelsan241001.depinspector.service;

import io.github.miguelsan241001.depinspector.model.DependencyInfo;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.model.Plugin;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.logging.Log;
import org.apache.maven.project.MavenProject;

import java.util.*;
import java.util.stream.Collectors;

public class DependencyCollector {

    private final MavenProject project;
    private final Log log;

    public DependencyCollector(MavenProject project, Log log) {
        this.project = project;
        this.log = log;
    }

    public List<DependencyInfo> collect() throws MojoExecutionException {
        if (project.getModules() != null && !project.getModules().isEmpty()) {
            throw new MojoExecutionException(
                    "dependency-inspector does not support multi-module projects. " +
                    "Run the plugin on each module individually.");
        }

        List<DependencyInfo> allDeps = new ArrayList<>();

        // Collect direct dependency coordinates for classification
        Set<String> directCoords = project.getDependencies().stream()
                .map(d -> d.getGroupId() + ":" + d.getArtifactId())
                .collect(Collectors.toSet());

        // Collect all resolved artifacts
        Set<Artifact> artifacts = project.getArtifacts();
        for (Artifact artifact : artifacts) {
            DependencyInfo dep = new DependencyInfo();
            dep.setGroupId(artifact.getGroupId());
            dep.setArtifactId(artifact.getArtifactId());
            dep.setVersion(artifact.getVersion());
            dep.setScope(artifact.getScope());

            String coords = artifact.getGroupId() + ":" + artifact.getArtifactId();
            if (directCoords.contains(coords)) {
                dep.setType(DependencyInfo.DependencyType.DIRECT);
            } else {
                dep.setType(DependencyInfo.DependencyType.TRANSITIVE);
                dep.setTransitiveOrigin(findTransitiveOrigin(artifact, directCoords));
            }

            if (artifact.getFile() != null) {
                dep.setJarFile(artifact.getFile());
            }

            allDeps.add(dep);
        }

        // Collect build plugins
        for (Plugin plugin : project.getBuildPlugins()) {
            DependencyInfo dep = new DependencyInfo();
            dep.setGroupId(plugin.getGroupId());
            dep.setArtifactId(plugin.getArtifactId());
            dep.setVersion(plugin.getVersion());
            dep.setScope("plugin");
            dep.setType(DependencyInfo.DependencyType.PLUGIN);
            allDeps.add(dep);
        }

        log.info("Collected " + allDeps.size() + " dependencies (" +
                allDeps.stream().filter(d -> d.getType() == DependencyInfo.DependencyType.DIRECT).count() + " direct, " +
                allDeps.stream().filter(d -> d.getType() == DependencyInfo.DependencyType.TRANSITIVE).count() + " transitive, " +
                allDeps.stream().filter(d -> d.getType() == DependencyInfo.DependencyType.PLUGIN).count() + " plugins)");

        return allDeps;
    }

    private String findTransitiveOrigin(Artifact artifact, Set<String> directCoords) {
        List<String> trail = artifact.getDependencyTrail();
        if (trail == null || trail.size() < 2) return null;

        // Trail[0] is the root project, trail[1] is the direct dependency
        for (String trailEntry : trail) {
            // trail entries look like: groupId:artifactId:jar:version
            String[] parts = trailEntry.split(":");
            if (parts.length >= 2) {
                String coords = parts[0] + ":" + parts[1];
                if (directCoords.contains(coords)) {
                    return coords;
                }
            }
        }
        return null;
    }
}
