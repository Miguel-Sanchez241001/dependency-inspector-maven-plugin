package io.github.miguelsan241001.depinspector.adapter.maven;

import io.github.miguelsan241001.depinspector.domain.model.*;
import io.github.miguelsan241001.depinspector.domain.port.DependencySource;
import io.github.miguelsan241001.depinspector.domain.service.GraphBuilder;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.model.Plugin;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.logging.Log;
import org.apache.maven.project.MavenProject;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Implements {@link DependencySource} using Maven's resolved artifact graph.
 *
 * <p>Uses {@code artifact.getDependencyTrail()} to build real graph edges,
 * replacing the old single-parent {@code transitiveOrigin} field.</p>
 */
public class MavenDependencyAdapter implements DependencySource {

    private final MavenProject project;
    private final Log log;
    private final GraphBuilder graphBuilder;

    public MavenDependencyAdapter(MavenProject project, Log log) {
        this.project      = project;
        this.log          = log;
        this.graphBuilder = new GraphBuilder();
    }

    @Override
    public DependencyGraph buildGraph() throws MojoExecutionException {
        if (project.getModules() != null && !project.getModules().isEmpty()) {
            throw new MojoExecutionException(
                    "dependency-inspector does not support multi-module projects. " +
                    "Run the plugin on each module individually.");
        }

        Set<String> directGas = project.getDependencies().stream()
                .map(d -> d.getGroupId() + ":" + d.getArtifactId())
                .collect(Collectors.toSet());

        List<Dependency> allDeps        = new ArrayList<>();
        Map<String, List<String>> trails = new LinkedHashMap<>();

        // Resolved artifacts (direct + transitive)
        Set<Artifact> artifacts = project.getArtifacts();
        for (Artifact artifact : artifacts) {
            String ga = artifact.getGroupId() + ":" + artifact.getArtifactId();
            DependencyType type = directGas.contains(ga)
                    ? DependencyType.DIRECT : DependencyType.TRANSITIVE;

            Dependency dep = new Dependency(
                    artifact.getGroupId(),
                    artifact.getArtifactId(),
                    artifact.getVersion(),
                    artifact.getScope(),
                    type,
                    artifact.getFile());
            allDeps.add(dep);

            // Store dependency trail for graph edge construction
            List<String> trail = artifact.getDependencyTrail();
            if (trail != null && !trail.isEmpty()) {
                trails.put(ga, trail);
            }
        }

        // Build plugins as PLUGIN-typed dependencies
        for (Plugin plugin : project.getBuildPlugins()) {
            if (plugin.getVersion() == null) continue;
            Dependency dep = new Dependency(
                    plugin.getGroupId(),
                    plugin.getArtifactId(),
                    plugin.getVersion(),
                    "plugin",
                    DependencyType.PLUGIN);
            allDeps.add(dep);
        }

        log.info("Collected " + allDeps.size() + " dependencies (" +
                allDeps.stream().filter(d -> d.getType() == DependencyType.DIRECT).count() + " direct, " +
                allDeps.stream().filter(d -> d.getType() == DependencyType.TRANSITIVE).count() + " transitive, " +
                allDeps.stream().filter(d -> d.getType() == DependencyType.PLUGIN).count() + " plugins)");

        return graphBuilder.build(allDeps, directGas, trails);
    }
}
