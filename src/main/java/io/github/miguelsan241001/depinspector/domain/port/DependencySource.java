package io.github.miguelsan241001.depinspector.domain.port;

import io.github.miguelsan241001.depinspector.domain.model.DependencyGraph;
import org.apache.maven.plugin.MojoExecutionException;

/** Port for obtaining the full dependency graph of the current project. */
public interface DependencySource {

    /**
     * Builds and returns the resolved dependency graph.
     *
     * @throws MojoExecutionException if the graph cannot be built
     *         (e.g. multi-module project).
     */
    DependencyGraph buildGraph() throws MojoExecutionException;
}
