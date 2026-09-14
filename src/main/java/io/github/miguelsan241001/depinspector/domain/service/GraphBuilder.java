package io.github.miguelsan241001.depinspector.domain.service;

import io.github.miguelsan241001.depinspector.domain.model.*;

import java.util.*;

/**
 * Builds a {@link DependencyGraph} from raw dependency trails.
 *
 * <p>Maven's {@code artifact.getDependencyTrail()} returns a list of coordinates
 * representing the path from the project root to each artifact, e.g.:
 * {@code ["myapp:jar:1.0", "spring-boot:jar:2.7", "spring-context:jar:5.3", "aopalliance:jar:1.0"]}.
 * This builder converts those trails into graph edges:
 * root→spring-boot, spring-boot→spring-context, spring-context→aopalliance.
 */
public class GraphBuilder {

    /**
     * Builds a dependency graph.
     *
     * @param allDeps       all resolved {@link Dependency} objects (direct + transitive + plugins)
     * @param directGas     set of "groupId:artifactId" coordinates that are direct dependencies
     * @param trailsByGa    map from "groupId:artifactId" to its dependency trail
     *                      (list of "groupId:artifactId:classifier:version" strings as returned by Maven)
     */
    public DependencyGraph build(List<Dependency> allDeps,
                                  Set<String> directGas,
                                  Map<String, List<String>> trailsByGa) {
        DependencyGraph graph = new DependencyGraph();

        // 1. Add all nodes
        for (Dependency dep : allDeps) {
            graph.addNode(new DependencyNode(dep));
        }

        // 2. Build edges from trails
        for (Map.Entry<String, List<String>> entry : trailsByGa.entrySet()) {
            List<String> trail = entry.getValue();
            if (trail == null || trail.size() < 2) continue;

            // Trail entries are "groupId:artifactId:classifier:version" or "groupId:artifactId:version"
            for (int i = 0; i < trail.size() - 1; i++) {
                String parentGa = extractGa(trail.get(i));
                String childGa  = extractGa(trail.get(i + 1));
                if (parentGa != null && childGa != null) {
                    graph.addEdge(parentGa, childGa);
                }
            }
        }

        // 3. Mark roots (direct deps or nodes with no parents)
        for (DependencyNode node : graph.getAllDependencies()) {
            if (node.getParents().isEmpty()) {
                graph.markRoot(node);
            }
        }

        return graph;
    }

    /**
     * Extracts "groupId:artifactId" from a trail entry.
     * Trail entry format: "groupId:artifactId[:classifier]:version"
     */
    private String extractGa(String trailEntry) {
        if (trailEntry == null || trailEntry.isBlank()) return null;
        String[] parts = trailEntry.split(":");
        if (parts.length < 2) return null;
        return parts[0] + ":" + parts[1];
    }
}
