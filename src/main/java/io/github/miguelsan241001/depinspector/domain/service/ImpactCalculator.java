package io.github.miguelsan241001.depinspector.domain.service;

import io.github.miguelsan241001.depinspector.domain.model.*;

import java.util.List;

/**
 * Calculates the {@link Impact} of a vulnerable dependency by combining graph
 * position data (paths from root) with actual source-code usage data.
 */
public class ImpactCalculator {

    /**
     * Calculates the impact of a vulnerable dependency.
     *
     * @param node   the graph node for the vulnerable dependency
     * @param graph  the full dependency graph
     * @param usages source-code usages found by the usage scanner
     */
    public Impact calculate(DependencyNode node, DependencyGraph graph, List<Usage> usages) {
        List<List<DependencyNode>> paths = graph.getAllPaths(node);

        boolean explicitImport = usages != null && !usages.isEmpty();
        boolean onlyTest = paths.isEmpty() || paths.stream().allMatch(this::isAllTestScoped);

        ImpactLevel level;
        if (explicitImport && !onlyTest) {
            level = ImpactLevel.CRITICAL_EXPLICIT;
        } else if (!onlyTest) {
            level = ImpactLevel.HIGH_TRANSITIVE;
        } else if (onlyTest) {
            level = ImpactLevel.LOW_TEST_ONLY;
        } else {
            level = ImpactLevel.NEGLIGIBLE_UNUSED;
        }

        return new Impact(node.getDependency(), usages, paths, level);
    }

    /** Returns true if every node in the path is test-scoped. */
    private boolean isAllTestScoped(List<DependencyNode> path) {
        return path.stream().allMatch(n -> n.getDependency().isTestScoped());
    }
}
