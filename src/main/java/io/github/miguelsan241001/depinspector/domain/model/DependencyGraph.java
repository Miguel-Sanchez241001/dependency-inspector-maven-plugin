package io.github.miguelsan241001.depinspector.domain.model;

import java.util.*;
import java.util.stream.Collectors;

/**
 * A directed acyclic graph of resolved Maven dependencies.
 * Root nodes represent the project itself; edges go from requirer to required.
 */
public class DependencyGraph {

    /** ga("groupId:artifactId") → node */
    private final Map<String, DependencyNode> nodesByGa = new LinkedHashMap<>();
    /** Nodes with no parents (the project root or roots). */
    private final List<DependencyNode> roots = new ArrayList<>();

    // -----------------------------------------------------------------------
    // Graph construction (package-private — used by GraphBuilder)
    // -----------------------------------------------------------------------

    public void addNode(DependencyNode node) {
        nodesByGa.putIfAbsent(node.getDependency().ga(), node);
    }

    public void addEdge(String parentGa, String childGa) {
        DependencyNode parent = nodesByGa.get(parentGa);
        DependencyNode child  = nodesByGa.get(childGa);
        if (parent == null || child == null) return;
        parent.addChild(child);
        child.addParent(parent);
    }

    public void markRoot(DependencyNode node) {
        if (!roots.contains(node)) roots.add(node);
    }

    // -----------------------------------------------------------------------
    // Query API
    // -----------------------------------------------------------------------

    /** All direct dependencies (depth-1 children of the project root). */
    public List<DependencyNode> getDirectDependencies() {
        return nodesByGa.values().stream()
                .filter(n -> n.getDependency().getType() == DependencyType.DIRECT)
                .collect(Collectors.toList());
    }

    /** All dependencies in the graph (direct + transitive + plugins). */
    public List<DependencyNode> getAllDependencies() {
        return Collections.unmodifiableList(new ArrayList<>(nodesByGa.values()));
    }

    public Optional<DependencyNode> findByGa(String groupId, String artifactId) {
        return Optional.ofNullable(nodesByGa.get(groupId + ":" + artifactId));
    }

    public Optional<DependencyNode> findByCoordinates(String groupId, String artifactId) {
        return findByGa(groupId, artifactId);
    }

    /**
     * Returns all paths from any root node to the given target node.
     * Each path is a list of nodes starting from the root and ending at target.
     */
    public List<List<DependencyNode>> getAllPaths(DependencyNode target) {
        List<List<DependencyNode>> result = new ArrayList<>();
        Deque<List<DependencyNode>> queue = new ArrayDeque<>();

        List<DependencyNode> startPath = new ArrayList<>();
        startPath.add(target);
        queue.add(startPath);

        while (!queue.isEmpty()) {
            List<DependencyNode> path = queue.poll();
            DependencyNode head = path.get(0);

            if (head.isRoot() || head.getParents().isEmpty()) {
                // path is already [root, ..., target] — add as-is
                result.add(new ArrayList<>(path));
            } else {
                for (DependencyNode parent : head.getParents()) {
                    if (!path.contains(parent)) { // prevent cycles
                        List<DependencyNode> extended = new ArrayList<>();
                        extended.add(parent);
                        extended.addAll(path);
                        queue.add(extended);
                    }
                }
            }
        }

        return result;
    }

    /**
     * Returns all descendants of the given node (transitive closure of children).
     */
    public Set<DependencyNode> getDescendants(DependencyNode node) {
        Set<DependencyNode> visited = new LinkedHashSet<>();
        collectDescendants(node, visited);
        return visited;
    }

    private void collectDescendants(DependencyNode node, Set<DependencyNode> visited) {
        for (DependencyNode child : node.getChildren()) {
            if (visited.add(child)) {
                collectDescendants(child, visited);
            }
        }
    }

    /** Serializes the graph to JSON for Canvas rendering in the HTML report. */
    public String toJson() {
        StringBuilder sb = new StringBuilder();
        sb.append("{\"nodes\":[");
        boolean firstNode = true;
        for (DependencyNode n : nodesByGa.values()) {
            if (!firstNode) sb.append(",");
            firstNode = false;
            Dependency d = n.getDependency();
            sb.append("{")
              .append("\"id\":\"").append(escapeJson(d.ga())).append("\",")
              .append("\"label\":\"").append(escapeJson(d.getArtifactId())).append("\",")
              .append("\"version\":\"").append(escapeJson(d.getVersion())).append("\",")
              .append("\"type\":\"").append(d.getType()).append("\",")
              .append("\"scope\":\"").append(escapeJson(d.getScope() != null ? d.getScope() : "")).append("\"")
              .append("}");
        }
        sb.append("],\"edges\":[");
        boolean firstEdge = true;
        for (DependencyNode parent : nodesByGa.values()) {
            for (DependencyNode child : parent.getChildren()) {
                if (!firstEdge) sb.append(",");
                firstEdge = false;
                sb.append("{")
                  .append("\"source\":\"").append(escapeJson(parent.getDependency().ga())).append("\",")
                  .append("\"target\":\"").append(escapeJson(child.getDependency().ga())).append("\"")
                  .append("}");
            }
        }
        sb.append("]}");
        return sb.toString();
    }

    private String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    public int size() {
        return nodesByGa.size();
    }

    @Override
    public String toString() {
        return "DependencyGraph{nodes=" + nodesByGa.size() + "}";
    }
}
