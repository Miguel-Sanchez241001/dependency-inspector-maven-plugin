package io.github.miguelsan241001.depinspector.domain.service;

import io.github.miguelsan241001.depinspector.domain.model.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

class GraphBuilderTest {

    private GraphBuilder builder;

    @BeforeEach
    void setUp() {
        builder = new GraphBuilder();
    }

    @Test
    void singleDirectDependency_isAddedAsNode() {
        Dependency dep = dep("com.example", "lib", "1.0", "compile", DependencyType.DIRECT);
        Set<String> directGas = Set.of("com.example:lib");
        Map<String, List<String>> trails = new LinkedHashMap<>();
        trails.put("com.example:lib", List.of("root:jar:1.0", "com.example:lib:jar:1.0"));

        DependencyGraph graph = builder.build(List.of(dep), directGas, trails);

        assertEquals(1, graph.size());
        Optional<DependencyNode> node = graph.findByCoordinates("com.example", "lib");
        assertTrue(node.isPresent());
        assertEquals("com.example:lib:1.0", node.get().getDependency().coordinates());
    }

    @Test
    void trailBuildsEdgesBetweenNodes() {
        // spring-boot → spring-context → aopalliance
        Dependency springBoot     = dep("org.springframework.boot", "spring-boot",     "2.7.0", "compile", DependencyType.DIRECT);
        Dependency springContext  = dep("org.springframework",      "spring-context",  "5.3.0", "compile", DependencyType.TRANSITIVE);
        Dependency aopalliance    = dep("aopalliance",              "aopalliance",     "1.0",   "compile", DependencyType.TRANSITIVE);

        Set<String> directGas = Set.of("org.springframework.boot:spring-boot");
        Map<String, List<String>> trails = new LinkedHashMap<>();
        trails.put("org.springframework:spring-context",
                List.of("myapp:jar:1.0", "org.springframework.boot:spring-boot:jar:2.7.0",
                        "org.springframework:spring-context:jar:5.3.0"));
        trails.put("aopalliance:aopalliance",
                List.of("myapp:jar:1.0", "org.springframework.boot:spring-boot:jar:2.7.0",
                        "org.springframework:spring-context:jar:5.3.0",
                        "aopalliance:aopalliance:jar:1.0"));

        DependencyGraph graph = builder.build(
                List.of(springBoot, springContext, aopalliance), directGas, trails);

        Optional<DependencyNode> springContextNode =
                graph.findByCoordinates("org.springframework", "spring-context");
        assertTrue(springContextNode.isPresent(), "spring-context should be in graph");

        Optional<DependencyNode> aopallianceNode =
                graph.findByCoordinates("aopalliance", "aopalliance");
        assertTrue(aopallianceNode.isPresent(), "aopalliance should be in graph");

        // Verify aopalliance has spring-context as a parent
        boolean aopallianceHasSpringContextParent = aopallianceNode.get().getParents().stream()
                .anyMatch(n -> n.getDependency().getArtifactId().equals("spring-context"));
        assertTrue(aopallianceHasSpringContextParent,
                "aopalliance should have spring-context as parent");
    }

    @Test
    void getAllPaths_returnsPathsFromRoot() {
        Dependency a = dep("com.a", "a", "1.0", "compile", DependencyType.DIRECT);
        Dependency b = dep("com.b", "b", "1.0", "compile", DependencyType.TRANSITIVE);
        Dependency c = dep("com.c", "c", "1.0", "compile", DependencyType.TRANSITIVE);

        Set<String> directGas = Set.of("com.a:a");
        Map<String, List<String>> trails = new LinkedHashMap<>();
        // a → b → c
        trails.put("com.b:b",
                List.of("myapp:jar:1.0", "com.a:a:jar:1.0", "com.b:b:jar:1.0"));
        trails.put("com.c:c",
                List.of("myapp:jar:1.0", "com.a:a:jar:1.0", "com.b:b:jar:1.0", "com.c:c:jar:1.0"));

        DependencyGraph graph = builder.build(List.of(a, b, c), directGas, trails);

        DependencyNode cNode = graph.findByCoordinates("com.c", "c").orElseThrow();
        List<List<DependencyNode>> paths = graph.getAllPaths(cNode);

        assertFalse(paths.isEmpty(), "Should find at least one path");
        // Each path should end at C
        for (List<DependencyNode> path : paths) {
            assertEquals("c", path.get(path.size() - 1).getDependency().getArtifactId());
        }
    }

    @Test
    void emptyDependencyList_producesEmptyGraph() {
        DependencyGraph graph = builder.build(
                Collections.emptyList(), Collections.emptySet(), Collections.emptyMap());
        assertEquals(0, graph.size());
        assertTrue(graph.getAllDependencies().isEmpty());
    }

    @Test
    void directDependencies_classifiedCorrectly() {
        Dependency direct     = dep("com.example", "direct",     "1.0", "compile", DependencyType.DIRECT);
        Dependency transitive = dep("com.example", "transitive", "2.0", "compile", DependencyType.TRANSITIVE);

        Set<String> directGas = Set.of("com.example:direct");
        DependencyGraph graph = builder.build(
                List.of(direct, transitive), directGas, Collections.emptyMap());

        List<DependencyNode> directNodes = graph.getDirectDependencies();
        assertEquals(1, directNodes.size());
        assertEquals("direct", directNodes.get(0).getDependency().getArtifactId());
    }

    @Test
    void toJson_producesValidJson() {
        Dependency dep = dep("com.example", "lib", "1.0", "compile", DependencyType.DIRECT);
        DependencyGraph graph = builder.build(List.of(dep), Set.of("com.example:lib"), Collections.emptyMap());

        String json = graph.toJson();
        assertNotNull(json);
        assertTrue(json.startsWith("{"));
        assertTrue(json.contains("\"nodes\""));
        assertTrue(json.contains("\"edges\""));
        assertTrue(json.contains("com.example:lib"));
    }

    private Dependency dep(String g, String a, String v, String scope, DependencyType type) {
        return new Dependency(g, a, v, scope, type);
    }
}
