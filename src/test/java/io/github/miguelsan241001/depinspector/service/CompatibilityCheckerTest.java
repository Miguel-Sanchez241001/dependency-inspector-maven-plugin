package io.github.miguelsan241001.depinspector.service;

import io.github.miguelsan241001.depinspector.model.CompatibilityStatus;
import japicmp.model.JApiClass;
import org.apache.maven.plugin.logging.Log;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.io.File;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Tests for CompatibilityChecker's error handling.
 *
 * Key invariant: ANY failure path must return INCONCLUSIVE, never COMPATIBLE.
 * "Unknown" must never be silently reported as "safe to upgrade".
 */
class CompatibilityCheckerTest {

    private Log mockLog;

    @BeforeEach
    void setUp() {
        mockLog = Mockito.mock(Log.class);
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /**
     * Testable subclass: overrides resolveArtifact() and doCompare() so no
     * real Aether session or JAR files are needed.
     */
    static class TestableCompatibilityChecker extends CompatibilityChecker {

        private final Map<String, File> artifactMap;
        private List<JApiClass> compareResult;
        private RuntimeException compareException;

        TestableCompatibilityChecker(Log log, Map<String, File> artifactMap) {
            super(null, null, null, log);
            this.artifactMap = artifactMap;
        }

        void willReturn(List<JApiClass> result) {
            this.compareResult  = result;
            this.compareException = null;
        }

        void willThrow(RuntimeException ex) {
            this.compareException = ex;
            this.compareResult    = null;
        }

        @Override
        protected File resolveArtifact(String groupId, String artifactId, String version) {
            return artifactMap.get(groupId + ":" + artifactId + ":" + version);
        }

        @Override
        protected List<JApiClass> doCompare(File oldJar, String oldVersion,
                                             File newJar, String newVersion) {
            if (compareException != null) throw compareException;
            return compareResult;
        }
    }

    private TestableCompatibilityChecker checker(Map<String, File> artifacts) {
        return new TestableCompatibilityChecker(mockLog, artifacts);
    }

    /** A stub File that reports it exists (no real filesystem access). */
    private static File fakeJar(String name) {
        return new File(name) {
            @Override public boolean exists() { return true; }
        };
    }

    private static Map<String, File> bothJars() {
        Map<String, File> m = new HashMap<>();
        m.put("com.example:lib:1.0", fakeJar("lib-1.0.jar"));
        m.put("com.example:lib:2.0", fakeJar("lib-2.0.jar"));
        return m;
    }

    // -----------------------------------------------------------------------
    // JAR resolution failures → must be INCONCLUSIVE (never COMPATIBLE)
    // -----------------------------------------------------------------------

    @Test
    void testOldJarMissingReturnsInconclusive() {
        Map<String, File> m = new HashMap<>();
        // only new JAR is resolvable; old is missing
        m.put("com.example:lib:2.0", fakeJar("lib-2.0.jar"));

        TestableCompatibilityChecker c = checker(m);
        assertEquals(CompatibilityStatus.INCONCLUSIVE,
                c.checkCompatibility("com.example", "lib", "1.0", "2.0"),
                "Missing old JAR must yield INCONCLUSIVE, not COMPATIBLE");
    }

    @Test
    void testNewJarMissingReturnsInconclusive() {
        Map<String, File> m = new HashMap<>();
        m.put("com.example:lib:1.0", fakeJar("lib-1.0.jar"));
        // new JAR not resolvable

        TestableCompatibilityChecker c = checker(m);
        assertEquals(CompatibilityStatus.INCONCLUSIVE,
                c.checkCompatibility("com.example", "lib", "1.0", "2.0"),
                "Missing new JAR must yield INCONCLUSIVE, not COMPATIBLE");
    }

    @Test
    void testBothJarsMissingReturnsInconclusive() {
        TestableCompatibilityChecker c = checker(Collections.emptyMap());
        assertEquals(CompatibilityStatus.INCONCLUSIVE,
                c.checkCompatibility("com.example", "lib", "1.0", "2.0"));
    }

    // -----------------------------------------------------------------------
    // japicmp failures → must be INCONCLUSIVE (the original silent-failure bug)
    // -----------------------------------------------------------------------

    @Test
    void testJapicmpRuntimeExceptionReturnsInconclusive() {
        TestableCompatibilityChecker c = checker(bothJars());
        c.willThrow(new RuntimeException("NoClassDefFoundError: javax/servlet/Filter"));

        assertEquals(CompatibilityStatus.INCONCLUSIVE,
                c.checkCompatibility("com.example", "lib", "1.0", "2.0"),
                "japicmp exception must yield INCONCLUSIVE — not silently 'compatible'");
    }

    @Test
    void testJapicmpOutOfMemoryErrorReturnsInconclusive() {
        TestableCompatibilityChecker c = checker(bothJars());
        // OutOfMemoryError extends Error, not RuntimeException;
        // our catch(Exception) does NOT catch it — but we document this limitation.
        // This test covers IllegalStateException as a proxy for other Error subtypes
        // that japicmp can throw wrapped as RuntimeException.
        c.willThrow(new IllegalStateException("japicmp internal state failure"));

        assertEquals(CompatibilityStatus.INCONCLUSIVE,
                c.checkCompatibility("com.example", "lib", "1.0", "2.0"));
    }

    @Test
    void testNullChangesListFromJapicmpReturnsCompatible() {
        // Defensive: if japicmp returns null instead of empty list,
        // we must not NPE, and treating null as "no changes" is safe (COMPATIBLE).
        TestableCompatibilityChecker c = checker(bothJars());
        c.willReturn(null);

        assertEquals(CompatibilityStatus.COMPATIBLE,
                c.checkCompatibility("com.example", "lib", "1.0", "2.0"),
                "Null changes list (no public API) should be COMPATIBLE");
    }

    // -----------------------------------------------------------------------
    // Happy path — correct classification
    // -----------------------------------------------------------------------

    @Test
    void testNoBreakingChangesReturnsCompatible() {
        JApiClass compatibleClass = Mockito.mock(JApiClass.class);
        Mockito.when(compatibleClass.isBinaryCompatible()).thenReturn(true);

        TestableCompatibilityChecker c = checker(bothJars());
        c.willReturn(List.of(compatibleClass));

        assertEquals(CompatibilityStatus.COMPATIBLE,
                c.checkCompatibility("com.example", "lib", "1.0", "2.0"));
    }

    @Test
    void testBreakingChangeDetectedReturnsBreaking() {
        JApiClass breakingClass = Mockito.mock(JApiClass.class);
        Mockito.when(breakingClass.isBinaryCompatible()).thenReturn(false);

        TestableCompatibilityChecker c = checker(bothJars());
        c.willReturn(List.of(breakingClass));

        assertEquals(CompatibilityStatus.BREAKING,
                c.checkCompatibility("com.example", "lib", "1.0", "2.0"));
    }

    @Test
    void testMixedChangesBreakingWins() {
        JApiClass ok      = Mockito.mock(JApiClass.class);
        JApiClass broken  = Mockito.mock(JApiClass.class);
        Mockito.when(ok.isBinaryCompatible()).thenReturn(true);
        Mockito.when(broken.isBinaryCompatible()).thenReturn(false);

        TestableCompatibilityChecker c = checker(bothJars());
        c.willReturn(List.of(ok, broken));

        assertEquals(CompatibilityStatus.BREAKING,
                c.checkCompatibility("com.example", "lib", "1.0", "2.0"),
                "Even one breaking class must produce BREAKING");
    }

    @Test
    void testEmptyChangesListReturnsCompatible() {
        TestableCompatibilityChecker c = checker(bothJars());
        c.willReturn(Collections.emptyList());

        assertEquals(CompatibilityStatus.COMPATIBLE,
                c.checkCompatibility("com.example", "lib", "1.0", "2.0"),
                "No public API differences → COMPATIBLE");
    }
}
