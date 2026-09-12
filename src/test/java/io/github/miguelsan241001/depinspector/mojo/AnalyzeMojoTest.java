package io.github.miguelsan241001.depinspector.mojo;

import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Smoke tests for AnalyzeMojo structure.
 * The @Mojo annotation has RetentionPolicy.CLASS so it is not available at runtime.
 * Full integration testing is covered by OsvClientTest and VersionResolverTest.
 */
class AnalyzeMojoTest {

    @Test
    void testMojoCanBeInstantiated() {
        assertDoesNotThrow(() -> new AnalyzeMojo());
    }

    @Test
    void testMojoHasSkipSslField() throws NoSuchFieldException {
        Field field = AnalyzeMojo.class.getDeclaredField("skipSslVerification");
        assertNotNull(field);
        assertEquals(boolean.class, field.getType());
    }

    @Test
    void testMojoHasOutputDirectoryField() throws NoSuchFieldException {
        Field field = AnalyzeMojo.class.getDeclaredField("outputDirectory");
        assertNotNull(field);
    }
}
