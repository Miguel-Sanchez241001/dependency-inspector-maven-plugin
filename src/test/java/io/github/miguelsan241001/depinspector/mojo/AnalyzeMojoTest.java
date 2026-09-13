package io.github.miguelsan241001.depinspector.mojo;

import io.github.miguelsan241001.depinspector.model.CompatibilityStatus;
import io.github.miguelsan241001.depinspector.model.UpgradeRecommendation;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Smoke and contract tests for AnalyzeMojo structure.
 * Full integration testing is covered by OsvClientTest, VersionResolverTest,
 * and ReportExporterTest.
 */
class AnalyzeMojoTest {

    @Test
    void testMojoCanBeInstantiated() {
        assertDoesNotThrow(() -> new AnalyzeMojo());
    }

    // -----------------------------------------------------------------------
    // Parameter contract tests — verify that all documented @Parameter fields
    // exist with correct types so breaking refactors are caught early.
    // -----------------------------------------------------------------------

    @Test
    void testHasSkipSslVerificationField() throws NoSuchFieldException {
        Field f = AnalyzeMojo.class.getDeclaredField("skipSslVerification");
        assertEquals(boolean.class, f.getType());
    }

    @Test
    void testHasOutputDirectoryField() throws NoSuchFieldException {
        assertNotNull(AnalyzeMojo.class.getDeclaredField("outputDirectory"));
    }

    @Test
    void testHasOutputFormatsField() throws NoSuchFieldException {
        Field f = AnalyzeMojo.class.getDeclaredField("outputFormats");
        assertEquals(String.class, f.getType());
    }

    @Test
    void testHasFailOnCvssField() throws NoSuchFieldException {
        Field f = AnalyzeMojo.class.getDeclaredField("failOnCvss");
        assertEquals(double.class, f.getType());
    }

    @Test
    void testHasFailOnSeverityField() throws NoSuchFieldException {
        Field f = AnalyzeMojo.class.getDeclaredField("failOnSeverity");
        assertEquals(String.class, f.getType());
    }

    @Test
    void testHasExcludeArtifactsField() throws NoSuchFieldException {
        Field f = AnalyzeMojo.class.getDeclaredField("excludeArtifacts");
        assertEquals(String.class, f.getType());
    }

    @Test
    void testHasMinCvssField() throws NoSuchFieldException {
        Field f = AnalyzeMojo.class.getDeclaredField("minCvss");
        assertEquals(double.class, f.getType());
    }

    // -----------------------------------------------------------------------
    // CompatibilityStatus model contract
    // -----------------------------------------------------------------------

    @Test
    void testCompatibilityStatusConvenienceMethod() {
        UpgradeRecommendation rec = new UpgradeRecommendation();

        rec.setCompatibilityStatus(CompatibilityStatus.BREAKING);
        assertTrue(rec.isHasBreakingChanges(), "BREAKING should return true from isHasBreakingChanges()");

        rec.setCompatibilityStatus(CompatibilityStatus.COMPATIBLE);
        assertFalse(rec.isHasBreakingChanges(), "COMPATIBLE should return false");

        rec.setCompatibilityStatus(CompatibilityStatus.INCONCLUSIVE);
        assertFalse(rec.isHasBreakingChanges(), "INCONCLUSIVE should return false (conservative)");

        rec.setCompatibilityStatus(CompatibilityStatus.NOT_CHECKED);
        assertFalse(rec.isHasBreakingChanges(), "NOT_CHECKED should return false");
    }

    @Test
    void testCompatibilityStatusDefaultIsNotChecked() {
        UpgradeRecommendation rec = new UpgradeRecommendation();
        assertEquals(CompatibilityStatus.NOT_CHECKED, rec.getCompatibilityStatus(),
                "Default compatibility status should be NOT_CHECKED");
    }

    @Test
    void testSetNullCompatibilityStatusDefaultsToNotChecked() {
        UpgradeRecommendation rec = new UpgradeRecommendation();
        rec.setCompatibilityStatus(CompatibilityStatus.COMPATIBLE);
        rec.setCompatibilityStatus(null);
        assertEquals(CompatibilityStatus.NOT_CHECKED, rec.getCompatibilityStatus(),
                "Setting null should fall back to NOT_CHECKED");
    }
}
