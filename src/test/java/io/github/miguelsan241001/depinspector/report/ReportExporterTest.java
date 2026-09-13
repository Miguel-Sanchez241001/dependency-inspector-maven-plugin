package io.github.miguelsan241001.depinspector.report;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.miguelsan241001.depinspector.model.*;
import org.apache.maven.plugin.logging.Log;
import org.junit.jupiter.api.*;
import org.mockito.Mockito;

import java.io.File;
import java.nio.file.Files;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ReportExporterTest {

    private File outputDir;
    private Log mockLog;
    private ReportExporter exporter;
    private ObjectMapper mapper;

    @BeforeEach
    void setUp() throws Exception {
        outputDir = Files.createTempDirectory("dep-inspector-test").toFile();
        mockLog = Mockito.mock(Log.class);
        exporter = new ReportExporter(mockLog);
        mapper = new ObjectMapper();
    }

    @AfterEach
    void tearDown() {
        // cleanup temp dir
        for (File f : outputDir.listFiles() != null ? outputDir.listFiles() : new File[0]) {
            f.delete();
        }
        outputDir.delete();
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private AnalysisReport buildReport() {
        DependencyInfo dep = new DependencyInfo(
                "org.apache.logging.log4j", "log4j-core", "2.14.1",
                "compile", DependencyInfo.DependencyType.DIRECT);

        VulnerabilityInfo vuln = new VulnerabilityInfo();
        vuln.setId("GHSA-jfh8-c2jp-5657");
        vuln.setSummary("Log4Shell remote code execution");
        vuln.setCvssScore(10.0);
        vuln.setSeverity(VulnerabilityInfo.Severity.CRITICAL);
        vuln.setAliases(List.of("CVE-2021-44228"));

        UpgradeRecommendation rec = new UpgradeRecommendation(dep, UpgradeRecommendation.Strategy.UPGRADE_MINOR);
        rec.setTargetVersion("2.17.1");
        rec.setCompatibilityStatus(CompatibilityStatus.COMPATIBLE);

        AnalysisResult result = new AnalysisResult(dep);
        result.setVulnerabilities(List.of(vuln));
        result.setRecommendation(rec);

        return new AnalysisReport("my-app", "1.0.0", List.of(result));
    }

    // -----------------------------------------------------------------------
    // JSON export tests
    // -----------------------------------------------------------------------

    @Test
    void testJsonFileIsCreated() throws Exception {
        exporter.exportJson(buildReport(), outputDir);
        assertTrue(new File(outputDir, "report.json").exists(), "report.json should be created");
    }

    @Test
    void testJsonContainsProjectMetadata() throws Exception {
        exporter.exportJson(buildReport(), outputDir);
        JsonNode root = mapper.readTree(new File(outputDir, "report.json"));

        assertEquals("my-app", root.get("project").asText());
        assertEquals("1.0.0", root.get("version").asText());
        assertNotNull(root.get("generatedAt"), "generatedAt should be present");
    }

    @Test
    void testJsonSummaryFields() throws Exception {
        exporter.exportJson(buildReport(), outputDir);
        JsonNode summary = mapper.readTree(new File(outputDir, "report.json")).get("summary");

        assertEquals(1, summary.get("totalAnalyzed").asInt());
        assertEquals(1, summary.get("vulnerable").asInt());
        assertEquals(0, summary.get("clean").asInt());
    }

    @Test
    void testJsonVulnerabilityId() throws Exception {
        exporter.exportJson(buildReport(), outputDir);
        JsonNode vuln = mapper.readTree(new File(outputDir, "report.json"))
                .get("vulnerabilities").get(0)
                .get("vulnerabilities").get(0);

        assertEquals("GHSA-jfh8-c2jp-5657", vuln.get("id").asText());
        assertEquals("Log4Shell remote code execution", vuln.get("summary").asText());
        assertEquals("CRITICAL", vuln.get("severity").asText());
        assertEquals(10.0, vuln.get("cvssScore").asDouble(), 0.01);
    }

    @Test
    void testJsonVulnerabilityAliasesPresent() throws Exception {
        exporter.exportJson(buildReport(), outputDir);
        JsonNode vuln = mapper.readTree(new File(outputDir, "report.json"))
                .get("vulnerabilities").get(0)
                .get("vulnerabilities").get(0);

        JsonNode aliases = vuln.get("aliases");
        assertNotNull(aliases, "aliases should be present in JSON");
        assertTrue(aliases.isArray());
        assertEquals("CVE-2021-44228", aliases.get(0).asText());
    }

    @Test
    void testJsonRecommendationCompatibilityStatus() throws Exception {
        exporter.exportJson(buildReport(), outputDir);
        JsonNode rec = mapper.readTree(new File(outputDir, "report.json"))
                .get("vulnerabilities").get(0)
                .get("recommendation");

        assertEquals("UPGRADE_MINOR", rec.get("strategy").asText());
        assertEquals("COMPATIBLE", rec.get("compatibilityStatus").asText());
        assertEquals("2.17.1", rec.get("targetVersion").asText());
    }

    @Test
    void testJsonDependencyCoordinates() throws Exception {
        exporter.exportJson(buildReport(), outputDir);
        JsonNode dep = mapper.readTree(new File(outputDir, "report.json"))
                .get("vulnerabilities").get(0);

        assertEquals("org.apache.logging.log4j", dep.get("groupId").asText());
        assertEquals("log4j-core", dep.get("artifactId").asText());
        assertEquals("2.14.1", dep.get("version").asText());
        assertEquals("DIRECT", dep.get("type").asText());
    }

    // -----------------------------------------------------------------------
    // SARIF export tests
    // -----------------------------------------------------------------------

    @Test
    void testSarifFileIsCreated() throws Exception {
        exporter.exportSarif(buildReport(), outputDir);
        assertTrue(new File(outputDir, "report.sarif").exists(), "report.sarif should be created");
    }

    @Test
    void testSarifSchemaVersion() throws Exception {
        exporter.exportSarif(buildReport(), outputDir);
        JsonNode root = mapper.readTree(new File(outputDir, "report.sarif"));

        assertEquals("2.1.0", root.get("version").asText());
        assertNotNull(root.get("$schema"), "SARIF schema URI should be present");
    }

    @Test
    void testSarifToolDriverName() throws Exception {
        exporter.exportSarif(buildReport(), outputDir);
        JsonNode driver = mapper.readTree(new File(outputDir, "report.sarif"))
                .get("runs").get(0).get("tool").get("driver");

        assertEquals("dependency-inspector-maven-plugin", driver.get("name").asText());
        assertNotNull(driver.get("version"));
    }

    @Test
    void testSarifRuleIdMatchesVulnId() throws Exception {
        exporter.exportSarif(buildReport(), outputDir);
        JsonNode rules = mapper.readTree(new File(outputDir, "report.sarif"))
                .get("runs").get(0).get("tool").get("driver").get("rules");

        assertEquals(1, rules.size());
        assertEquals("GHSA-jfh8-c2jp-5657", rules.get(0).get("id").asText());
    }

    @Test
    void testSarifResultLevelForCritical() throws Exception {
        exporter.exportSarif(buildReport(), outputDir);
        JsonNode result = mapper.readTree(new File(outputDir, "report.sarif"))
                .get("runs").get(0).get("results").get(0);

        assertEquals("error", result.get("level").asText(),
                "CRITICAL severity should map to SARIF 'error' level");
    }

    @Test
    void testSarifResultLocationIsPomXml() throws Exception {
        exporter.exportSarif(buildReport(), outputDir);
        JsonNode location = mapper.readTree(new File(outputDir, "report.sarif"))
                .get("runs").get(0).get("results").get(0)
                .get("locations").get(0)
                .get("physicalLocation").get("artifactLocation");

        assertEquals("pom.xml", location.get("uri").asText());
    }

    @Test
    void testSarifResultMessageContainsCveAlias() throws Exception {
        exporter.exportSarif(buildReport(), outputDir);
        String msg = mapper.readTree(new File(outputDir, "report.sarif"))
                .get("runs").get(0).get("results").get(0)
                .get("message").get("text").asText();

        assertTrue(msg.contains("CVE-2021-44228"),
                "SARIF result message should mention CVE alias, got: " + msg);
    }

    @Test
    void testSarifFingerprintIsUnique() throws Exception {
        exporter.exportSarif(buildReport(), outputDir);
        JsonNode fingerprints = mapper.readTree(new File(outputDir, "report.sarif"))
                .get("runs").get(0).get("results").get(0)
                .get("fingerprints");

        assertNotNull(fingerprints, "Fingerprints should be present for deduplication");
        assertTrue(fingerprints.has("dependencyVulnerability/v1"));
    }

    @Test
    void testEmptyReportProducesValidSarif() throws Exception {
        AnalysisReport emptyReport = new AnalysisReport("empty-app", "1.0", List.of());
        exporter.exportSarif(emptyReport, outputDir);

        JsonNode root = mapper.readTree(new File(outputDir, "report.sarif"));
        assertEquals("2.1.0", root.get("version").asText());
        assertEquals(0, root.get("runs").get(0).get("results").size());
    }
}
