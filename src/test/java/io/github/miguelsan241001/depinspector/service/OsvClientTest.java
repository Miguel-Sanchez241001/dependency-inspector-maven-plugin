package io.github.miguelsan241001.depinspector.service;

import io.github.miguelsan241001.depinspector.model.DependencyInfo;
import io.github.miguelsan241001.depinspector.model.VulnerabilityInfo;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.OkHttpClient;
import org.apache.maven.plugin.logging.Log;
import org.junit.jupiter.api.*;
import org.mockito.Mockito;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

/**
 * OsvClient uses a two-step protocol:
 *  1. POST /v1/querybatch  → returns vuln IDs only
 *  2. GET  /v1/vulns/{id}  → returns full advisory details
 *
 * Each test must enqueue BOTH responses in MockWebServer order.
 */
class OsvClientTest {

    private MockWebServer mockServer;
    private OkHttpClient httpClient;
    private Log mockLog;

    @BeforeEach
    void setUp() throws IOException {
        mockServer = new MockWebServer();
        mockServer.start();
        httpClient = new OkHttpClient.Builder()
                .connectTimeout(5, TimeUnit.SECONDS)
                .readTimeout(5, TimeUnit.SECONDS)
                .build();
        mockLog = Mockito.mock(Log.class);
    }

    @AfterEach
    void tearDown() throws IOException {
        mockServer.shutdown();
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private OsvClient client() {
        String base = mockServer.url("/").toString();
        return new TestableOsvClient(httpClient, mockLog,
                base + "v1/querybatch",
                base + "v1/vulns/");
    }

    private DependencyInfo dep(String g, String a, String v) {
        return new DependencyInfo(g, a, v, "compile", DependencyInfo.DependencyType.DIRECT);
    }

    /** Enqueue the querybatch response (IDs only) */
    private void enqueueBatch(String vulnId) {
        String body = "{\"results\":[{\"vulns\":[{\"id\":\"" + vulnId + "\"}]}]}";
        mockServer.enqueue(new MockResponse().setResponseCode(200)
                .setHeader("Content-Type", "application/json").setBody(body));
    }

    /** Enqueue an empty batch (no vulns) */
    private void enqueueBatchEmpty() {
        mockServer.enqueue(new MockResponse().setResponseCode(200)
                .setHeader("Content-Type", "application/json")
                .setBody("{\"results\":[{}]}"));
    }

    /** Enqueue the full advisory detail */
    private void enqueueVulnDetail(String json) {
        mockServer.enqueue(new MockResponse().setResponseCode(200)
                .setHeader("Content-Type", "application/json").setBody(json));
    }

    // -----------------------------------------------------------------------
    // Basic detection
    // -----------------------------------------------------------------------

    @Test
    void testDependencyWithVulnerabilities_basicFields() {
        enqueueBatch("GHSA-2qrg-x229-3v8q");
        enqueueVulnDetail("{" +
                "\"id\":\"GHSA-2qrg-x229-3v8q\"," +
                "\"summary\":\"Remote code execution in Log4j\"," +
                "\"aliases\":[\"CVE-2021-44228\"]," +
                "\"severity\":[{\"type\":\"CVSS_V3\",\"score\":\"10.0\"}]" +
                "}");

        Map<DependencyInfo, List<VulnerabilityInfo>> result =
                client().queryBatch(List.of(dep("log4j", "log4j", "1.2.17")));

        List<VulnerabilityInfo> vulns = result.values().iterator().next();
        assertFalse(vulns.isEmpty());

        VulnerabilityInfo v = vulns.get(0);
        assertEquals("GHSA-2qrg-x229-3v8q", v.getId());
        assertEquals("Remote code execution in Log4j", v.getSummary());
        assertEquals(10.0, v.getCvssScore(), 0.01);
        assertEquals(VulnerabilityInfo.Severity.CRITICAL, v.getSeverity());
        assertTrue(v.getAliases().contains("CVE-2021-44228"), "should contain CVE alias");
    }

    @Test
    void testDependencyWithNoVulnerabilities() {
        enqueueBatchEmpty();
        // No vuln detail request will be made

        Map<DependencyInfo, List<VulnerabilityInfo>> result =
                client().queryBatch(List.of(dep("org.slf4j", "slf4j-api", "2.0.13")));

        List<VulnerabilityInfo> vulns = result.values().iterator().next();
        assertNotNull(vulns);
        assertTrue(vulns.isEmpty(), "Clean dependency should have no vulnerabilities");
    }

    @Test
    void testRetryOnServerError() {
        // Batch fails twice, succeeds third time → no vuln detail needed
        mockServer.enqueue(new MockResponse().setResponseCode(503));
        mockServer.enqueue(new MockResponse().setResponseCode(503));
        enqueueBatchEmpty();

        OkHttpClient fastClient = new OkHttpClient.Builder()
                .connectTimeout(2, TimeUnit.SECONDS).readTimeout(2, TimeUnit.SECONDS).build();

        String base = mockServer.url("/").toString();
        OsvClient c = new TestableOsvClient(fastClient, mockLog,
                base + "v1/querybatch", base + "v1/vulns/");

        assertNotNull(c.queryBatch(List.of(dep("com.example", "lib", "1.0"))));
    }

    // -----------------------------------------------------------------------
    // CVSS parsing — root cause of "NONE N/A" bug
    // -----------------------------------------------------------------------

    @Test
    void testCvssFromDatabaseSpecificNumericScore() {
        enqueueBatch("GHSA-abc-123");
        enqueueVulnDetail("{" +
                "\"id\":\"GHSA-abc-123\"," +
                "\"summary\":\"Test vulnerability\"," +
                "\"severity\":[{\"type\":\"CVSS_V3\",\"score\":\"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\"}]," +
                "\"database_specific\":{\"severity\":\"CRITICAL\",\"cvss\":{\"score\":9.8}}" +
                "}");

        VulnerabilityInfo v = client().queryBatch(
                List.of(dep("com.example", "lib", "1.0")))
                .values().iterator().next().get(0);

        assertEquals(9.8, v.getCvssScore(), 0.01,
                "Should parse numeric CVSS from database_specific.cvss.score");
        assertEquals(VulnerabilityInfo.Severity.CRITICAL, v.getSeverity());
    }

    @Test
    void testCvssVectorStringFallsBackToSeverityString() {
        enqueueBatch("GHSA-def-456");
        enqueueVulnDetail("{" +
                "\"id\":\"GHSA-def-456\"," +
                "\"summary\":\"High severity vuln\"," +
                "\"severity\":[{\"type\":\"CVSS_V3\",\"score\":\"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H\"}]," +
                "\"database_specific\":{\"severity\":\"HIGH\"}" +
                "}");

        VulnerabilityInfo v = client().queryBatch(
                List.of(dep("com.example", "lib", "2.0")))
                .values().iterator().next().get(0);

        assertEquals(VulnerabilityInfo.Severity.HIGH, v.getSeverity(),
                "Should map HIGH from database_specific.severity");
    }

    @Test
    void testDatabaseSpecificSeverityModerateMapsTOMedium() {
        enqueueBatch("GHSA-mod-123");
        enqueueVulnDetail("{" +
                "\"id\":\"GHSA-mod-123\"," +
                "\"database_specific\":{\"severity\":\"MODERATE\"}" +
                "}");

        VulnerabilityInfo v = client().queryBatch(
                List.of(dep("com.example", "lib", "3.0")))
                .values().iterator().next().get(0);

        assertEquals(VulnerabilityInfo.Severity.MEDIUM, v.getSeverity(),
                "MODERATE from GitHub Advisory should map to MEDIUM");
    }

    @Test
    void testSeverityPlainNumericScore() {
        enqueueBatch("GHSA-num-789");
        enqueueVulnDetail("{" +
                "\"id\":\"GHSA-num-789\"," +
                "\"summary\":\"Medium vuln\"," +
                "\"severity\":[{\"type\":\"CVSS_V3\",\"score\":\"6.5\"}]" +
                "}");

        VulnerabilityInfo v = client().queryBatch(
                List.of(dep("com.example", "lib", "4.0")))
                .values().iterator().next().get(0);

        assertEquals(6.5, v.getCvssScore(), 0.01);
        assertEquals(VulnerabilityInfo.Severity.MEDIUM, v.getSeverity());
    }

    // -----------------------------------------------------------------------
    // Summary fallback
    // -----------------------------------------------------------------------

    @Test
    void testSummaryFallbackFromDetails() {
        enqueueBatch("GHSA-nosummary");
        enqueueVulnDetail("{" +
                "\"id\":\"GHSA-nosummary\"," +
                "\"details\":\"This is the details field.\\nSecond line.\"" +
                "}");

        VulnerabilityInfo v = client().queryBatch(
                List.of(dep("com.example", "lib", "5.0")))
                .values().iterator().next().get(0);

        assertEquals("This is the details field.", v.getSummary(),
                "Should fall back to first line of details when summary is absent");
    }

    @Test
    void testBlankSummaryFallsBackToDetails() {
        enqueueBatch("GHSA-blanksummary");
        enqueueVulnDetail("{" +
                "\"id\":\"GHSA-blanksummary\"," +
                "\"summary\":\"\"," +
                "\"details\":\"Details line one.\\nDetails line two.\"" +
                "}");

        VulnerabilityInfo v = client().queryBatch(
                List.of(dep("com.example", "lib", "6.0")))
                .values().iterator().next().get(0);

        assertEquals("Details line one.", v.getSummary(),
                "Blank summary should fall back to first line of details");
    }

    // -----------------------------------------------------------------------
    // CVE aliases
    // -----------------------------------------------------------------------

    @Test
    void testMultipleCveAliases() {
        enqueueBatch("GHSA-multi-alias");
        enqueueVulnDetail("{" +
                "\"id\":\"GHSA-multi-alias\"," +
                "\"summary\":\"Multi-alias vuln\"," +
                "\"aliases\":[\"CVE-2021-1234\",\"CVE-2021-5678\",\"SNYK-JAVA-001\"]" +
                "}");

        VulnerabilityInfo v = client().queryBatch(
                List.of(dep("com.example", "lib", "7.0")))
                .values().iterator().next().get(0);

        List<String> aliases = v.getAliases();
        assertNotNull(aliases);
        assertEquals(3, aliases.size());
        assertTrue(aliases.contains("CVE-2021-1234"));
        assertTrue(aliases.contains("CVE-2021-5678"));
        assertTrue(aliases.contains("SNYK-JAVA-001"));
    }

    @Test
    void testNoAliasesReturnsEmptyList() {
        enqueueBatch("GHSA-no-alias");
        enqueueVulnDetail("{\"id\":\"GHSA-no-alias\",\"summary\":\"Vuln without aliases\"}");

        VulnerabilityInfo v = client().queryBatch(
                List.of(dep("com.example", "lib", "8.0")))
                .values().iterator().next().get(0);

        assertNotNull(v.getAliases(), "aliases should never be null");
        assertTrue(v.getAliases().isEmpty(), "should return empty list when no aliases present");
    }

    // -----------------------------------------------------------------------
    // Batch ordering
    // -----------------------------------------------------------------------

    @Test
    void testBatchResultsPreserveOrderWithMixedVulnAndClean() {
        DependencyInfo vulnDep  = dep("log4j", "log4j", "1.2.17");
        DependencyInfo cleanDep = dep("org.slf4j", "slf4j-api", "2.0.13");

        // Step 1: batch IDs response (vuln first, clean second)
        mockServer.enqueue(new MockResponse().setResponseCode(200)
                .setHeader("Content-Type", "application/json")
                .setBody("{\"results\":[{\"vulns\":[{\"id\":\"GHSA-vuln\"}]},{}]}"));

        // Step 2: full advisory for the one vuln
        enqueueVulnDetail("{\"id\":\"GHSA-vuln\",\"summary\":\"Log4j CVE\"," +
                "\"aliases\":[\"CVE-2021-44228\"]}");

        Map<DependencyInfo, List<VulnerabilityInfo>> result =
                client().queryBatch(List.of(vulnDep, cleanDep));

        assertFalse(result.get(vulnDep).isEmpty(),  "First dep should be vulnerable");
        assertTrue(result.get(cleanDep).isEmpty(),  "Second dep should be clean");
    }

    // -----------------------------------------------------------------------
    // Testable subclass (overrides both URL points)
    // -----------------------------------------------------------------------

    static class TestableOsvClient extends OsvClient {
        private final String batchUrl;
        private final String vulnBaseUrl;

        TestableOsvClient(OkHttpClient httpClient, Log log, String batchUrl, String vulnBaseUrl) {
            super(httpClient, log);
            this.batchUrl    = batchUrl;
            this.vulnBaseUrl = vulnBaseUrl;
        }

        @Override protected String getOsvBatchUrl() { return batchUrl; }
        @Override protected String getOsvVulnUrl()  { return vulnBaseUrl; }
    }
}
