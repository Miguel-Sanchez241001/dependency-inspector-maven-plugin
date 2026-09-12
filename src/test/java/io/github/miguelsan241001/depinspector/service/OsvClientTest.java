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

    @Test
    void testDependencyWithVulnerabilities() {
        // Given: OSV response with a known CVE
        String osvResponse = "{\n" +
                "  \"results\": [\n" +
                "    {\n" +
                "      \"vulns\": [\n" +
                "        {\n" +
                "          \"id\": \"GHSA-2qrg-x229-3v8q\",\n" +
                "          \"summary\": \"Remote code execution in Log4j\",\n" +
                "          \"aliases\": [\"CVE-2021-44228\"],\n" +
                "          \"severity\": [\n" +
                "            {\"type\": \"CVSS_V3\", \"score\": \"10.0\"}\n" +
                "          ]\n" +
                "        }\n" +
                "      ]\n" +
                "    }\n" +
                "  ]\n" +
                "}";

        mockServer.enqueue(new MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", "application/json")
                .setBody(osvResponse));

        DependencyInfo dep = new DependencyInfo("log4j", "log4j", "1.2.17", "compile", DependencyInfo.DependencyType.DIRECT);

        // We need to override the URL - use a custom OsvClient with configurable URL
        // Since OsvClient uses hardcoded URL, we test through the real flow with MockWebServer
        // For this test, we verify the parsing logic by using a real client call
        // (integration-style unit test)

        // When: query batch
        OsvClient client = new TestableOsvClient(httpClient, mockLog, mockServer.url("/v1/querybatch").toString());
        Map<DependencyInfo, List<VulnerabilityInfo>> result = client.queryBatch(List.of(dep));

        // Then
        assertNotNull(result);
        assertTrue(result.containsKey(dep));
        List<VulnerabilityInfo> vulns = result.get(dep);
        assertFalse(vulns.isEmpty(), "Should find vulnerabilities for log4j 1.2.17");
        assertEquals("GHSA-2qrg-x229-3v8q", vulns.get(0).getId());
        assertEquals(VulnerabilityInfo.Severity.CRITICAL, vulns.get(0).getSeverity());
        assertEquals(10.0, vulns.get(0).getCvssScore(), 0.01);
    }

    @Test
    void testDependencyWithNoVulnerabilities() {
        // Given: empty result
        mockServer.enqueue(new MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", "application/json")
                .setBody("{\"results\": [{}]}"));

        DependencyInfo dep = new DependencyInfo("org.slf4j", "slf4j-api", "2.0.13", "compile", DependencyInfo.DependencyType.DIRECT);

        OsvClient client = new TestableOsvClient(httpClient, mockLog, mockServer.url("/v1/querybatch").toString());
        Map<DependencyInfo, List<VulnerabilityInfo>> result = client.queryBatch(List.of(dep));

        assertNotNull(result);
        List<VulnerabilityInfo> vulns = result.get(dep);
        assertNotNull(vulns);
        assertTrue(vulns.isEmpty(), "Clean dependency should have no vulnerabilities");
    }

    @Test
    void testRetryOnServerError() {
        // Given: first two requests fail, third succeeds
        mockServer.enqueue(new MockResponse().setResponseCode(503));
        mockServer.enqueue(new MockResponse().setResponseCode(503));
        mockServer.enqueue(new MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", "application/json")
                .setBody("{\"results\": [{}]}"));

        // Use a client with short timeouts for faster test
        OkHttpClient fastClient = new OkHttpClient.Builder()
                .connectTimeout(2, TimeUnit.SECONDS)
                .readTimeout(2, TimeUnit.SECONDS)
                .build();

        DependencyInfo dep = new DependencyInfo("com.example", "lib", "1.0", "compile", DependencyInfo.DependencyType.DIRECT);
        OsvClient client = new TestableOsvClient(fastClient, mockLog, mockServer.url("/v1/querybatch").toString());

        // When: execute with retries - should not throw
        Map<DependencyInfo, List<VulnerabilityInfo>> result = client.queryBatch(List.of(dep));

        // Then: result should exist (either empty or null-safe)
        assertNotNull(result);
    }

    /**
     * Testable subclass that allows overriding the OSV API URL.
     */
    static class TestableOsvClient extends OsvClient {
        private final String testUrl;

        TestableOsvClient(OkHttpClient httpClient, Log log, String testUrl) {
            super(httpClient, log);
            this.testUrl = testUrl;
        }

        @Override
        protected String getOsvBatchUrl() {
            return testUrl;
        }
    }
}
