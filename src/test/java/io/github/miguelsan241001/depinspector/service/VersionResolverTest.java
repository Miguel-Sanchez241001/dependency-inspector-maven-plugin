package io.github.miguelsan241001.depinspector.service;

import io.github.miguelsan241001.depinspector.model.DependencyInfo;
import io.github.miguelsan241001.depinspector.model.UpgradeRecommendation;
import io.github.miguelsan241001.depinspector.model.VulnerabilityInfo;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.OkHttpClient;
import org.apache.maven.plugin.logging.Log;
import org.junit.jupiter.api.*;
import org.mockito.Mockito;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.when;

class VersionResolverTest {

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
    void testFindsNewerCleanVersion() {
        // Given: maven-metadata.xml with multiple versions
        String metadata = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                "<metadata>\n" +
                "  <versioning>\n" +
                "    <versions>\n" +
                "      <version>1.2.17</version>\n" +
                "      <version>2.0.0</version>\n" +
                "      <version>2.1.0</version>\n" +
                "    </versions>\n" +
                "  </versioning>\n" +
                "</metadata>";

        mockServer.enqueue(new MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", "text/xml")
                .setBody(metadata));

        // OSV client mock: return empty vulns for 2.1.0 (clean version)
        OsvClient mockOsvClient = Mockito.mock(OsvClient.class);
        when(mockOsvClient.queryBatch(anyList())).thenAnswer(inv -> {
            List<DependencyInfo> deps = inv.getArgument(0);
            Map<DependencyInfo, List<VulnerabilityInfo>> result = new java.util.LinkedHashMap<>();
            for (DependencyInfo dep : deps) {
                // 2.0.0 has vulns, 2.1.0 is clean
                if ("2.0.0".equals(dep.getVersion())) {
                    VulnerabilityInfo vuln = new VulnerabilityInfo();
                    vuln.setId("CVE-TEST");
                    result.put(dep, List.of(vuln));
                } else {
                    result.put(dep, Collections.emptyList());
                }
            }
            return result;
        });

        DependencyInfo dep = new DependencyInfo("log4j", "log4j", "1.2.17", "compile", DependencyInfo.DependencyType.DIRECT);

        VersionResolver resolver = new TestableVersionResolver(httpClient, mockOsvClient, mockLog,
                mockServer.url("/").toString());
        UpgradeRecommendation rec = resolver.resolve(dep);

        assertNotNull(rec);
        assertEquals("2.1.0", rec.getTargetVersion());
        assertNotNull(rec.getStrategy());
    }

    @Test
    void testFallbackToExclusionForTransitive() {
        // Given: metadata with no newer versions
        String metadata = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                "<metadata>\n" +
                "  <versioning>\n" +
                "    <versions>\n" +
                "      <version>1.2.17</version>\n" +
                "    </versions>\n" +
                "  </versioning>\n" +
                "</metadata>";

        mockServer.enqueue(new MockResponse()
                .setResponseCode(200)
                .setBody(metadata));

        OsvClient mockOsvClient = Mockito.mock(OsvClient.class);
        when(mockOsvClient.queryBatch(anyList())).thenReturn(Collections.emptyMap());

        DependencyInfo dep = new DependencyInfo("log4j", "log4j", "1.2.17", "compile",
                DependencyInfo.DependencyType.TRANSITIVE);

        VersionResolver resolver = new TestableVersionResolver(httpClient, mockOsvClient, mockLog,
                mockServer.url("/").toString());
        UpgradeRecommendation rec = resolver.resolve(dep);

        assertNotNull(rec);
        assertEquals(UpgradeRecommendation.Strategy.EXCLUSION, rec.getStrategy());
        assertNotNull(rec.getExclusionSnippet());
    }

    @Test
    void testAlternativeLibSuggestion() {
        // Given: no newer clean versions available
        String metadata = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                "<metadata><versioning><versions>" +
                "<version>1.2.17</version>" +
                "</versions></versioning></metadata>";

        mockServer.enqueue(new MockResponse().setResponseCode(200).setBody(metadata));

        OsvClient mockOsvClient = Mockito.mock(OsvClient.class);
        when(mockOsvClient.queryBatch(anyList())).thenReturn(Collections.emptyMap());

        // log4j:log4j is in the alternatives map
        DependencyInfo dep = new DependencyInfo("log4j", "log4j", "1.2.17", "compile",
                DependencyInfo.DependencyType.DIRECT);

        VersionResolver resolver = new TestableVersionResolver(httpClient, mockOsvClient, mockLog,
                mockServer.url("/").toString());
        UpgradeRecommendation rec = resolver.resolve(dep);

        assertNotNull(rec);
        assertEquals(UpgradeRecommendation.Strategy.ALTERNATIVE_LIB, rec.getStrategy());
        assertNotNull(rec.getAlternativeSuggestion());
        assertTrue(rec.getAlternativeSuggestion().contains("logback"));
    }

    static class TestableVersionResolver extends VersionResolver {
        private final String baseUrl;

        TestableVersionResolver(OkHttpClient httpClient, OsvClient osvClient, Log log, String baseUrl) {
            super(httpClient, osvClient, log);
            this.baseUrl = baseUrl;
        }

        @Override
        protected String buildMetadataUrl(DependencyInfo dep) {
            return baseUrl + dep.getGroupId() + "/" + dep.getArtifactId() + "/maven-metadata.xml";
        }
    }
}
