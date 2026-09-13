package io.github.miguelsan241001.depinspector.service;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.miguelsan241001.depinspector.model.DependencyInfo;
import io.github.miguelsan241001.depinspector.model.VulnerabilityInfo;
import io.github.miguelsan241001.depinspector.util.RetryExecutor;
import okhttp3.*;
import org.apache.maven.plugin.logging.Log;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class OsvClient {

    private static final String OSV_BATCH_URL  = "https://api.osv.dev/v1/querybatch";
    private static final String OSV_VULN_URL   = "https://api.osv.dev/v1/vulns/";
    private static final int    BATCH_SIZE     = 50;
    private static final MediaType JSON = MediaType.get("application/json; charset=utf-8");

    private final OkHttpClient httpClient;
    private final ObjectMapper mapper;
    private final RetryExecutor retryExecutor;
    private final Log log;

    public OsvClient(OkHttpClient httpClient, Log log) {
        this.httpClient = httpClient;
        this.mapper = new ObjectMapper();
        this.log = log;
        this.retryExecutor = new RetryExecutor(log);
    }

    public Map<DependencyInfo, List<VulnerabilityInfo>> queryBatch(List<DependencyInfo> dependencies) {
        // Step 1 — identify which deps have vulnerabilities (querybatch returns IDs only)
        Map<DependencyInfo, List<String>> idsByDep = new LinkedHashMap<>();

        for (int i = 0; i < dependencies.size(); i += BATCH_SIZE) {
            List<DependencyInfo> batch = dependencies.subList(i, Math.min(i + BATCH_SIZE, dependencies.size()));
            Map<DependencyInfo, List<String>> batchIds = queryBatchIds(batch);
            if (batchIds != null) {
                idsByDep.putAll(batchIds);
            } else {
                for (DependencyInfo dep : batch) {
                    idsByDep.put(dep, Collections.emptyList());
                }
            }
        }

        // Step 2 — enrich: fetch full advisory for each unique vuln ID
        Set<String> uniqueIds = new LinkedHashSet<>();
        idsByDep.values().forEach(uniqueIds::addAll);

        Map<String, OsvVuln> vulnCache = new LinkedHashMap<>();
        for (String id : uniqueIds) {
            OsvVuln full = fetchVulnDetails(id);
            if (full != null) {
                vulnCache.put(id, full);
            }
        }

        // Step 3 — build final result using enriched data
        Map<DependencyInfo, List<VulnerabilityInfo>> results = new LinkedHashMap<>();
        for (Map.Entry<DependencyInfo, List<String>> entry : idsByDep.entrySet()) {
            List<VulnerabilityInfo> vulns = new ArrayList<>();
            for (String id : entry.getValue()) {
                OsvVuln full = vulnCache.get(id);
                if (full != null) {
                    vulns.add(mapVuln(full));
                } else {
                    // fallback: minimal info from ID alone
                    VulnerabilityInfo v = new VulnerabilityInfo();
                    v.setId(id);
                    vulns.add(v);
                }
            }
            results.put(entry.getKey(), vulns);
        }

        return results;
    }

    /** Fetches the full advisory detail for a single vulnerability ID. */
    private OsvVuln fetchVulnDetails(String id) {
        return retryExecutor.execute(() -> {
            Request request = new Request.Builder()
                    .url(getOsvVulnUrl() + id)
                    .get()
                    .build();
            try (Response response = httpClient.newCall(request).execute()) {
                if (!response.isSuccessful()) {
                    throw new IOException("OSV /vulns/" + id + " returned HTTP " + response.code());
                }
                String body = response.body() != null ? response.body().string() : "{}";
                return mapper.readValue(body, OsvVuln.class);
            }
        });
    }

    protected String getOsvVulnUrl() {
        return OSV_VULN_URL;
    }

    protected String getOsvBatchUrl() {
        return OSV_BATCH_URL;
    }

    /** Calls /v1/querybatch and returns only the vuln IDs per dep (no full details). */
    private Map<DependencyInfo, List<String>> queryBatchIds(List<DependencyInfo> batch) {
        return retryExecutor.execute(() -> {
            String requestJson = buildRequestJson(batch);
            RequestBody body = RequestBody.create(requestJson, JSON);
            Request request = new Request.Builder()
                    .url(getOsvBatchUrl())
                    .post(body)
                    .build();

            try (Response response = httpClient.newCall(request).execute()) {
                if (!response.isSuccessful()) {
                    throw new IOException("OSV API returned HTTP " + response.code());
                }
                String responseBody = response.body() != null ? response.body().string() : "{}";
                return parseIdsResponse(batch, responseBody);
            }
        });
    }

    private String buildRequestJson(List<DependencyInfo> batch) throws Exception {
        List<Map<String, Object>> queries = new ArrayList<>();
        for (DependencyInfo dep : batch) {
            Map<String, Object> pkg = new HashMap<>();
            pkg.put("name", dep.getGroupId() + ":" + dep.getArtifactId());
            pkg.put("ecosystem", "Maven");

            Map<String, Object> query = new HashMap<>();
            query.put("package", pkg);
            query.put("version", dep.getVersion());
            queries.add(query);
        }

        Map<String, Object> requestBody = new HashMap<>();
        requestBody.put("queries", queries);
        return mapper.writeValueAsString(requestBody);
    }

    /** Parses the querybatch response, extracting only the vuln IDs. */
    private Map<DependencyInfo, List<String>> parseIdsResponse(List<DependencyInfo> batch, String responseJson) throws Exception {
        Map<DependencyInfo, List<String>> result = new LinkedHashMap<>();

        BatchResponse batchResponse = mapper.readValue(responseJson, BatchResponse.class);
        List<QueryResult> queryResults = batchResponse.results != null ? batchResponse.results : Collections.emptyList();

        for (int i = 0; i < batch.size(); i++) {
            DependencyInfo dep = batch.get(i);
            List<String> ids = new ArrayList<>();

            if (i < queryResults.size() && queryResults.get(i).vulns != null) {
                for (OsvVuln v : queryResults.get(i).vulns) {
                    if (v.id != null) ids.add(v.id);
                }
            }

            result.put(dep, ids);
        }

        return result;
    }

    private VulnerabilityInfo mapVuln(OsvVuln osvVuln) {
        VulnerabilityInfo vuln = new VulnerabilityInfo();
        vuln.setId(osvVuln.id);
        vuln.setAliases(osvVuln.aliases != null ? osvVuln.aliases : Collections.emptyList());

        // Summary: use OSV summary field, fallback to first line of details
        String summary = osvVuln.summary;
        if (summary == null || summary.isBlank()) {
            summary = extractFirstLine(osvVuln.details);
        }
        vuln.setSummary(summary);
        vuln.setDetails(osvVuln.details);

        // --- CVSS score resolution (in priority order) ---
        double cvssScore = -1;
        VulnerabilityInfo.Severity severity = null;

        // 1. database_specific.cvss.score (GitHub Advisory DB — most common)
        if (osvVuln.databaseSpecific != null) {
            if (osvVuln.databaseSpecific.cvss != null && osvVuln.databaseSpecific.cvss.score > 0) {
                cvssScore = osvVuln.databaseSpecific.cvss.score;
            }
            // database_specific.severity: "CRITICAL", "HIGH", "MODERATE", "LOW"
            if (osvVuln.databaseSpecific.severity != null) {
                severity = parseSeverityString(osvVuln.databaseSpecific.severity);
            }
        }

        // 2. ecosystem_specific (NVD / other sources)
        if (cvssScore < 0 && osvVuln.ecosystemSpecific != null
                && osvVuln.ecosystemSpecific.cvss != null
                && osvVuln.ecosystemSpecific.cvss.score > 0) {
            cvssScore = osvVuln.ecosystemSpecific.cvss.score;
        }

        // 3. severity[].score — try parsing as plain number first, then as CVSS vector
        if (cvssScore < 0 && osvVuln.severity != null) {
            for (OsvSeverity sev : osvVuln.severity) {
                if (sev.score == null) continue;
                double parsed = parseScoreField(sev.score);
                if (parsed >= 0) {
                    cvssScore = parsed;
                    break;
                }
            }
        }

        vuln.setCvssScore(cvssScore);

        // Severity: prefer string from database_specific; fallback to numeric bands
        if (severity != null) {
            vuln.setSeverity(severity);
        } else if (cvssScore >= 0) {
            vuln.setSeverity(cvssToSeverity(cvssScore));
        } else {
            vuln.setSeverity(VulnerabilityInfo.Severity.NONE);
        }

        return vuln;
    }

    /**
     * Tries to extract a numeric CVSS score from a field that may be:
     * - a plain number ("9.8")
     * - a CVSS vector string ("CVSS:3.1/AV:N/AC:L/..." — not parseable, return -1)
     */
    private double parseScoreField(String value) {
        try {
            double d = Double.parseDouble(value);
            return (d >= 0 && d <= 10.0) ? d : -1;
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    /** Maps GitHub Advisory severity strings to our enum. */
    private VulnerabilityInfo.Severity parseSeverityString(String s) {
        if (s == null) return null;
        switch (s.toUpperCase()) {
            case "CRITICAL": return VulnerabilityInfo.Severity.CRITICAL;
            case "HIGH":     return VulnerabilityInfo.Severity.HIGH;
            case "MODERATE":
            case "MEDIUM":   return VulnerabilityInfo.Severity.MEDIUM;
            case "LOW":      return VulnerabilityInfo.Severity.LOW;
            default:         return VulnerabilityInfo.Severity.NONE;
        }
    }

    private VulnerabilityInfo.Severity cvssToSeverity(double score) {
        if (score >= 9.0) return VulnerabilityInfo.Severity.CRITICAL;
        if (score >= 7.0) return VulnerabilityInfo.Severity.HIGH;
        if (score >= 4.0) return VulnerabilityInfo.Severity.MEDIUM;
        if (score >  0)   return VulnerabilityInfo.Severity.LOW;
        return VulnerabilityInfo.Severity.NONE;
    }

    /** Returns the first non-blank line of a multi-line text, truncated to 200 chars. */
    private String extractFirstLine(String text) {
        if (text == null || text.isBlank()) return null;
        for (String line : text.split("\\r?\\n")) {
            String trimmed = line.trim();
            if (!trimmed.isEmpty()) {
                return trimmed.length() > 200 ? trimmed.substring(0, 200) + "…" : trimmed;
            }
        }
        return null;
    }

    // -----------------------------------------------------------------------
    // Jackson DTOs
    // -----------------------------------------------------------------------

    @JsonIgnoreProperties(ignoreUnknown = true)
    static class BatchResponse {
        public List<QueryResult> results;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    static class QueryResult {
        public List<OsvVuln> vulns;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    static class OsvVuln {
        public String id;
        public String summary;
        public String details;
        public List<String> aliases;
        public List<OsvSeverity> severity;

        @JsonProperty("database_specific")
        public DatabaseSpecific databaseSpecific;

        @JsonProperty("ecosystem_specific")
        public EcosystemSpecific ecosystemSpecific;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    static class OsvSeverity {
        public String type;
        public String score;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    static class DatabaseSpecific {
        /** "CRITICAL", "HIGH", "MODERATE", "LOW" — GitHub Advisory Database */
        public String severity;
        /** Numeric CVSS details block */
        public CvssInfo cvss;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    static class EcosystemSpecific {
        public CvssInfo cvss;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    static class CvssInfo {
        /** Numeric base score, e.g. 9.8 */
        public double score;
        @JsonProperty("vector_string")
        public String vectorString;
        @JsonProperty("scoring_type")
        public String scoringType;
    }
}
