package io.github.miguelsan241001.depinspector.service;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.miguelsan241001.depinspector.model.DependencyInfo;
import io.github.miguelsan241001.depinspector.model.VulnerabilityInfo;
import io.github.miguelsan241001.depinspector.util.RetryExecutor;
import okhttp3.*;
import org.apache.maven.plugin.logging.Log;

import java.io.IOException;
import java.util.*;

public class OsvClient {

    private static final String OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch";
    private static final int BATCH_SIZE = 50;
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
        Map<DependencyInfo, List<VulnerabilityInfo>> results = new LinkedHashMap<>();

        for (int i = 0; i < dependencies.size(); i += BATCH_SIZE) {
            List<DependencyInfo> batch = dependencies.subList(i, Math.min(i + BATCH_SIZE, dependencies.size()));
            Map<DependencyInfo, List<VulnerabilityInfo>> batchResult = queryBatchInternal(batch);
            if (batchResult != null) {
                results.putAll(batchResult);
            } else {
                // On failure, mark all as empty (no vulns found)
                for (DependencyInfo dep : batch) {
                    results.put(dep, Collections.emptyList());
                }
            }
        }

        return results;
    }

    protected String getOsvBatchUrl() {
        return OSV_BATCH_URL;
    }

    private Map<DependencyInfo, List<VulnerabilityInfo>> queryBatchInternal(List<DependencyInfo> batch) {
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
                return parseResponse(batch, responseBody);
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

    private Map<DependencyInfo, List<VulnerabilityInfo>> parseResponse(List<DependencyInfo> batch, String responseJson) throws Exception {
        Map<DependencyInfo, List<VulnerabilityInfo>> result = new LinkedHashMap<>();

        BatchResponse batchResponse = mapper.readValue(responseJson, BatchResponse.class);
        List<QueryResult> queryResults = batchResponse.results != null ? batchResponse.results : Collections.emptyList();

        for (int i = 0; i < batch.size(); i++) {
            DependencyInfo dep = batch.get(i);
            List<VulnerabilityInfo> vulns = new ArrayList<>();

            if (i < queryResults.size() && queryResults.get(i).vulns != null) {
                for (OsvVuln osvVuln : queryResults.get(i).vulns) {
                    vulns.add(mapVuln(osvVuln));
                }
            }

            result.put(dep, vulns);
        }

        return result;
    }

    private VulnerabilityInfo mapVuln(OsvVuln osvVuln) {
        VulnerabilityInfo vuln = new VulnerabilityInfo();
        vuln.setId(osvVuln.id);
        vuln.setSummary(osvVuln.summary);
        vuln.setDetails(osvVuln.details);
        vuln.setAliases(osvVuln.aliases != null ? osvVuln.aliases : Collections.emptyList());

        // Extract CVSS V3 score
        if (osvVuln.severity != null) {
            for (OsvSeverity sev : osvVuln.severity) {
                if ("CVSS_V3".equals(sev.type) && sev.score != null) {
                    try {
                        double score = parseCvssScore(sev.score);
                        vuln.setCvssScore(score);
                        vuln.setSeverity(cvssToSeverity(score));
                    } catch (Exception e) {
                        log.debug("Could not parse CVSS score: " + sev.score);
                    }
                    break;
                }
            }
        }

        if (vuln.getCvssScore() < 0) {
            // Try to infer severity from database_specific or ecosystem_specific
            vuln.setSeverity(VulnerabilityInfo.Severity.NONE);
        }

        return vuln;
    }

    private double parseCvssScore(String cvssVector) {
        // CVSS vectors look like: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
        // Score might be embedded or we need to calculate. OSV sometimes returns just the score.
        try {
            return Double.parseDouble(cvssVector);
        } catch (NumberFormatException e) {
            // It's a vector string, return -1 (we can't easily compute without a library)
            return -1;
        }
    }

    private VulnerabilityInfo.Severity cvssToSeverity(double score) {
        if (score >= 9.0) return VulnerabilityInfo.Severity.CRITICAL;
        if (score >= 7.0) return VulnerabilityInfo.Severity.HIGH;
        if (score >= 4.0) return VulnerabilityInfo.Severity.MEDIUM;
        if (score > 0) return VulnerabilityInfo.Severity.LOW;
        return VulnerabilityInfo.Severity.NONE;
    }

    // --- Jackson DTOs ---

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
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    static class OsvSeverity {
        public String type;
        public String score;
    }
}
