package io.github.miguelsan241001.depinspector.report;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import io.github.miguelsan241001.depinspector.model.*;
import org.apache.maven.plugin.logging.Log;

import java.io.File;
import java.io.IOException;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Exports an {@link AnalysisReport} to machine-readable formats:
 * <ul>
 *   <li>JSON — structured report for internal tooling</li>
 *   <li>SARIF 2.1.0 — GitHub / GitLab Code Scanning compatible</li>
 * </ul>
 */
public class ReportExporter {

    private static final String PLUGIN_VERSION = "1.1.0";
    private static final DateTimeFormatter ISO_FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'");

    private final Log log;
    private final ObjectMapper mapper;

    public ReportExporter(Log log) {
        this.log = log;
        this.mapper = new ObjectMapper();
        this.mapper.enable(SerializationFeature.INDENT_OUTPUT);
    }

    // -----------------------------------------------------------------------
    // JSON export
    // -----------------------------------------------------------------------

    public File exportJson(AnalysisReport report, File outputDir) throws IOException {
        outputDir.mkdirs();
        File out = new File(outputDir, "report.json");

        Map<String, Object> root = new LinkedHashMap<>();
        root.put("project", report.getProjectArtifactId());
        root.put("version", report.getProjectVersion());
        root.put("generatedAt", report.getGeneratedAt().format(ISO_FMT));
        root.put("summary", buildJsonSummary(report));
        root.put("vulnerabilities", buildJsonVulnerabilities(report));

        mapper.writeValue(out, root);
        log.info("JSON report written: " + out.getAbsolutePath());
        return out;
    }

    private Map<String, Object> buildJsonSummary(AnalysisReport report) {
        Map<String, Object> s = new LinkedHashMap<>();
        s.put("totalAnalyzed", report.getResults() != null ? report.getResults().size() : 0);
        s.put("vulnerable", report.countVulnerable());
        s.put("clean", report.countClean());
        s.put("skipped", report.countSkipped());
        s.put("scopeIssues", report.getScopeIssues() != null ? report.getScopeIssues().size() : 0);
        return s;
    }

    private List<Map<String, Object>> buildJsonVulnerabilities(AnalysisReport report) {
        if (report.getResults() == null) return Collections.emptyList();
        return report.getVulnerableResults().stream().map(result -> {
            DependencyInfo dep = result.getDependency();
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("groupId", dep.getGroupId());
            entry.put("artifactId", dep.getArtifactId());
            entry.put("version", dep.getVersion());
            entry.put("scope", dep.getScope());
            entry.put("type", dep.getType() != null ? dep.getType().name() : "DIRECT");
            if (dep.getTransitiveOrigin() != null) {
                entry.put("transitiveOrigin", dep.getTransitiveOrigin());
            }
            entry.put("vulnerabilities", buildJsonVulnList(result.getVulnerabilities()));
            if (result.getRecommendation() != null) {
                entry.put("recommendation", buildJsonRecommendation(result.getRecommendation()));
            }
            if (result.getUsages() != null && !result.getUsages().isEmpty()) {
                entry.put("usages", result.getUsages().stream()
                        .map(UsageLocation::toString).collect(Collectors.toList()));
            }
            return entry;
        }).collect(Collectors.toList());
    }

    private List<Map<String, Object>> buildJsonVulnList(List<VulnerabilityInfo> vulns) {
        if (vulns == null) return Collections.emptyList();
        return vulns.stream().map(v -> {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", v.getId());
            m.put("summary", v.getSummary() != null ? v.getSummary() : "");
            m.put("severity", v.getSeverity() != null ? v.getSeverity().name() : "NONE");
            m.put("cvssScore", v.getCvssScore() >= 0 ? v.getCvssScore() : null);
            if (v.getAliases() != null && !v.getAliases().isEmpty()) {
                m.put("aliases", v.getAliases());
            }
            return m;
        }).collect(Collectors.toList());
    }

    private Map<String, Object> buildJsonRecommendation(UpgradeRecommendation rec) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("strategy", rec.getStrategy().name());
        m.put("compatibilityStatus", rec.getCompatibilityStatus().name());
        if (rec.getTargetVersion() != null) m.put("targetVersion", rec.getTargetVersion());
        if (rec.getUpgradeCommand() != null) m.put("upgradeCommand", rec.getUpgradeCommand());
        if (rec.getAlternativeSuggestion() != null) m.put("alternativeSuggestion", rec.getAlternativeSuggestion());
        return m;
    }

    // -----------------------------------------------------------------------
    // SARIF 2.1.0 export
    // -----------------------------------------------------------------------

    public File exportSarif(AnalysisReport report, File outputDir) throws IOException {
        outputDir.mkdirs();
        File out = new File(outputDir, "report.sarif");

        Map<String, Object> sarif = new LinkedHashMap<>();
        sarif.put("$schema", "https://json.schemastore.org/sarif-2.1.0.json");
        sarif.put("version", "2.1.0");
        sarif.put("runs", Collections.singletonList(buildSarifRun(report)));

        mapper.writeValue(out, sarif);
        log.info("SARIF report written: " + out.getAbsolutePath());
        return out;
    }

    private Map<String, Object> buildSarifRun(AnalysisReport report) {
        // Collect unique rules (one per vulnerability ID)
        Map<String, Map<String, Object>> rulesById = new LinkedHashMap<>();
        List<Map<String, Object>> results = new ArrayList<>();

        if (report.getResults() != null) {
            for (AnalysisResult ar : report.getVulnerableResults()) {
                DependencyInfo dep = ar.getDependency();
                if (ar.getVulnerabilities() == null) continue;

                for (VulnerabilityInfo vuln : ar.getVulnerabilities()) {
                    // Register rule once
                    rulesById.computeIfAbsent(vuln.getId(), id -> buildSarifRule(vuln));

                    // Build result
                    results.add(buildSarifResult(vuln, dep));
                }
            }
        }

        Map<String, Object> driver = new LinkedHashMap<>();
        driver.put("name", "dependency-inspector-maven-plugin");
        driver.put("version", PLUGIN_VERSION);
        driver.put("informationUri", "https://github.com/Miguel-Sanchez241001/dependency-inspector-maven-plugin");
        driver.put("rules", new ArrayList<>(rulesById.values()));

        Map<String, Object> tool = new LinkedHashMap<>();
        tool.put("driver", driver);

        Map<String, Object> run = new LinkedHashMap<>();
        run.put("tool", tool);
        run.put("results", results);
        return run;
    }

    private Map<String, Object> buildSarifRule(VulnerabilityInfo vuln) {
        Map<String, Object> rule = new LinkedHashMap<>();
        rule.put("id", vuln.getId());
        rule.put("name", "VulnerableDependency");

        String shortDesc = vuln.getSummary() != null ? vuln.getSummary() : vuln.getId();
        rule.put("shortDescription", singleText(shortDesc));

        String cvssStr = vuln.getCvssScore() >= 0
                ? " (CVSS " + String.format("%.1f", vuln.getCvssScore()) + ")"
                : "";
        rule.put("fullDescription", singleText(shortDesc + cvssStr));

        rule.put("defaultConfiguration", Collections.singletonMap("level", severityToSarifLevel(vuln.getSeverity())));

        // Help with CVE links
        List<String> aliases = vuln.getAliases();
        if (aliases != null && !aliases.isEmpty()) {
            String firstCve = aliases.stream().filter(a -> a.startsWith("CVE-")).findFirst().orElse(aliases.get(0));
            Map<String, Object> help = new LinkedHashMap<>();
            help.put("text", "See " + firstCve + " at https://osv.dev/vulnerability/" + vuln.getId());
            help.put("markdown", "See [" + firstCve + "](https://osv.dev/vulnerability/" + vuln.getId() + ")");
            rule.put("help", help);

            List<Map<String, String>> relationships = aliases.stream()
                    .filter(a -> a.startsWith("CVE-"))
                    .map(cve -> {
                        Map<String, String> rel = new LinkedHashMap<>();
                        rel.put("target", cve);
                        rel.put("kind", "superset");
                        return rel;
                    }).collect(Collectors.toList());
            if (!relationships.isEmpty()) {
                rule.put("relationships", relationships);
            }
        }

        return rule;
    }

    private Map<String, Object> buildSarifResult(VulnerabilityInfo vuln, DependencyInfo dep) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("ruleId", vuln.getId());
        result.put("level", severityToSarifLevel(vuln.getSeverity()));

        String msg = dep.getCoordinates() + " is affected by " + vuln.getId();
        if (vuln.getSummary() != null && !vuln.getSummary().isBlank()) {
            msg += ": " + vuln.getSummary();
        }
        List<String> aliases = vuln.getAliases();
        if (aliases != null && !aliases.isEmpty()) {
            String cveList = aliases.stream().filter(a -> a.startsWith("CVE-"))
                    .collect(Collectors.joining(", "));
            if (!cveList.isBlank()) msg += " (" + cveList + ")";
        }
        result.put("message", singleText(msg));

        // Location: pom.xml
        Map<String, Object> artifactLoc = new LinkedHashMap<>();
        artifactLoc.put("uri", "pom.xml");
        artifactLoc.put("uriBaseId", "%SRCROOT%");
        Map<String, Object> physLoc = new LinkedHashMap<>();
        physLoc.put("artifactLocation", artifactLoc);
        result.put("locations", Collections.singletonList(
                Collections.singletonMap("physicalLocation", physLoc)));

        // Fingerprint based on dep coords + vuln id
        result.put("fingerprints", Collections.singletonMap(
                "dependencyVulnerability/v1",
                dep.getCoordinates() + "/" + vuln.getId()));

        return result;
    }

    private String severityToSarifLevel(VulnerabilityInfo.Severity severity) {
        if (severity == null) return "note";
        switch (severity) {
            case CRITICAL:
            case HIGH:   return "error";
            case MEDIUM: return "warning";
            case LOW:
            default:     return "note";
        }
    }

    private Map<String, String> singleText(String text) {
        return Collections.singletonMap("text", text);
    }
}
