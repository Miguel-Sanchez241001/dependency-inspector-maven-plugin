package io.github.miguelsan241001.depinspector.service;

import io.github.miguelsan241001.depinspector.model.DependencyInfo;
import io.github.miguelsan241001.depinspector.model.UpgradeRecommendation;
import io.github.miguelsan241001.depinspector.model.VulnerabilityInfo;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.apache.maven.artifact.versioning.ComparableVersion;
import org.apache.maven.plugin.logging.Log;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;

public class VersionResolver {

    private static final String CENTRAL_METADATA_URL =
            "https://repo1.maven.org/maven2/%s/%s/maven-metadata.xml";

    private static final Map<String, String> KNOWN_ALTERNATIVES = new HashMap<>();

    static {
        KNOWN_ALTERNATIVES.put("log4j:log4j", "ch.qos.logback:logback-classic");
        KNOWN_ALTERNATIVES.put("commons-collections:commons-collections", "org.apache.commons:commons-collections4");
        KNOWN_ALTERNATIVES.put("struts:struts", "org.springframework:spring-webmvc");
        KNOWN_ALTERNATIVES.put("com.google.guava:guava-jdk5", "com.google.guava:guava");
        KNOWN_ALTERNATIVES.put("commons-beanutils:commons-beanutils", "commons-beanutils:commons-beanutils");
        KNOWN_ALTERNATIVES.put("org.codehaus.jackson:jackson-mapper-asl", "com.fasterxml.jackson.core:jackson-databind");
        KNOWN_ALTERNATIVES.put("org.codehaus.jackson:jackson-core-asl", "com.fasterxml.jackson.core:jackson-core");
        KNOWN_ALTERNATIVES.put("xerces:xercesImpl", "org.apache.xerces:xercesImpl");
        KNOWN_ALTERNATIVES.put("xml-apis:xml-apis", "xerces:xercesImpl");
        KNOWN_ALTERNATIVES.put("org.springframework:spring-web", null); // upgrade only
    }

    private final OkHttpClient httpClient;
    private final OsvClient osvClient;
    private final Log log;

    public VersionResolver(OkHttpClient httpClient, OsvClient osvClient, Log log) {
        this.httpClient = httpClient;
        this.osvClient = osvClient;
        this.log = log;
    }

    public UpgradeRecommendation resolve(DependencyInfo dep) {
        List<String> availableVersions = fetchAvailableVersions(dep);
        if (availableVersions == null || availableVersions.isEmpty()) {
            log.warn("Could not fetch versions for " + dep.getCoordinates());
            return buildFallbackRecommendation(dep);
        }

        ComparableVersion currentVersion = new ComparableVersion(dep.getVersion());

        // Filter to newer versions only, sort descending
        List<ComparableVersion> newerVersions = availableVersions.stream()
                .map(ComparableVersion::new)
                .filter(v -> v.compareTo(currentVersion) > 0)
                .sorted(Comparator.reverseOrder())
                .collect(Collectors.toList());

        if (newerVersions.isEmpty()) {
            return buildFallbackRecommendation(dep);
        }

        // Find first clean version (no vulns)
        String cleanVersion = findFirstCleanVersion(dep, newerVersions);

        if (cleanVersion != null) {
            UpgradeRecommendation rec = new UpgradeRecommendation(dep, determineStrategy(dep.getVersion(), cleanVersion));
            rec.setTargetVersion(cleanVersion);
            rec.setUpgradeCommand(buildUpgradeCommand(dep, cleanVersion));
            return rec;
        }

        // No clean version found
        return buildFallbackRecommendation(dep);
    }

    private String findFirstCleanVersion(DependencyInfo dep, List<ComparableVersion> candidates) {
        // Query OSV for each candidate in batches
        for (ComparableVersion candidate : candidates) {
            DependencyInfo candidateDep = new DependencyInfo(
                    dep.getGroupId(), dep.getArtifactId(),
                    candidate.toString(), dep.getScope(), dep.getType());

            Map<DependencyInfo, List<VulnerabilityInfo>> result = osvClient.queryBatch(List.of(candidateDep));
            List<VulnerabilityInfo> vulns = result.get(candidateDep);

            if (vulns != null && vulns.isEmpty()) {
                return candidate.toString();
            }
        }
        return null;
    }

    private UpgradeRecommendation.Strategy determineStrategy(String current, String target) {
        try {
            String[] currentParts = current.split("\\.");
            String[] targetParts = target.split("\\.");

            if (currentParts.length >= 1 && targetParts.length >= 1) {
                int currentMajor = parseInt(currentParts[0]);
                int targetMajor = parseInt(targetParts[0]);

                if (targetMajor > currentMajor) return UpgradeRecommendation.Strategy.UPGRADE_MAJOR;

                if (currentParts.length >= 2 && targetParts.length >= 2) {
                    int currentMinor = parseInt(currentParts[1]);
                    int targetMinor = parseInt(targetParts[1]);
                    if (targetMinor > currentMinor) return UpgradeRecommendation.Strategy.UPGRADE_MINOR;
                }
            }
        } catch (Exception e) {
            log.debug("Could not determine strategy for " + current + " -> " + target);
        }

        return UpgradeRecommendation.Strategy.UPGRADE_PATCH;
    }

    private int parseInt(String s) {
        try {
            return Integer.parseInt(s.replaceAll("[^0-9]", ""));
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private UpgradeRecommendation buildFallbackRecommendation(DependencyInfo dep) {
        String depKey = dep.getGroupId() + ":" + dep.getArtifactId();

        if (dep.getType() == DependencyInfo.DependencyType.TRANSITIVE) {
            UpgradeRecommendation rec = new UpgradeRecommendation(dep, UpgradeRecommendation.Strategy.EXCLUSION);
            rec.setExclusionSnippet(buildExclusionSnippet(dep));
            return rec;
        }

        if (KNOWN_ALTERNATIVES.containsKey(depKey)) {
            String alternative = KNOWN_ALTERNATIVES.get(depKey);
            if (alternative != null) {
                UpgradeRecommendation rec = new UpgradeRecommendation(dep, UpgradeRecommendation.Strategy.ALTERNATIVE_LIB);
                rec.setAlternativeSuggestion("Consider migrating to: " + alternative);
                return rec;
            }
        }

        UpgradeRecommendation rec = new UpgradeRecommendation(dep, UpgradeRecommendation.Strategy.MANUAL_IMPL);
        rec.setAlternativeSuggestion(
                "No safe version found for " + depKey + ". " +
                "Manual review required. Consider removing or replacing this dependency.");
        return rec;
    }

    private String buildExclusionSnippet(DependencyInfo dep) {
        return String.format(
                "<exclusion>\n" +
                "    <groupId>%s</groupId>\n" +
                "    <artifactId>%s</artifactId>\n" +
                "</exclusion>",
                dep.getGroupId(), dep.getArtifactId());
    }

    private String buildUpgradeCommand(DependencyInfo dep, String targetVersion) {
        return String.format(
                "mvn versions:use-dep-version -Dincludes=%s:%s -DdepVersion=%s",
                dep.getGroupId(), dep.getArtifactId(), targetVersion);
    }

    protected String buildMetadataUrl(DependencyInfo dep) {
        String groupPath = dep.getGroupId().replace('.', '/');
        return String.format(CENTRAL_METADATA_URL, groupPath, dep.getArtifactId());
    }

    private List<String> fetchAvailableVersions(DependencyInfo dep) {
        String url = buildMetadataUrl(dep);

        try {
            Request request = new Request.Builder().url(url).get().build();
            try (Response response = httpClient.newCall(request).execute()) {
                if (!response.isSuccessful() || response.body() == null) {
                    return null;
                }
                String xml = response.body().string();
                return parseVersionsFromMetadata(xml);
            }
        } catch (Exception e) {
            log.warn("Failed to fetch maven-metadata.xml for " + dep.getCoordinates() + ": " + e.getMessage());
            return null;
        }
    }

    private List<String> parseVersionsFromMetadata(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        DocumentBuilder builder = factory.newDocumentBuilder();

        Document doc = builder.parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
        NodeList versionNodes = doc.getElementsByTagName("version");

        List<String> versions = new ArrayList<>();
        for (int i = 0; i < versionNodes.getLength(); i++) {
            String v = versionNodes.item(i).getTextContent().trim();
            // Skip snapshots, alphas, betas, release candidates
            if (!v.isEmpty() && !v.toUpperCase().contains("SNAPSHOT") &&
                !v.toUpperCase().contains("ALPHA") &&
                !v.toUpperCase().contains("BETA") &&
                !v.toUpperCase().contains("RC") &&
                !v.toUpperCase().contains("M1") &&
                !v.toUpperCase().contains("M2")) {
                versions.add(v);
            }
        }

        return versions;
    }
}
