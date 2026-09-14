package io.github.miguelsan241001.depinspector.domain.service;

import io.github.miguelsan241001.depinspector.domain.model.Dependency;
import io.github.miguelsan241001.depinspector.domain.model.DependencyType;
import io.github.miguelsan241001.depinspector.domain.model.Vulnerability;
import io.github.miguelsan241001.depinspector.domain.port.VersionSource;
import io.github.miguelsan241001.depinspector.domain.port.VulnerabilitySource;
import io.github.miguelsan241001.depinspector.model.UpgradeRecommendation;
import io.github.miguelsan241001.depinspector.model.UpgradeRecommendation.Strategy;
import org.apache.maven.artifact.versioning.ComparableVersion;

import java.util.*;

/**
 * Determines the best upgrade strategy for a vulnerable dependency.
 * Delegates version discovery and vulnerability checking to ports.
 */
public class UpgradeDecisionService {

    private static final Map<String, String> KNOWN_ALTERNATIVES = new HashMap<>();

    static {
        KNOWN_ALTERNATIVES.put("log4j:log4j",                             "ch.qos.logback:logback-classic");
        KNOWN_ALTERNATIVES.put("commons-collections:commons-collections",  "org.apache.commons:commons-collections4");
        KNOWN_ALTERNATIVES.put("struts:struts",                            "org.springframework:spring-webmvc");
        KNOWN_ALTERNATIVES.put("com.google.guava:guava-jdk5",             "com.google.guava:guava");
        KNOWN_ALTERNATIVES.put("org.codehaus.jackson:jackson-mapper-asl", "com.fasterxml.jackson.core:jackson-databind");
        KNOWN_ALTERNATIVES.put("org.codehaus.jackson:jackson-core-asl",   "com.fasterxml.jackson.core:jackson-core");
    }

    private final VersionSource versionSource;
    private final VulnerabilitySource vulnSource;

    public UpgradeDecisionService(VersionSource versionSource, VulnerabilitySource vulnSource) {
        this.versionSource = versionSource;
        this.vulnSource = vulnSource;
    }

    /**
     * Resolves the best upgrade recommendation for the given vulnerable dependency.
     */
    public UpgradeRecommendation resolve(Dependency dep) {
        List<String> versions = versionSource.findAvailableVersions(dep);
        if (versions == null || versions.isEmpty()) {
            return buildFallback(dep);
        }

        String cleanVersion = findFirstClean(dep, versions);
        if (cleanVersion != null) {
            Strategy strategy = determineStrategy(dep.getVersion(), cleanVersion);
            io.github.miguelsan241001.depinspector.model.DependencyInfo depInfo = toDependencyInfo(dep);
            UpgradeRecommendation rec = new UpgradeRecommendation(depInfo, strategy);
            rec.setTargetVersion(cleanVersion);
            rec.setUpgradeCommand(buildUpgradeCommand(dep, cleanVersion));
            return rec;
        }

        return buildFallback(dep);
    }

    private String findFirstClean(Dependency dep, List<String> candidates) {
        ComparableVersion current = new ComparableVersion(dep.getVersion());
        for (String v : candidates) {
            if (new ComparableVersion(v).compareTo(current) <= 0) continue;
            Dependency candidate = dep.withVersion(v);
            Map<Dependency, List<Vulnerability>> result =
                    vulnSource.findVulnerabilities(Collections.singletonList(candidate));
            List<Vulnerability> vulns = result.get(candidate);
            if (vulns != null && vulns.isEmpty()) {
                return v;
            }
        }
        return null;
    }

    private Strategy determineStrategy(String current, String target) {
        try {
            String[] c = current.split("\\.");
            String[] t = target.split("\\.");
            int cMajor = parseInt(c.length > 0 ? c[0] : "0");
            int tMajor = parseInt(t.length > 0 ? t[0] : "0");
            if (tMajor > cMajor) return Strategy.UPGRADE_MAJOR;

            int cMinor = parseInt(c.length > 1 ? c[1] : "0");
            int tMinor = parseInt(t.length > 1 ? t[1] : "0");
            if (tMinor > cMinor) return Strategy.UPGRADE_MINOR;
        } catch (Exception ignored) {}
        return Strategy.UPGRADE_PATCH;
    }

    private UpgradeRecommendation buildFallback(Dependency dep) {
        io.github.miguelsan241001.depinspector.model.DependencyInfo depInfo = toDependencyInfo(dep);

        if (dep.getType() == DependencyType.TRANSITIVE) {
            UpgradeRecommendation rec = new UpgradeRecommendation(depInfo, Strategy.EXCLUSION);
            rec.setExclusionSnippet(buildExclusionSnippet(dep));
            return rec;
        }

        String key = dep.ga();
        if (KNOWN_ALTERNATIVES.containsKey(key)) {
            String alt = KNOWN_ALTERNATIVES.get(key);
            UpgradeRecommendation rec = new UpgradeRecommendation(depInfo, Strategy.ALTERNATIVE_LIB);
            rec.setAlternativeSuggestion("Consider migrating to: " + alt);
            return rec;
        }

        UpgradeRecommendation rec = new UpgradeRecommendation(depInfo, Strategy.MANUAL_IMPL);
        rec.setAlternativeSuggestion("No safe version found for " + key + ". Manual review required.");
        return rec;
    }

    private String buildExclusionSnippet(Dependency dep) {
        return String.format(
                "<exclusion>\n    <groupId>%s</groupId>\n    <artifactId>%s</artifactId>\n</exclusion>",
                dep.getGroupId(), dep.getArtifactId());
    }

    private String buildUpgradeCommand(Dependency dep, String targetVersion) {
        return String.format("mvn versions:use-dep-version -Dincludes=%s:%s -DdepVersion=%s",
                dep.getGroupId(), dep.getArtifactId(), targetVersion);
    }

    private int parseInt(String s) {
        try { return Integer.parseInt(s.replaceAll("[^0-9]", "")); }
        catch (NumberFormatException e) { return 0; }
    }

    private io.github.miguelsan241001.depinspector.model.DependencyInfo toDependencyInfo(Dependency dep) {
        io.github.miguelsan241001.depinspector.model.DependencyInfo info =
                new io.github.miguelsan241001.depinspector.model.DependencyInfo(
                        dep.getGroupId(), dep.getArtifactId(), dep.getVersion(), dep.getScope(),
                        io.github.miguelsan241001.depinspector.model.DependencyInfo.DependencyType
                                .valueOf(dep.getType().name()));
        if (dep.getResolvedJar() != null) info.setJarFile(dep.getResolvedJar());
        return info;
    }
}
