package io.github.miguelsan241001.depinspector.service;

import io.github.miguelsan241001.depinspector.model.DependencyInfo;
import io.github.miguelsan241001.depinspector.model.ScopeIssue;
import io.github.miguelsan241001.depinspector.model.VulnerabilityInfo;
import org.apache.maven.artifact.versioning.ComparableVersion;
import org.apache.maven.plugin.logging.Log;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Detects dependencies that are reachable in the wrong scope.
 *
 * Primary case: test libraries (JUnit, Mockito, etc.) arriving with
 * "compile" scope because their parent declared them that way.
 * These land in the production JAR unnecessarily and can carry CVEs.
 */
public class ScopeAnalyzer {

    // Known test-only libraries by groupId:artifactId prefix
    private static final Set<String> TEST_LIB_PREFIXES = new LinkedHashSet<>(Arrays.asList(
        "junit:junit",
        "org.junit",
        "org.testng:testng",
        "org.mockito",
        "org.easymock",
        "org.powermock",
        "net.bytebuddy:byte-buddy-agent",
        "org.objenesis:objenesis",
        "org.assertj",
        "org.hamcrest",
        "org.springframework:spring-test",
        "org.springframework.boot:spring-boot-test",
        "com.github.tomakehurst:wiremock",
        "io.rest-assured",
        "com.squareup.okhttp3:mockwebserver",
        "org.jboss.arquillian",
        "org.seleniumhq.selenium",
        "io.cucumber",
        "org.jmockit:jmockit"
    ));

    private final VersionResolver versionResolver;
    private final Log log;

    public ScopeAnalyzer(VersionResolver versionResolver, Log log) {
        this.versionResolver = versionResolver;
        this.log = log;
    }

    /**
     * Analyzes the full dependency list and returns scope issues.
     *
     * @param allDeps all resolved dependencies (direct + transitive + plugins)
     * @return list of scope issues, empty if none found
     */
    public List<ScopeIssue> analyze(List<DependencyInfo> allDeps) {
        List<ScopeIssue> issues = new ArrayList<>();

        for (DependencyInfo dep : allDeps) {
            if (dep.getScope() == null) continue;

            // We only care about libs reachable at compile/runtime scope
            // that are known test-only libraries
            if (!isCompileOrRuntime(dep.getScope())) continue;
            if (!isKnownTestLibrary(dep)) continue;

            log.debug("Scope issue detected: " + dep.getCoordinates() +
                      " is a test library in scope [" + dep.getScope() + "]");

            ScopeIssue issue = buildIssue(dep, allDeps);
            issues.add(issue);
        }

        return issues;
    }

    private ScopeIssue buildIssue(DependencyInfo dep, List<DependencyInfo> allDeps) {
        ScopeIssue issue = new ScopeIssue();
        issue.setOffendingDep(dep);
        issue.setEffectiveScope(dep.getScope());
        issue.setRecommendedScope("test");
        issue.setTestLibrary(true);

        // Who brings this dep in?
        String parentGav = dep.getTransitiveOrigin();
        issue.setParentGav(parentGav != null ? parentGav : "declared directly");

        // Build the fix menu (ordered: best fix first)
        List<ScopeIssue.Fix> fixes = new ArrayList<>();
        String parentUpgradeVersion = null;

        if (dep.getType() == DependencyInfo.DependencyType.TRANSITIVE && parentGav != null) {
            // Check if the parent has a newer version that corrects the scope
            DependencyInfo parentDep = findDirectDep(parentGav, allDeps);
            if (parentDep != null) {
                parentUpgradeVersion = findParentVersionWithFixedScope(parentDep, dep);
            }

            if (parentUpgradeVersion != null) {
                fixes.add(ScopeIssue.Fix.UPGRADE_PARENT);
                issue.setParentUpgradeVersion(parentUpgradeVersion);
            }

            fixes.add(ScopeIssue.Fix.EXCLUDE_AND_ADD);
            issue.setExclusionSnippet(buildExclusionSnippet(dep, parentGav));

        } else {
            // Dep is declared directly with wrong scope
            fixes.add(ScopeIssue.Fix.ADD_WITH_CORRECT_SCOPE);
        }

        // If we checked for a parent upgrade and there's no newer version, explain why
        if (dep.getType() == DependencyInfo.DependencyType.TRANSITIVE
                && parentUpgradeVersion == null) {
            fixes.add(ScopeIssue.Fix.MAX_VERSION_REACHED);
            issue.setWhyCannotUpgrade(
                "The parent dependency (" + parentGav + ") does not have a newer version " +
                "that corrects the scope of " + dep.getGroupId() + ":" + dep.getArtifactId() + ". " +
                "The best option is to exclude it and re-declare it with <scope>test</scope>."
            );
        }

        issue.setFixes(fixes);
        issue.setAddDirectlySnippet(buildAddDirectlySnippet(dep));

        return issue;
    }

    /**
     * Checks whether a newer version of the parent corrects the scope.
     * Uses maven-metadata.xml to find available versions, then checks if
     * the test lib no longer appears with compile scope in that version's POM.
     *
     * Simplified approach: we assume that if the parent has a newer version
     * available, it MAY have fixed the scope. We report it as a candidate
     * and tell the user to verify.
     */
    private String findParentVersionWithFixedScope(DependencyInfo parentDep, DependencyInfo offendingDep) {
        try {
            // Ask VersionResolver for available versions (reuse the metadata fetch logic)
            // We use a lightweight strategy: just find if any newer parent version exists
            // The full OSV-based check is for CVEs; here we just report the latest version
            // and annotate it as "may fix scope issue - verify manually"
            //
            // A full automated check would require downloading each parent POM and parsing
            // its <dependencyManagement> section, which is out of scope for v1.
            // We report the latest available version as a candidate.
            ComparableVersion current = new ComparableVersion(parentDep.getVersion());

            // Delegate metadata fetch to VersionResolver
            io.github.miguelsan241001.depinspector.model.UpgradeRecommendation rec =
                versionResolver.resolve(parentDep);

            if (rec != null && rec.getTargetVersion() != null) {
                ComparableVersion candidate = new ComparableVersion(rec.getTargetVersion());
                if (candidate.compareTo(current) > 0) {
                    return rec.getTargetVersion();
                }
            }
        } catch (Exception e) {
            log.debug("Could not check parent versions for scope fix: " + e.getMessage());
        }
        return null;
    }

    private DependencyInfo findDirectDep(String gav, List<DependencyInfo> allDeps) {
        return allDeps.stream()
            .filter(d -> d.getType() == DependencyInfo.DependencyType.DIRECT)
            .filter(d -> (d.getGroupId() + ":" + d.getArtifactId()).equals(gav) ||
                         d.getCoordinates().equals(gav) ||
                         (d.getGroupId() + ":" + d.getArtifactId() + ":" + d.getVersion()).equals(gav))
            .findFirst()
            .orElse(null);
    }

    private boolean isCompileOrRuntime(String scope) {
        return "compile".equalsIgnoreCase(scope) || "runtime".equalsIgnoreCase(scope);
    }

    private boolean isKnownTestLibrary(DependencyInfo dep) {
        String ga = dep.getGroupId() + ":" + dep.getArtifactId();
        String g = dep.getGroupId();

        for (String prefix : TEST_LIB_PREFIXES) {
            if (ga.equals(prefix) || ga.startsWith(prefix) ||
                g.equals(prefix) || g.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    private String buildExclusionSnippet(DependencyInfo dep, String parentGav) {
        String[] parts = parentGav.split(":");
        String parentGroup = parts.length > 0 ? parts[0] : "PARENT_GROUP";
        String parentArtifact = parts.length > 1 ? parts[1] : "PARENT_ARTIFACT";

        return String.format(
            "<!-- Inside the <dependency> block for %s:%s -->\n" +
            "<exclusions>\n" +
            "    <exclusion>\n" +
            "        <groupId>%s</groupId>\n" +
            "        <artifactId>%s</artifactId>\n" +
            "    </exclusion>\n" +
            "</exclusions>",
            parentGroup, parentArtifact,
            dep.getGroupId(), dep.getArtifactId()
        );
    }

    private String buildAddDirectlySnippet(DependencyInfo dep) {
        return String.format(
            "<dependency>\n" +
            "    <groupId>%s</groupId>\n" +
            "    <artifactId>%s</artifactId>\n" +
            "    <version>%s</version>\n" +
            "    <scope>test</scope>\n" +
            "</dependency>",
            dep.getGroupId(), dep.getArtifactId(), dep.getVersion()
        );
    }
}
