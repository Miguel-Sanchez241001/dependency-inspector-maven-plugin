package io.github.miguelsan241001.depinspector.model;

import java.util.List;

/**
 * Represents a dependency that is reachable in the wrong scope.
 *
 * Example: a test library (JUnit, Mockito) that arrives transitively
 * with "compile" scope because its parent declared it that way.
 * This causes the test lib to land in the final production JAR.
 */
public class ScopeIssue {

    public enum Fix {
        /** Add the dep directly with the correct scope and exclude it from its parent. */
        ADD_WITH_CORRECT_SCOPE,
        /** Upgrade the parent dep — it fixed the scope in a newer version. */
        UPGRADE_PARENT,
        /** No clean version of parent exists; exclude + add independently. */
        EXCLUDE_AND_ADD,
        /** Already on the latest version; no automated fix available. */
        MAX_VERSION_REACHED
    }

    private DependencyInfo offendingDep;       // e.g. junit:junit:4.13 at compile scope
    private String effectiveScope;             // what scope it has now, e.g. "compile"
    private String recommendedScope;           // what it should be, e.g. "test"
    private String parentGav;                  // "groupId:artifactId:version" that pulls it in
    private boolean isTestLibrary;             // true if it matches a known test lib pattern

    private List<Fix> fixes;                   // ordered: best fix first
    private String parentUpgradeVersion;       // set if Fix.UPGRADE_PARENT is available
    private String exclusionSnippet;           // XML ready to paste inside the parent <dependency>
    private String addDirectlySnippet;         // full <dependency> block with correct scope
    private String whyCannotUpgrade;           // explanation when Fix.MAX_VERSION_REACHED

    // ── getters / setters ────────────────────────────────────────────────────

    public DependencyInfo getOffendingDep() { return offendingDep; }
    public void setOffendingDep(DependencyInfo offendingDep) { this.offendingDep = offendingDep; }

    public String getEffectiveScope() { return effectiveScope; }
    public void setEffectiveScope(String effectiveScope) { this.effectiveScope = effectiveScope; }

    public String getRecommendedScope() { return recommendedScope; }
    public void setRecommendedScope(String recommendedScope) { this.recommendedScope = recommendedScope; }

    public String getParentGav() { return parentGav; }
    public void setParentGav(String parentGav) { this.parentGav = parentGav; }

    public boolean isTestLibrary() { return isTestLibrary; }
    public void setTestLibrary(boolean testLibrary) { isTestLibrary = testLibrary; }

    public List<Fix> getFixes() { return fixes; }
    public void setFixes(List<Fix> fixes) { this.fixes = fixes; }

    public String getParentUpgradeVersion() { return parentUpgradeVersion; }
    public void setParentUpgradeVersion(String parentUpgradeVersion) { this.parentUpgradeVersion = parentUpgradeVersion; }

    public String getExclusionSnippet() { return exclusionSnippet; }
    public void setExclusionSnippet(String exclusionSnippet) { this.exclusionSnippet = exclusionSnippet; }

    public String getAddDirectlySnippet() { return addDirectlySnippet; }
    public void setAddDirectlySnippet(String addDirectlySnippet) { this.addDirectlySnippet = addDirectlySnippet; }

    public String getWhyCannotUpgrade() { return whyCannotUpgrade; }
    public void setWhyCannotUpgrade(String whyCannotUpgrade) { this.whyCannotUpgrade = whyCannotUpgrade; }
}
