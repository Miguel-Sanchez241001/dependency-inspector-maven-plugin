package io.github.miguelsan241001.depinspector.model;

public class UpgradeRecommendation {

    public enum Strategy {
        UPGRADE_PATCH,
        UPGRADE_MINOR,
        UPGRADE_MAJOR,
        ALTERNATIVE_LIB,
        EXCLUSION,
        MANUAL_IMPL,
        NO_ACTION_AVAILABLE
    }

    private DependencyInfo dependency;
    private Strategy strategy;
    private String targetVersion;
    private String alternativeSuggestion;
    private String exclusionSnippet;
    private boolean hasBreakingChanges;
    private String upgradeCommand; // ready to copy-paste

    public UpgradeRecommendation() {}

    public UpgradeRecommendation(DependencyInfo dependency, Strategy strategy) {
        this.dependency = dependency;
        this.strategy = strategy;
    }

    public boolean isAutomaticUpgrade() {
        return strategy == Strategy.UPGRADE_PATCH || strategy == Strategy.UPGRADE_MINOR;
    }

    public DependencyInfo getDependency() { return dependency; }
    public void setDependency(DependencyInfo dependency) { this.dependency = dependency; }

    public Strategy getStrategy() { return strategy; }
    public void setStrategy(Strategy strategy) { this.strategy = strategy; }

    public String getTargetVersion() { return targetVersion; }
    public void setTargetVersion(String targetVersion) { this.targetVersion = targetVersion; }

    public String getAlternativeSuggestion() { return alternativeSuggestion; }
    public void setAlternativeSuggestion(String alternativeSuggestion) { this.alternativeSuggestion = alternativeSuggestion; }

    public String getExclusionSnippet() { return exclusionSnippet; }
    public void setExclusionSnippet(String exclusionSnippet) { this.exclusionSnippet = exclusionSnippet; }

    public boolean isHasBreakingChanges() { return hasBreakingChanges; }
    public void setHasBreakingChanges(boolean hasBreakingChanges) { this.hasBreakingChanges = hasBreakingChanges; }

    public String getUpgradeCommand() { return upgradeCommand; }
    public void setUpgradeCommand(String upgradeCommand) { this.upgradeCommand = upgradeCommand; }
}
