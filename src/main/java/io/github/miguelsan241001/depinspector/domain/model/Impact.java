package io.github.miguelsan241001.depinspector.domain.model;

import java.util.Collections;
import java.util.List;

/** The calculated impact of a vulnerable dependency on the project. */
public final class Impact {

    private final Dependency dependency;
    private final List<Usage> usages;
    private final List<List<DependencyNode>> paths; // all paths from root to this node
    private final ImpactLevel level;

    public Impact(Dependency dependency, List<Usage> usages,
                  List<List<DependencyNode>> paths, ImpactLevel level) {
        this.dependency = dependency;
        this.usages = usages != null ? Collections.unmodifiableList(usages) : Collections.emptyList();
        this.paths  = paths  != null ? Collections.unmodifiableList(paths)  : Collections.emptyList();
        this.level  = level != null ? level : ImpactLevel.NEGLIGIBLE_UNUSED;
    }

    public Dependency getDependency() { return dependency; }
    public List<Usage> getUsages()    { return usages; }
    public List<List<DependencyNode>> getPaths() { return paths; }
    public ImpactLevel getLevel()     { return level; }
    public boolean isDirectlyUsed()   { return !usages.isEmpty(); }

    @Override
    public String toString() {
        return dependency.coordinates() + " [impact=" + level + ", usages=" + usages.size() + "]";
    }
}
