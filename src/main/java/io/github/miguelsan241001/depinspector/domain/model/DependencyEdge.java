package io.github.miguelsan241001.depinspector.domain.model;

import java.util.Objects;

/** A directed edge in the dependency graph: parent → child. */
public final class DependencyEdge {

    private final String parentGa;  // "groupId:artifactId"
    private final String childGa;   // "groupId:artifactId"

    public DependencyEdge(String parentGa, String childGa) {
        this.parentGa = Objects.requireNonNull(parentGa, "parentGa");
        this.childGa  = Objects.requireNonNull(childGa,  "childGa");
    }

    public String getParentGa() { return parentGa; }
    public String getChildGa()  { return childGa; }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof DependencyEdge)) return false;
        DependencyEdge e = (DependencyEdge) o;
        return parentGa.equals(e.parentGa) && childGa.equals(e.childGa);
    }

    @Override
    public int hashCode() {
        return Objects.hash(parentGa, childGa);
    }

    @Override
    public String toString() {
        return parentGa + " → " + childGa;
    }
}
