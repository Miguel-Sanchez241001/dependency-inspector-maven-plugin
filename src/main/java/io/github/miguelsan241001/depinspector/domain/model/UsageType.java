package io.github.miguelsan241001.depinspector.domain.model;

/** How a dependency is referenced in source code. */
public enum UsageType {
    /** A standard import statement: {@code import com.example.Foo}. */
    IMPORT,
    /** A static import: {@code import static com.example.Foo.bar}. */
    STATIC_IMPORT
}
