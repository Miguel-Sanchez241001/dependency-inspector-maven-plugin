package io.github.miguelsan241001.depinspector.domain.model;

/** A specific import of a dependency's class in a source file. */
public final class Usage {

    private final String fileName;    // relative path (e.g. src/main/java/Foo.java)
    private final int lineNumber;
    private final String importStatement;
    private final UsageType usageType;

    public Usage(String fileName, int lineNumber, String importStatement, UsageType usageType) {
        this.fileName = fileName;
        this.lineNumber = lineNumber;
        this.importStatement = importStatement;
        this.usageType = usageType != null ? usageType : UsageType.IMPORT;
    }

    public Usage(String fileName, int lineNumber, String importStatement) {
        this(fileName, lineNumber, importStatement, importStatement.contains("import static ")
                ? UsageType.STATIC_IMPORT : UsageType.IMPORT);
    }

    public String getFileName()        { return fileName; }
    public int getLineNumber()         { return lineNumber; }
    public String getImportStatement() { return importStatement; }
    public UsageType getUsageType()    { return usageType; }

    @Override
    public String toString() {
        return fileName + ":" + lineNumber;
    }
}
