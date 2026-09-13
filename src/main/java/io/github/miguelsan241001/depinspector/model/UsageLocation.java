package io.github.miguelsan241001.depinspector.model;

public class UsageLocation {

    private String fileName;      // relative path from project root
    private int lineNumber;
    private String importStatement;

    public UsageLocation() {}

    public UsageLocation(String fileName, int lineNumber, String importStatement) {
        this.fileName = fileName;
        this.lineNumber = lineNumber;
        this.importStatement = importStatement;
    }

    public String getFileName() { return fileName; }
    public void setFileName(String fileName) { this.fileName = fileName; }

    public int getLineNumber() { return lineNumber; }
    public void setLineNumber(int lineNumber) { this.lineNumber = lineNumber; }

    public String getImportStatement() { return importStatement; }
    public void setImportStatement(String importStatement) { this.importStatement = importStatement; }

    @Override
    public String toString() {
        return fileName + ":" + lineNumber;
    }
}
