package io.github.miguelsan241001.depinspector.domain.port;

import io.github.miguelsan241001.depinspector.application.DependencyAnalysisReport;

import java.io.File;
import java.io.IOException;

/** Port for writing an analysis report to a persistent format. */
public interface ReportSink {

    /**
     * Writes the report to the given output directory.
     *
     * @return the generated file, or {@code null} if nothing was written.
     * @throws IOException on I/O failure.
     */
    File write(DependencyAnalysisReport report, File outputDir) throws IOException;
}
