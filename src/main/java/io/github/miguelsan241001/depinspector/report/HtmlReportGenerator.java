package io.github.miguelsan241001.depinspector.report;

import io.github.miguelsan241001.depinspector.model.*;

import java.util.List;
import org.apache.maven.plugin.logging.Log;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.time.format.DateTimeFormatter;
import java.util.List;

public class HtmlReportGenerator {

    private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private final Log log;

    public HtmlReportGenerator(Log log) {
        this.log = log;
    }

    public File generate(AnalysisReport report, File outputDir) throws IOException {
        outputDir.mkdirs();
        File reportFile = new File(outputDir, "report.html");

        try (PrintWriter writer = new PrintWriter(new OutputStreamWriter(
                new FileOutputStream(reportFile), StandardCharsets.UTF_8))) {
            writer.println(buildHtml(report));
        }

        return reportFile;
    }

    private String buildHtml(AnalysisReport report) {
        StringBuilder sb = new StringBuilder();

        sb.append("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
        sb.append("<meta charset=\"UTF-8\">\n");
        sb.append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
        sb.append("<title>Dependency Inspector Report - ").append(esc(report.getProjectArtifactId())).append("</title>\n");
        sb.append(buildCss());
        sb.append("</head>\n<body>\n");

        sb.append(buildHeader(report));
        sb.append(buildSummary(report));

        List<AnalysisResult> vulnerable = report.getVulnerableResults();
        if (!vulnerable.isEmpty()) {
            sb.append(buildVulnerableSection(vulnerable));
        }

        List<AnalysisResult> noVersion = report.getResults() != null
                ? report.getResults().stream()
                    .filter(r -> r.isVulnerable() &&
                                 r.getRecommendation() != null &&
                                 !r.getRecommendation().isAutomaticUpgrade())
                    .collect(java.util.stream.Collectors.toList())
                : List.of();

        if (!noVersion.isEmpty()) {
            sb.append(buildManualSection(noVersion));
        }

        if (report.getScopeIssues() != null && !report.getScopeIssues().isEmpty()) {
            sb.append(buildScopeIssuesSection(report.getScopeIssues()));
        }

        sb.append(buildFooter());
        sb.append("</body>\n</html>");

        return sb.toString();
    }

    private String buildCss() {
        return "<style>\n" +
               "* { box-sizing: border-box; margin: 0; padding: 0; }\n" +
               "body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; " +
               "       background: #f5f7fa; color: #333; line-height: 1.6; }\n" +
               ".container { max-width: 1200px; margin: 0 auto; padding: 20px; }\n" +
               "header { background: #1a1a2e; color: white; padding: 30px 20px; margin-bottom: 30px; }\n" +
               "header h1 { font-size: 1.8em; margin-bottom: 5px; }\n" +
               "header .meta { color: #aaa; font-size: 0.9em; }\n" +
               ".summary { display: flex; gap: 15px; margin-bottom: 30px; flex-wrap: wrap; }\n" +
               ".summary-card { background: white; border-radius: 8px; padding: 20px; " +
               "                flex: 1; min-width: 150px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }\n" +
               ".summary-card .count { font-size: 2.5em; font-weight: bold; }\n" +
               ".summary-card .label { color: #666; font-size: 0.85em; }\n" +
               ".card-vuln .count { color: #dc3545; }\n" +
               ".card-clean .count { color: #28a745; }\n" +
               ".card-skip .count { color: #6c757d; }\n" +
               ".card-scope .count { color: #e67e22; }\n" +
               ".scope-card { background: white; border-radius: 8px; margin-bottom: 15px; " +
               "              box-shadow: 0 2px 8px rgba(0,0,0,0.08); overflow: hidden; " +
               "              border-left: 5px solid #e67e22; }\n" +
               ".scope-header { padding: 12px 20px; background: #fef9f0; }\n" +
               ".scope-tag { display: inline-block; padding: 2px 8px; border-radius: 4px; " +
               "             font-size: 0.75em; font-weight: bold; }\n" +
               ".scope-wrong { background: #fde8d8; color: #c0392b; }\n" +
               ".scope-right { background: #d5f5e3; color: #1e8449; }\n" +
               ".fix-menu { padding: 12px 20px; }\n" +
               ".fix-item { padding: 8px 0; border-bottom: 1px solid #f5f5f5; }\n" +
               ".fix-item:last-child { border-bottom: none; }\n" +
               ".fix-badge { display: inline-block; padding: 2px 8px; border-radius: 4px; " +
               "             font-size: 0.72em; font-weight: bold; margin-right: 8px; " +
               "             background: #1a1a2e; color: white; }\n" +
               ".fix-badge-warn { background: #e67e22; }\n" +
               ".code-block { font-family: monospace; background: #f8f9fa; border-radius: 4px; " +
               "              padding: 8px 12px; font-size: 0.8em; margin-top: 6px; " +
               "              white-space: pre; overflow-x: auto; }\n" +
               "section { margin-bottom: 30px; }\n" +
               "section h2 { font-size: 1.3em; margin-bottom: 15px; padding-bottom: 8px; " +
               "             border-bottom: 2px solid #e0e0e0; }\n" +
               ".dep-card { background: white; border-radius: 8px; margin-bottom: 15px; " +
               "            box-shadow: 0 2px 8px rgba(0,0,0,0.08); overflow: hidden; }\n" +
               ".dep-header { padding: 15px 20px; border-left: 5px solid #dc3545; }\n" +
               ".dep-header .coords { font-weight: bold; font-size: 1em; font-family: monospace; }\n" +
               ".dep-header .type-badge { display: inline-block; padding: 2px 8px; border-radius: 12px; " +
               "                          font-size: 0.75em; font-weight: bold; margin-left: 8px; }\n" +
               ".badge-direct { background: #e3f2fd; color: #1565c0; }\n" +
               ".badge-transitive { background: #f3e5f5; color: #7b1fa2; }\n" +
               ".badge-plugin { background: #e8f5e9; color: #2e7d32; }\n" +
               ".dep-body { padding: 15px 20px; }\n" +
               ".vulns-list { margin: 10px 0; }\n" +
               ".vuln-item { display: flex; align-items: flex-start; gap: 12px; " +
               "             padding: 8px 0; border-bottom: 1px solid #f0f0f0; }\n" +
               ".vuln-item:last-child { border-bottom: none; }\n" +
               ".severity-badge { display: inline-block; padding: 3px 10px; border-radius: 4px; " +
               "                  font-size: 0.75em; font-weight: bold; white-space: nowrap; }\n" +
               ".sev-CRITICAL { background: #dc3545; color: white; }\n" +
               ".sev-HIGH { background: #fd7e14; color: white; }\n" +
               ".sev-MEDIUM { background: #ffc107; color: #333; }\n" +
               ".sev-LOW { background: #0d6efd; color: white; }\n" +
               ".sev-NONE { background: #6c757d; color: white; }\n" +
               ".vuln-id { font-family: monospace; font-weight: bold; font-size: 0.9em; }\n" +
               ".vuln-summary { color: #555; font-size: 0.9em; }\n" +
               ".recommendation { background: #f8f9fa; border-radius: 6px; padding: 12px 15px; " +
               "                  margin-top: 12px; }\n" +
               ".recommendation .label { font-size: 0.8em; color: #666; text-transform: uppercase; " +
               "                          letter-spacing: 0.5px; margin-bottom: 5px; }\n" +
               ".upgrade-cmd { font-family: monospace; background: #1a1a2e; color: #a8ff78; " +
               "               padding: 8px 12px; border-radius: 4px; font-size: 0.85em; " +
               "               margin-top: 8px; word-break: break-all; }\n" +
               ".breaking-warning { color: #dc3545; font-size: 0.85em; margin-top: 5px; }\n" +
               ".manual-card { background: white; border-radius: 8px; margin-bottom: 15px; " +
               "               padding: 15px 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); " +
               "               border-left: 5px solid #fd7e14; }\n" +
               ".exclusion-snippet { font-family: monospace; background: #f8f9fa; border-radius: 4px; " +
               "                     padding: 10px; font-size: 0.82em; margin-top: 8px; " +
               "                     white-space: pre; overflow-x: auto; }\n" +
               "footer { text-align: center; padding: 20px; color: #999; font-size: 0.85em; " +
               "         border-top: 1px solid #e0e0e0; margin-top: 30px; }\n" +
               "</style>\n";
    }

    private String buildHeader(AnalysisReport report) {
        return "<header>\n" +
               "  <div class=\"container\">\n" +
               "    <h1>Dependency Inspector Report</h1>\n" +
               "    <div class=\"meta\">" +
               "      Project: <strong>" + esc(report.getProjectArtifactId()) + "</strong> " +
               "      v" + esc(report.getProjectVersion()) + " &nbsp;|&nbsp; " +
               "      Generated: " + esc(report.getGeneratedAt().format(FORMATTER)) +
               "    </div>\n" +
               "  </div>\n" +
               "</header>\n";
    }

    private String buildSummary(AnalysisReport report) {
        return "<div class=\"container\">\n" +
               "<div class=\"summary\">\n" +
               "  <div class=\"summary-card card-vuln\">\n" +
               "    <div class=\"count\">" + report.countVulnerable() + "</div>\n" +
               "    <div class=\"label\">Vulnerable</div>\n" +
               "  </div>\n" +
               "  <div class=\"summary-card card-clean\">\n" +
               "    <div class=\"count\">" + report.countClean() + "</div>\n" +
               "    <div class=\"label\">Clean</div>\n" +
               "  </div>\n" +
               "  <div class=\"summary-card card-skip\">\n" +
               "    <div class=\"count\">" + report.countSkipped() + "</div>\n" +
               "    <div class=\"label\">Skipped</div>\n" +
               "  </div>\n" +
               "  <div class=\"summary-card card-scope\">\n" +
               "    <div class=\"count\">" + (report.getScopeIssues() != null ? report.getScopeIssues().size() : 0) + "</div>\n" +
               "    <div class=\"label\">Scope Issues</div>\n" +
               "  </div>\n" +
               "  <div class=\"summary-card\">\n" +
               "    <div class=\"count\">" + (report.getResults() != null ? report.getResults().size() : 0) + "</div>\n" +
               "    <div class=\"label\">Total Analyzed</div>\n" +
               "  </div>\n" +
               "</div>\n";
    }

    private String buildVulnerableSection(List<AnalysisResult> results) {
        StringBuilder sb = new StringBuilder();
        sb.append("<section>\n<h2>Vulnerable Dependencies</h2>\n");

        for (AnalysisResult result : results) {
            sb.append(buildDepCard(result));
        }

        sb.append("</section>\n");
        return sb.toString();
    }

    private String buildDepCard(AnalysisResult result) {
        DependencyInfo dep = result.getDependency();
        StringBuilder sb = new StringBuilder();

        sb.append("<div class=\"dep-card\">\n");
        sb.append("  <div class=\"dep-header\">\n");
        sb.append("    <span class=\"coords\">").append(esc(dep.getCoordinates())).append("</span>\n");
        sb.append("    <span class=\"type-badge badge-").append(dep.getType().name().toLowerCase())
          .append("\">").append(dep.getType().name()).append("</span>\n");

        if (dep.getTransitiveOrigin() != null) {
            sb.append("    <div style=\"font-size:0.8em;color:#888;margin-top:4px;\">via ")
              .append(esc(dep.getTransitiveOrigin())).append("</div>\n");
        }
        sb.append("  </div>\n");

        sb.append("  <div class=\"dep-body\">\n");
        sb.append("    <div class=\"vulns-list\">\n");

        if (result.getVulnerabilities() != null) {
            for (VulnerabilityInfo vuln : result.getVulnerabilities()) {
                sb.append(buildVulnItem(vuln));
            }
        }

        sb.append("    </div>\n");

        if (result.getRecommendation() != null) {
            sb.append(buildRecommendationBlock(result.getRecommendation()));
        }

        sb.append("  </div>\n</div>\n");
        return sb.toString();
    }

    private String buildVulnItem(VulnerabilityInfo vuln) {
        String sevClass = "sev-" + vuln.getSeverity().name();
        String cvss = vuln.getCvssScore() >= 0
                ? String.format("%.1f", vuln.getCvssScore())
                : "N/A";

        return "      <div class=\"vuln-item\">\n" +
               "        <span class=\"severity-badge " + sevClass + "\">" +
               vuln.getSeverity().name() + " " + cvss + "</span>\n" +
               "        <div>\n" +
               "          <div class=\"vuln-id\">" + esc(vuln.getId()) + "</div>\n" +
               "          <div class=\"vuln-summary\">" + esc(nvl(vuln.getSummary())) + "</div>\n" +
               "        </div>\n" +
               "      </div>\n";
    }

    private String buildRecommendationBlock(UpgradeRecommendation rec) {
        StringBuilder sb = new StringBuilder();
        sb.append("    <div class=\"recommendation\">\n");
        sb.append("      <div class=\"label\">Recommendation: ").append(rec.getStrategy().name()).append("</div>\n");

        if (rec.getTargetVersion() != null) {
            sb.append("      <div>Safe version: <strong>").append(esc(rec.getTargetVersion())).append("</strong></div>\n");
        }

        if (rec.isHasBreakingChanges()) {
            sb.append("      <div class=\"breaking-warning\">⚠ Breaking changes detected - manual review recommended</div>\n");
        }

        if (rec.getUpgradeCommand() != null) {
            sb.append("      <div class=\"upgrade-cmd\">").append(esc(rec.getUpgradeCommand())).append("</div>\n");
        }

        if (rec.getAlternativeSuggestion() != null) {
            sb.append("      <div>").append(esc(rec.getAlternativeSuggestion())).append("</div>\n");
        }

        sb.append("    </div>\n");
        return sb.toString();
    }

    private String buildManualSection(List<AnalysisResult> results) {
        StringBuilder sb = new StringBuilder();
        sb.append("<section>\n<h2>Requires Manual Action</h2>\n");

        for (AnalysisResult result : results) {
            UpgradeRecommendation rec = result.getRecommendation();
            DependencyInfo dep = result.getDependency();

            sb.append("<div class=\"manual-card\">\n");
            sb.append("  <div class=\"coords\">").append(esc(dep.getCoordinates())).append("</div>\n");
            sb.append("  <div style=\"font-size:0.85em;color:#666;margin:5px 0;\">Strategy: ")
              .append(rec.getStrategy().name()).append("</div>\n");

            if (rec.getAlternativeSuggestion() != null) {
                sb.append("  <div>").append(esc(rec.getAlternativeSuggestion())).append("</div>\n");
            }

            if (rec.getExclusionSnippet() != null) {
                sb.append("  <div class=\"label\" style=\"margin-top:8px;\">Exclusion snippet:</div>\n");
                sb.append("  <pre class=\"exclusion-snippet\">").append(esc(rec.getExclusionSnippet())).append("</pre>\n");
            }

            sb.append("</div>\n");
        }

        sb.append("</section>\n");
        return sb.toString();
    }

    private String buildScopeIssuesSection(List<ScopeIssue> issues) {
        StringBuilder sb = new StringBuilder();
        sb.append("<section>\n");
        sb.append("<h2>&#9888; Scope Issues — Test Libraries Reachable in Production Classpath</h2>\n");
        sb.append("<p style=\"color:#666;font-size:0.9em;margin-bottom:15px;\">");
        sb.append("These libraries are test-only frameworks that appear in <code>compile</code> or <code>runtime</code> scope. ");
        sb.append("They will be included in your final JAR/WAR unnecessarily, increasing attack surface.</p>\n");

        for (ScopeIssue issue : issues) {
            DependencyInfo dep = issue.getOffendingDep();
            sb.append("<div class=\"scope-card\">\n");

            // Header
            sb.append("  <div class=\"scope-header\">\n");
            sb.append("    <span style=\"font-family:monospace;font-weight:bold;\">")
              .append(esc(dep.getCoordinates())).append("</span>\n");
            sb.append("    &nbsp;");
            sb.append("    <span class=\"scope-tag scope-wrong\">").append(esc(issue.getEffectiveScope())).append("</span>\n");
            sb.append("    <span style=\"color:#aaa;font-size:0.9em;\"> &rarr; should be </span>\n");
            sb.append("    <span class=\"scope-tag scope-right\">").append(esc(issue.getRecommendedScope())).append("</span>\n");
            if (dep.getTransitiveOrigin() != null) {
                sb.append("    <div style=\"font-size:0.8em;color:#888;margin-top:4px;\">Brought in by: <code>")
                  .append(esc(dep.getTransitiveOrigin())).append("</code></div>\n");
            }
            sb.append("  </div>\n");

            // Fix menu
            sb.append("  <div class=\"fix-menu\">\n");
            if (issue.getFixes() != null) {
                for (ScopeIssue.Fix fix : issue.getFixes()) {
                    sb.append(buildFixItem(fix, issue));
                }
            }
            sb.append("  </div>\n");
            sb.append("</div>\n");
        }

        sb.append("</section>\n");
        return sb.toString();
    }

    private String buildFixItem(ScopeIssue.Fix fix, ScopeIssue issue) {
        StringBuilder sb = new StringBuilder();
        sb.append("    <div class=\"fix-item\">\n");

        switch (fix) {
            case UPGRADE_PARENT:
                sb.append("      <span class=\"fix-badge\">OPTION 1</span> ");
                sb.append("Upgrade parent <code>").append(esc(issue.getParentGav())).append("</code>");
                sb.append(" to <strong>").append(esc(issue.getParentUpgradeVersion())).append("</strong> ");
                sb.append("— it may have corrected the scope. Verify with <code>mvn dependency:tree</code> after upgrading.\n");
                break;

            case EXCLUDE_AND_ADD:
                sb.append("      <span class=\"fix-badge\">OPTION 2</span> ");
                sb.append("Exclude from parent and re-declare with correct scope:\n");
                if (issue.getExclusionSnippet() != null) {
                    sb.append("      <pre class=\"code-block\">").append(esc(issue.getExclusionSnippet())).append("</pre>\n");
                }
                if (issue.getAddDirectlySnippet() != null) {
                    sb.append("      <div style=\"font-size:0.82em;color:#666;margin-top:6px;\">Then add directly:</div>\n");
                    sb.append("      <pre class=\"code-block\">").append(esc(issue.getAddDirectlySnippet())).append("</pre>\n");
                }
                break;

            case ADD_WITH_CORRECT_SCOPE:
                sb.append("      <span class=\"fix-badge\">FIX</span> ");
                sb.append("Change scope to <code>test</code> in your pom.xml:\n");
                if (issue.getAddDirectlySnippet() != null) {
                    sb.append("      <pre class=\"code-block\">").append(esc(issue.getAddDirectlySnippet())).append("</pre>\n");
                }
                break;

            case MAX_VERSION_REACHED:
                sb.append("      <span class=\"fix-badge fix-badge-warn\">NOTE</span> ");
                sb.append(issue.getWhyCannotUpgrade() != null
                    ? esc(issue.getWhyCannotUpgrade())
                    : "No newer version of the parent available that fixes this scope issue.").append("\n");
                break;
        }

        sb.append("    </div>\n");
        return sb.toString();
    }

    private String buildFooter() {
        return "</div>\n" +
               "<footer>Powered by <a href=\"https://osv.dev\" style=\"color:#666;\">OSV.dev</a> &mdash; " +
               "dependency-inspector-maven-plugin</footer>\n";
    }

    private String esc(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;");
    }

    private String nvl(String s) {
        return s != null ? s : "";
    }
}
