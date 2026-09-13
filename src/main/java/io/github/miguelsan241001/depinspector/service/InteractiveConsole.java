package io.github.miguelsan241001.depinspector.service;

import io.github.miguelsan241001.depinspector.model.AnalysisResult;
import io.github.miguelsan241001.depinspector.model.DependencyInfo;
import io.github.miguelsan241001.depinspector.model.UsageLocation;
import io.github.miguelsan241001.depinspector.model.VulnerabilityInfo;
import org.apache.maven.plugin.logging.Log;

import java.util.List;
import java.util.Scanner;
import java.util.concurrent.*;

/**
 * Interactive terminal console for the upgrade goal.
 * Presents each dependency to the user and waits up to 60 seconds for input.
 */
public class InteractiveConsole {

    private static final int TIMEOUT_SECONDS = 60;
    private static final int MAX_RETRIES = 3;

    private final Log log;
    private final Scanner scanner;
    private final ExecutorService executor;

    public InteractiveConsole(Log log) {
        this.log = log;
        this.scanner = new Scanner(System.in);
        this.executor = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "interactive-console");
            t.setDaemon(true);
            return t;
        });
    }

    /**
     * Asks the user what to do with one dependency.
     *
     * @param result     the analysis result
     * @param index      1-based index in the current batch
     * @param total      total number of deps being asked
     * @param canExclude whether EXCLUDE is a sensible option (transitive dep)
     */
    public InteractiveDecision ask(AnalysisResult result, int index, int total, boolean canExclude) {
        DependencyInfo dep = result.getDependency();
        List<VulnerabilityInfo> vulns = result.getVulnerabilities();

        System.out.println();
        System.out.printf("[%d/%d] %s (%s)%n", index, total, dep.getCoordinates(), dep.getScope());

        // Show CVEs
        if (vulns != null && !vulns.isEmpty()) {
            VulnerabilityInfo worst = vulns.stream()
                    .max((a, b) -> Double.compare(a.getCvssScore(), b.getCvssScore()))
                    .orElse(vulns.get(0));
            System.out.printf("  %s — %s (CVSS %.1f)%n",
                    worst.getId(),
                    nvl(worst.getSummary()),
                    worst.getCvssScore());
            if (vulns.size() > 1) {
                System.out.printf("  ... and %d more CVE(s)%n", vulns.size() - 1);
            }
        }

        // Show usages
        List<UsageLocation> usages = result.getUsages();
        if (usages != null && !usages.isEmpty()) {
            System.out.println("  Used in:");
            usages.stream().limit(3).forEach(u -> System.out.printf("    %s%n", u));
            if (usages.size() > 3) {
                System.out.printf("    ... and %d more%n", usages.size() - 3);
            }
        }

        // Show recommendation
        if (result.getRecommendation() != null && result.getRecommendation().getTargetVersion() != null) {
            System.out.printf("  a) Upgrade to %s  (recommended)%n",
                    result.getRecommendation().getTargetVersion());
        } else {
            System.out.println("  a) Upgrade  (no safe version found — attempt anyway)");
        }

        if (canExclude && dep.getTransitiveOrigin() != null) {
            System.out.printf("  b) Exclude from parent %s%n", dep.getTransitiveOrigin());
        } else {
            System.out.println("  b) Exclude from direct dependency");
        }
        System.out.println("  c) Skip (do nothing)");
        System.out.printf("Choose [a/b/c] (%ds timeout → skip): ", TIMEOUT_SECONDS);
        System.out.flush();

        return readWithTimeout();
    }

    private InteractiveDecision readWithTimeout() {
        for (int attempt = 1; attempt <= MAX_RETRIES; attempt++) {
            Future<String> future = executor.submit(scanner::nextLine);
            String input = null;
            try {
                input = future.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            } catch (TimeoutException e) {
                future.cancel(true);
                System.out.println();
                log.warn("No response in " + TIMEOUT_SECONDS + "s — skipping");
                return InteractiveDecision.SKIP;
            } catch (InterruptedException | ExecutionException e) {
                log.warn("Input error: " + e.getMessage());
                return InteractiveDecision.SKIP;
            }

            if (input == null) return InteractiveDecision.SKIP;
            String choice = input.trim().toLowerCase();
            switch (choice) {
                case "a": return InteractiveDecision.UPGRADE;
                case "b": return InteractiveDecision.EXCLUDE;
                case "c": return InteractiveDecision.SKIP;
                default:
                    if (attempt < MAX_RETRIES) {
                        System.out.printf("  Invalid input '%s'. Please enter a, b, or c: ", input.trim());
                        System.out.flush();
                    } else {
                        log.warn("Too many invalid inputs — skipping");
                        return InteractiveDecision.SKIP;
                    }
            }
        }
        return InteractiveDecision.SKIP;
    }

    public void close() {
        executor.shutdownNow();
    }

    private String nvl(String s) { return s != null ? s : ""; }
}
