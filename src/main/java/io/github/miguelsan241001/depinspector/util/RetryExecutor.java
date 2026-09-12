package io.github.miguelsan241001.depinspector.util;

import org.apache.maven.plugin.logging.Log;

import java.util.concurrent.Callable;

public class RetryExecutor {

    private static final int MAX_RETRIES = 3;
    private static final long BASE_DELAY_MS = 1000L;

    private final Log log;

    public RetryExecutor(Log log) {
        this.log = log;
    }

    public <T> T execute(Callable<T> action) {
        Exception lastException = null;

        for (int attempt = 1; attempt <= MAX_RETRIES; attempt++) {
            try {
                return action.call();
            } catch (Exception e) {
                lastException = e;
                if (attempt < MAX_RETRIES) {
                    long delay = BASE_DELAY_MS * (long) Math.pow(2, attempt - 1);
                    log.warn("Attempt " + attempt + " failed: " + e.getMessage() + ". Retrying in " + delay + "ms...");
                    try {
                        Thread.sleep(delay);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        log.warn("Retry interrupted");
                        return null;
                    }
                }
            }
        }

        log.warn("All " + MAX_RETRIES + " attempts failed. Last error: " +
                (lastException != null ? lastException.getMessage() : "unknown"));
        return null;
    }
}
