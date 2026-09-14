package io.github.miguelsan241001.depinspector.adapter.scanner;

import io.github.miguelsan241001.depinspector.domain.model.Dependency;
import io.github.miguelsan241001.depinspector.domain.model.Usage;
import org.apache.maven.plugin.logging.Log;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.stream.Stream;

/**
 * Scans Java source files to find which files import classes from a given dependency.
 * Returns domain {@link Usage} objects (replaces the old {@code UsageScanner}).
 */
public class JavaSourceUsageAdapter {

    // artifactId → list of package prefixes that identify this dependency's classes
    private static final Map<String, List<String>> PACKAGE_INDEX = new HashMap<>();

    static {
        PACKAGE_INDEX.put("log4j-core",              List.of("org.apache.logging.log4j"));
        PACKAGE_INDEX.put("log4j",                   List.of("org.apache.log4j"));
        PACKAGE_INDEX.put("log4j-api",               List.of("org.apache.logging.log4j"));
        PACKAGE_INDEX.put("slf4j-api",               List.of("org.slf4j"));
        PACKAGE_INDEX.put("logback-classic",         List.of("ch.qos.logback"));
        PACKAGE_INDEX.put("logback-core",            List.of("ch.qos.logback.core"));
        PACKAGE_INDEX.put("spring-core",             List.of("org.springframework.core", "org.springframework.util"));
        PACKAGE_INDEX.put("spring-context",          List.of("org.springframework.context", "org.springframework.beans"));
        PACKAGE_INDEX.put("spring-web",              List.of("org.springframework.web", "org.springframework.http"));
        PACKAGE_INDEX.put("spring-webmvc",           List.of("org.springframework.web.servlet"));
        PACKAGE_INDEX.put("spring-boot",             List.of("org.springframework.boot"));
        PACKAGE_INDEX.put("spring-boot-autoconfigure", List.of("org.springframework.boot.autoconfigure"));
        PACKAGE_INDEX.put("jackson-databind",        List.of("com.fasterxml.jackson.databind"));
        PACKAGE_INDEX.put("jackson-core",            List.of("com.fasterxml.jackson.core"));
        PACKAGE_INDEX.put("jackson-annotations",     List.of("com.fasterxml.jackson.annotation"));
        PACKAGE_INDEX.put("guava",                   List.of("com.google.common"));
        PACKAGE_INDEX.put("commons-lang3",           List.of("org.apache.commons.lang3"));
        PACKAGE_INDEX.put("commons-lang",            List.of("org.apache.commons.lang"));
        PACKAGE_INDEX.put("commons-collections",     List.of("org.apache.commons.collections"));
        PACKAGE_INDEX.put("commons-collections4",    List.of("org.apache.commons.collections4"));
        PACKAGE_INDEX.put("commons-io",              List.of("org.apache.commons.io"));
        PACKAGE_INDEX.put("httpclient",              List.of("org.apache.http.client", "org.apache.http"));
        PACKAGE_INDEX.put("httpclient5",             List.of("org.apache.hc.client5"));
        PACKAGE_INDEX.put("okhttp",                  List.of("okhttp3"));
        PACKAGE_INDEX.put("retrofit",                List.of("retrofit2"));
        PACKAGE_INDEX.put("mockito-core",            List.of("org.mockito"));
        PACKAGE_INDEX.put("junit-jupiter-api",       List.of("org.junit.jupiter.api"));
        PACKAGE_INDEX.put("junit-jupiter",           List.of("org.junit.jupiter"));
        PACKAGE_INDEX.put("junit",                   List.of("org.junit", "junit.framework"));
        PACKAGE_INDEX.put("testng",                  List.of("org.testng"));
        PACKAGE_INDEX.put("assertj-core",            List.of("org.assertj.core"));
        PACKAGE_INDEX.put("hamcrest-core",           List.of("org.hamcrest"));
        PACKAGE_INDEX.put("hamcrest",                List.of("org.hamcrest"));
        PACKAGE_INDEX.put("snakeyaml",               List.of("org.yaml.snakeyaml"));
        PACKAGE_INDEX.put("h2",                      List.of("org.h2"));
        PACKAGE_INDEX.put("mysql-connector-java",    List.of("com.mysql", "com.mysql.cj"));
        PACKAGE_INDEX.put("mysql-connector-j",       List.of("com.mysql", "com.mysql.cj"));
        PACKAGE_INDEX.put("postgresql",              List.of("org.postgresql"));
        PACKAGE_INDEX.put("hibernate-core",          List.of("org.hibernate"));
        PACKAGE_INDEX.put("mybatis",                 List.of("org.apache.ibatis"));
        PACKAGE_INDEX.put("flyway-core",             List.of("org.flywaydb"));
        PACKAGE_INDEX.put("liquibase-core",          List.of("liquibase"));
        PACKAGE_INDEX.put("netty-all",               List.of("io.netty"));
        PACKAGE_INDEX.put("kafka-clients",           List.of("org.apache.kafka"));
        PACKAGE_INDEX.put("aws-java-sdk-core",       List.of("com.amazonaws"));
        PACKAGE_INDEX.put("xstream",                 List.of("com.thoughtworks.xstream"));
        PACKAGE_INDEX.put("gson",                    List.of("com.google.gson"));
        PACKAGE_INDEX.put("fastjson",                List.of("com.alibaba.fastjson"));
    }

    private final File baseDir;
    private final Log log;
    private List<Path> javaFiles; // lazily initialised

    public JavaSourceUsageAdapter(File baseDir, Log log) {
        this.baseDir = baseDir;
        this.log = log;
    }

    /**
     * Returns all import-level usages of the given dependency found in the project's
     * Java source files.
     */
    public List<Usage> findUsages(Dependency dep) {
        List<String> prefixes = resolvePackagePrefixes(dep);
        if (prefixes.isEmpty()) return Collections.emptyList();

        List<Path> files = getJavaFiles();
        if (files.isEmpty()) return Collections.emptyList();

        List<Usage> usages = new ArrayList<>();
        for (Path file : files) {
            scanFile(file, prefixes, usages);
        }
        return usages;
    }

    private List<String> resolvePackagePrefixes(Dependency dep) {
        if (PACKAGE_INDEX.containsKey(dep.getArtifactId())) {
            return PACKAGE_INDEX.get(dep.getArtifactId());
        }
        // Heuristic fallback: use last two segments of groupId
        String groupId = dep.getGroupId();
        if (groupId != null && groupId.contains(".")) {
            String[] parts = groupId.split("\\.");
            if (parts.length >= 2) {
                return List.of(parts[parts.length - 2] + "." + parts[parts.length - 1]);
            }
        }
        return Collections.emptyList();
    }

    private void scanFile(Path filePath, List<String> prefixes, List<Usage> usages) {
        String relPath = baseDir.toPath().relativize(filePath).toString().replace('\\', '/');
        try {
            List<String> lines = Files.readAllLines(filePath);
            for (int i = 0; i < lines.size(); i++) {
                String line = lines.get(i).trim();
                if (!line.startsWith("import ")) continue;
                for (String prefix : prefixes) {
                    if (line.startsWith("import " + prefix) ||
                            line.startsWith("import static " + prefix)) {
                        usages.add(new Usage(relPath, i + 1, line));
                        break;
                    }
                }
            }
        } catch (IOException e) {
            log.debug("Could not read file: " + filePath + " — " + e.getMessage());
        }
    }

    private List<Path> getJavaFiles() {
        if (javaFiles == null) {
            javaFiles = new ArrayList<>();
            collectJavaFiles(new File(baseDir, "src/main/java"), javaFiles);
            collectJavaFiles(new File(baseDir, "src/test/java"), javaFiles);
            log.debug("JavaSourceUsageAdapter: found " + javaFiles.size() + " Java files");
        }
        return javaFiles;
    }

    private void collectJavaFiles(File dir, List<Path> result) {
        if (!dir.exists() || !dir.isDirectory()) return;
        try (Stream<Path> walk = Files.walk(dir.toPath())) {
            walk.filter(p -> p.toString().endsWith(".java")).forEach(result::add);
        } catch (IOException e) {
            log.debug("Could not walk " + dir.getAbsolutePath() + ": " + e.getMessage());
        }
    }
}
