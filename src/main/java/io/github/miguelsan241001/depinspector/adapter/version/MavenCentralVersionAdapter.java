package io.github.miguelsan241001.depinspector.adapter.version;

import io.github.miguelsan241001.depinspector.domain.model.Dependency;
import io.github.miguelsan241001.depinspector.domain.port.VersionSource;
import io.github.miguelsan241001.depinspector.domain.port.VulnerabilitySource;
import io.github.miguelsan241001.depinspector.model.DependencyInfo;
import io.github.miguelsan241001.depinspector.service.OsvClient;
import io.github.miguelsan241001.depinspector.service.VersionResolver;
import okhttp3.OkHttpClient;
import org.apache.maven.plugin.logging.Log;

import java.util.Collections;
import java.util.List;

/**
 * Implements {@link VersionSource} by delegating to {@link VersionResolver}
 * (Maven Central maven-metadata.xml fetcher).
 */
public class MavenCentralVersionAdapter implements VersionSource {

    private final VersionResolver versionResolver;
    private final VulnerabilitySource vulnSource;

    public MavenCentralVersionAdapter(OkHttpClient httpClient,
                                       OsvClient osvClient,
                                       VulnerabilitySource vulnSource,
                                       Log log) {
        this.versionResolver = new VersionResolver(httpClient, osvClient, log);
        this.vulnSource = vulnSource;
    }

    @Override
    public List<String> findAvailableVersions(Dependency dep) {
        DependencyInfo legacyDep = toLegacy(dep);
        List<String> versions = versionResolver.fetchAvailableVersions(legacyDep);
        return versions != null ? versions : Collections.emptyList();
    }

    @Override
    public boolean hasVulnerabilities(Dependency dep) {
        List<?> vulns = vulnSource.findVulnerabilities(List.of(dep)).get(dep);
        return vulns != null && !vulns.isEmpty();
    }

    private DependencyInfo toLegacy(Dependency dep) {
        return new DependencyInfo(
                dep.getGroupId(), dep.getArtifactId(), dep.getVersion(),
                dep.getScope(), DependencyInfo.DependencyType.valueOf(dep.getType().name()));
    }
}
