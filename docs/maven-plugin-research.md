# Maven Plugin Development — Investigación Completa

> Documento de contexto para construir un plugin de Maven desde cero.
> Fuentes: documentación oficial Apache Maven, Sonatype Central, y referencias técnicas verificadas.

---

## 1. ¿Qué es un Plugin de Maven?

Un plugin de Maven es un JAR con packaging especial (`maven-plugin`) que contiene uno o varios **Mojos** (Maven Plain Old Java Objects). Cada Mojo representa un **goal** ejecutable dentro del ciclo de vida de Maven.

- **Plugin** → agrupa goals relacionados (ej: `maven-compiler-plugin`)
- **Goal** → acción concreta (ej: `compiler:compile`)
- **Mojo** → clase Java que implementa un goal

---

## 2. Estructura del Proyecto

```
mi-maven-plugin/
├── pom.xml                          ← packaging = maven-plugin
└── src/
    ├── main/
    │   └── java/
    │       └── com/ejemplo/
    │           └── MiMojo.java      ← extiende AbstractMojo
    └── test/
        ├── java/
        │   └── com/ejemplo/
        │       └── MiMojoTest.java
        └── resources/
            └── unit/
                └── proyecto-test/
                    └── pom.xml      ← POM stub para los tests
```

---

## 3. POM del Plugin (`pom.xml`)

```xml
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.ejemplo</groupId>

  <!-- Convención: {nombre}-maven-plugin -->
  <!-- NUNCA: maven-{nombre}-plugin  ← reservado para Apache -->
  <artifactId>dependency-inspector-maven-plugin</artifactId>
  <version>1.0-SNAPSHOT</version>

  <!-- CRÍTICO: debe ser maven-plugin -->
  <packaging>maven-plugin</packaging>

  <properties>
    <maven-plugin-tools.version>3.15.2</maven-plugin-tools.version>
    <maven.version>3.9.9</maven.version>
  </properties>

  <dependencies>
    <!-- API base del plugin (provided: ya lo tiene Maven en runtime) -->
    <dependency>
      <groupId>org.apache.maven</groupId>
      <artifactId>maven-plugin-api</artifactId>
      <version>${maven.version}</version>
      <scope>provided</scope>
    </dependency>

    <!-- Anotaciones @Mojo, @Parameter, @Component -->
    <dependency>
      <groupId>org.apache.maven.plugin-tools</groupId>
      <artifactId>maven-plugin-annotations</artifactId>
      <version>${maven-plugin-tools.version}</version>
      <scope>provided</scope>
    </dependency>

    <!-- Acceso a MavenProject, dependencias, etc. -->
    <dependency>
      <groupId>org.apache.maven</groupId>
      <artifactId>maven-core</artifactId>
      <version>${maven.version}</version>
      <scope>provided</scope>
    </dependency>

    <!-- Resolución de artefactos con Eclipse Aether -->
    <dependency>
      <groupId>org.apache.maven.resolver</groupId>
      <artifactId>maven-resolver-api</artifactId>
      <version>1.9.22</version>
      <scope>provided</scope>
    </dependency>

    <!-- HTTP client (si se necesita llamar APIs externas) -->
    <dependency>
      <groupId>com.squareup.okhttp3</groupId>
      <artifactId>okhttp</artifactId>
      <version>5.4.0</version>
    </dependency>

    <!-- Testing -->
    <dependency>
      <groupId>org.apache.maven.plugin-testing</groupId>
      <artifactId>maven-plugin-testing-harness</artifactId>
      <version>4.0.0-alpha-2</version>
      <scope>test</scope>
    </dependency>
    <dependency>
      <groupId>org.junit.jupiter</groupId>
      <artifactId>junit-jupiter-api</artifactId>
      <version>5.11.0</version>
      <scope>test</scope>
    </dependency>
  </dependencies>

  <build>
    <pluginManagement>
      <plugins>
        <!-- Genera plugin.xml y el goal de ayuda -->
        <plugin>
          <groupId>org.apache.maven.plugins</groupId>
          <artifactId>maven-plugin-plugin</artifactId>
          <version>${maven-plugin-tools.version}</version>
          <executions>
            <execution>
              <id>help-mojo</id>
              <goals>
                <goal>helpmojo</goal>
              </goals>
            </execution>
          </executions>
        </plugin>
      </plugins>
    </pluginManagement>
  </build>
</project>
```

---

## 4. Clase Mojo — Estructura Completa

### 4.1 Mojo Mínimo

```java
package com.ejemplo;

import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.LifecyclePhase;

@Mojo(
    name = "inspect",                          // nombre del goal: mvn dependency-inspector:inspect
    defaultPhase = LifecyclePhase.VERIFY,      // fase por defecto
    requiresProject = true                     // necesita estar dentro de un proyecto
)
public class InspectorMojo extends AbstractMojo {

    @Override
    public void execute() throws MojoExecutionException, MojoFailureException {
        getLog().info("Ejecutando inspector de dependencias...");
    }
}
```

### 4.2 Mojo Completo con Parámetros, MavenProject y Resolución de Dependencias

```java
package com.ejemplo;

import org.apache.maven.artifact.Artifact;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.*;
import org.apache.maven.project.MavenProject;
import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.artifact.DefaultArtifact;
import org.eclipse.aether.repository.RemoteRepository;
import org.eclipse.aether.resolution.ArtifactRequest;
import org.eclipse.aether.resolution.ArtifactResult;

import java.io.File;
import java.util.List;
import java.util.Set;

@Mojo(
    name = "inspect",
    defaultPhase = LifecyclePhase.VERIFY,
    requiresDependencyResolution = ResolutionScope.COMPILE_PLUS_RUNTIME
)
public class InspectorMojo extends AbstractMojo {

    // ─── Parámetros configurables desde el pom.xml del usuario ───────────────

    /** Si true, falla el build cuando encuentra una vulnerabilidad. */
    @Parameter(property = "inspector.failOnVulnerability", defaultValue = "true")
    private boolean failOnVulnerability;

    /** URL de la API de vulnerabilidades. */
    @Parameter(property = "inspector.apiUrl", required = true)
    private String apiUrl;

    /** Directorio de salida del reporte. */
    @Parameter(defaultValue = "${project.build.directory}/inspector-report", required = true)
    private File outputDirectory;

    // ─── Componentes inyectados por Maven ─────────────────────────────────────

    /** El proyecto Maven actual (acceso a groupId, dependencias, etc.). */
    @Parameter(defaultValue = "${project}", readonly = true, required = true)
    private MavenProject project;

    /** Sistema de resolución de artefactos (Eclipse Aether). */
    @Component
    private RepositorySystem repoSystem;

    /** Sesión del repositorio (credenciales, caché local, etc.). */
    @Parameter(defaultValue = "${repositorySystemSession}", readonly = true, required = true)
    private RepositorySystemSession repoSession;

    /** Repositorios remotos del proyecto. */
    @Parameter(defaultValue = "${project.remoteProjectRepositories}", readonly = true, required = true)
    private List<RemoteRepository> repositories;

    // ─── Implementación del goal ──────────────────────────────────────────────

    @Override
    public void execute() throws MojoExecutionException {
        getLog().info("Inspeccionando dependencias del proyecto: " + project.getArtifactId());

        Set<Artifact> dependencies = project.getDependencyArtifacts();

        for (Artifact artifact : dependencies) {
            getLog().info(String.format(
                "  → %s:%s:%s",
                artifact.getGroupId(),
                artifact.getArtifactId(),
                artifact.getVersion()
            ));

            // Resolver el artefacto físico (obtener el .jar en disco)
            File jarFile = resolveArtifact(artifact);
            if (jarFile != null) {
                getLog().debug("  JAR en: " + jarFile.getAbsolutePath());
            }

            // Aquí se llamaría la API externa de vulnerabilidades
            // checkVulnerability(artifact, apiUrl);
        }
    }

    private File resolveArtifact(Artifact unresolvedArtifact) throws MojoExecutionException {
        try {
            org.eclipse.aether.artifact.Artifact aetherArtifact = new DefaultArtifact(
                unresolvedArtifact.getGroupId(),
                unresolvedArtifact.getArtifactId(),
                unresolvedArtifact.getClassifier(),
                unresolvedArtifact.getType(),
                unresolvedArtifact.getVersion()
            );

            ArtifactRequest request = new ArtifactRequest()
                .setArtifact(aetherArtifact)
                .setRepositories(repositories);

            ArtifactResult result = repoSystem.resolveArtifact(repoSession, request);
            return result.getArtifact().getFile();

        } catch (Exception e) {
            throw new MojoExecutionException("Error resolviendo: " + unresolvedArtifact, e);
        }
    }
}
```

---

## 5. Anotaciones Clave

| Anotación | Uso |
|-----------|-----|
| `@Mojo(name, defaultPhase, requiresProject, requiresDependencyResolution)` | Define el goal — **obligatoria** |
| `@Parameter(property, defaultValue, required, readonly)` | Parámetro configurable desde el `<configuration>` del usuario |
| `@Component` | Inyecta un componente del contenedor de Maven (Guice/Plexus) |
| `@Execute(phase)` | Ejecuta una fase del lifecycle antes de que corra este goal |

### `requiresDependencyResolution` — valores:
- `ResolutionScope.NONE` → no resuelve dependencias (default)
- `ResolutionScope.COMPILE` → solo compile
- `ResolutionScope.COMPILE_PLUS_RUNTIME` → compile + runtime
- `ResolutionScope.RUNTIME` → solo runtime
- `ResolutionScope.TEST` → todas (incluyendo test)

---

## 6. Ciclo de Vida de Maven — Fases Disponibles para Binding

El ciclo `default` en orden completo:

```
validate → initialize → generate-sources → process-sources →
generate-resources → process-resources → compile → process-classes →
generate-test-sources → process-test-sources → generate-test-resources →
process-test-resources → test-compile → process-test-classes →
test → prepare-package → package → pre-integration-test →
integration-test → post-integration-test → verify → install → deploy
```

**Fases más usadas para plugins de análisis/inspección:**
- `generate-sources` → generar código antes de compilar
- `compile` → post-compilación
- `verify` → antes de instalar, ideal para validaciones y auditorías
- `package` → cuando ya existe el JAR del proyecto

---

## 7. Integración de Servicios Externos (HTTP)

No hay nada especial — simplemente se añade el cliente HTTP como **dependencia normal** al `pom.xml` del plugin (scope `compile`, no `provided`). El classpath del plugin está **aislado** del classpath del proyecto que lo usa.

```xml
<!-- pom.xml del plugin -->
<dependency>
    <groupId>com.squareup.okhttp3</groupId>
    <artifactId>okhttp</artifactId>
    <version>5.4.0</version>
    <!-- scope compile: se empaqueta dentro del plugin -->
</dependency>
```

```java
// Dentro del Mojo
import okhttp3.*;

private void checkVulnerability(Artifact artifact, String apiUrl) throws MojoExecutionException {
    OkHttpClient client = new OkHttpClient();

    String url = apiUrl + "?groupId=" + artifact.getGroupId()
                        + "&artifactId=" + artifact.getArtifactId()
                        + "&version=" + artifact.getVersion();

    Request request = new Request.Builder().url(url).build();

    try (Response response = client.newCall(request).execute()) {
        if (!response.isSuccessful()) {
            throw new MojoExecutionException("API respondió: " + response.code());
        }
        String body = response.body().string();
        getLog().info("Respuesta API: " + body);
        // Parsear JSON y decidir si failOnVulnerability
    } catch (IOException e) {
        throw new MojoExecutionException("Error llamando API de vulnerabilidades", e);
    }
}
```

> **Classpath isolation:** Las dependencias del plugin NO entran en conflicto con las del proyecto
> que lo usa. Maven maneja dos classloaders distintos.

---

## 8. Cómo Usar el Plugin en Otro Proyecto

### 8.1 Ejecución manual desde línea de comandos

```bash
# Forma completa
mvn com.ejemplo:dependency-inspector-maven-plugin:1.0-SNAPSHOT:inspect

# Forma corta (si está en settings.xml o groupId termina en "plugin")
mvn dependency-inspector:inspect
```

### 8.2 Vincular al ciclo de vida en el `pom.xml` del proyecto consumidor

```xml
<build>
  <plugins>
    <plugin>
      <groupId>com.ejemplo</groupId>
      <artifactId>dependency-inspector-maven-plugin</artifactId>
      <version>1.0-SNAPSHOT</version>
      <configuration>
        <apiUrl>https://api.vulnerabilidades.com/check</apiUrl>
        <failOnVulnerability>true</failOnVulnerability>
        <outputDirectory>${project.build.directory}/security-report</outputDirectory>
      </configuration>
      <executions>
        <execution>
          <id>inspeccionar-dependencias</id>
          <phase>verify</phase>
          <goals>
            <goal>inspect</goal>
          </goals>
        </execution>
      </executions>
    </plugin>
  </plugins>
</build>
```

---

## 9. Testing del Plugin

```xml
<!-- Dependencias de test en el pom.xml del plugin -->
<dependency>
    <groupId>org.apache.maven.plugin-testing</groupId>
    <artifactId>maven-plugin-testing-harness</artifactId>
    <version>4.0.0-alpha-2</version>
    <scope>test</scope>
</dependency>
```

```java
// src/test/java/com/ejemplo/InspectorMojoTest.java
import org.apache.maven.api.plugin.testing.InjectMojo;
import org.apache.maven.api.plugin.testing.MojoParameter;
import org.apache.maven.api.plugin.testing.MojoTest;
import org.junit.jupiter.api.Test;

@MojoTest
class InspectorMojoTest {

    @Test
    @InjectMojo(goal = "inspect", pom = "src/test/resources/unit/proyecto-test/pom.xml")
    void testInspect(InspectorMojo mojo) throws Exception {
        mojo.execute();
        // Assertions aquí
    }

    @Test
    @InjectMojo(goal = "inspect")
    @MojoParameter(name = "apiUrl", value = "http://localhost:8080/mock")
    @MojoParameter(name = "failOnVulnerability", value = "false")
    void testInspectConParametros(InspectorMojo mojo) throws Exception {
        mojo.execute();
    }
}
```

```xml
<!-- src/test/resources/unit/proyecto-test/pom.xml -->
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.test</groupId>
  <artifactId>proyecto-para-test</artifactId>
  <version>1.0-SNAPSHOT</version>

  <dependencies>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>33.3.1-jre</version>
    </dependency>
  </dependencies>
</project>
```

---

## 10. Construcción e Instalación Local

```bash
# Compilar y instalar en ~/.m2/repository (disponible para proyectos locales)
mvn clean install

# Generar el descriptor del plugin (plugin.xml en META-INF/maven/)
mvn plugin:descriptor

# Ver información del plugin
mvn plugin:help

# Ejecutar un goal específico en otro proyecto
cd /ruta/proyecto-consumidor
mvn com.ejemplo:dependency-inspector-maven-plugin:1.0-SNAPSHOT:inspect
```

---

## 11. Publicación en Maven Central (2025)

> **Cambio importante:** OSSRH fue **discontinuado el 30 de junio de 2025**.
> Ahora se usa el **Central Portal**: https://central.sonatype.com

### 11.1 Pasos para publicar

1. **Registrarse** en [central.sonatype.com](https://central.sonatype.com)
2. **Registrar namespace** (= tu `groupId`)
   - Si usas GitHub: `io.github.tuusuario` → verificación automática en minutos
   - Si tienes dominio propio (`com.tuempresa`) → verifica via registro TXT DNS
3. **Generar clave GPG** para firmar artefactos
4. **Configurar `~/.m2/settings.xml`** con credenciales
5. **Publicar** con `mvn deploy`

### 11.2 Requisitos mínimos para Maven Central

| Requisito | Plugin necesario |
|-----------|-----------------|
| Sources JAR | `maven-source-plugin` |
| Javadoc JAR | `maven-javadoc-plugin` |
| Firmas GPG | `maven-gpg-plugin` |
| POM completo (name, description, url, scm, licenses, developers) | — |

### 11.3 POM completo para publicación

```xml
<build>
  <plugins>
    <!-- Sources -->
    <plugin>
      <groupId>org.apache.maven.plugins</groupId>
      <artifactId>maven-source-plugin</artifactId>
      <version>3.3.1</version>
      <executions>
        <execution>
          <id>attach-sources</id>
          <goals><goal>jar-no-fork</goal></goals>
        </execution>
      </executions>
    </plugin>

    <!-- Javadoc -->
    <plugin>
      <groupId>org.apache.maven.plugins</groupId>
      <artifactId>maven-javadoc-plugin</artifactId>
      <version>3.10.1</version>
      <executions>
        <execution>
          <id>attach-javadocs</id>
          <goals><goal>jar</goal></goals>
        </execution>
      </executions>
    </plugin>

    <!-- GPG Signing -->
    <plugin>
      <groupId>org.apache.maven.plugins</groupId>
      <artifactId>maven-gpg-plugin</artifactId>
      <version>3.2.7</version>
      <executions>
        <execution>
          <id>sign-artifacts</id>
          <phase>verify</phase>
          <goals><goal>sign</goal></goals>
        </execution>
      </executions>
    </plugin>

    <!-- Deploy al Central Portal -->
    <plugin>
      <groupId>org.sonatype.central</groupId>
      <artifactId>central-publishing-maven-plugin</artifactId>
      <version>0.6.0</version>
      <extensions>true</extensions>
      <configuration>
        <publishingServerId>central</publishingServerId>
        <autoPublish>true</autoPublish>
      </configuration>
    </plugin>
  </plugins>
</build>
```

### 11.4 Alternativas más rápidas a Maven Central

| Opción | Velocidad | Uso |
|--------|-----------|-----|
| `~/.m2` local (`mvn install`) | Inmediato | Desarrollo local |
| GitHub Packages | Minutos | Proyectos privados/equipo |
| JitPack | Minutos | Open source en GitHub/GitLab |
| Nexus/Artifactory privado | Minutos | Empresa |
| Maven Central | Días (primera vez) | Librería pública |

---

## 12. Generación Rápida con Archetype

```bash
mvn archetype:generate \
  -DgroupId=com.ejemplo \
  -DartifactId=dependency-inspector-maven-plugin \
  -DarchetypeGroupId=org.apache.maven.archetypes \
  -DarchetypeArtifactId=maven-archetype-plugin \
  -DinteractiveMode=false
```

Esto genera toda la estructura base en segundos.

---

## 13. Separación de Classloaders (Importante)

```
Maven Runtime
├── Classpath del Plugin        ← tus deps (okhttp, jackson, etc.)
│   └── InspectorMojo.class
└── Classpath del Proyecto      ← deps del proyecto que usa el plugin
    └── spring-boot, etc.
```

- Las dependencias del plugin **no contaminan** el proyecto del usuario
- El plugin **puede leer** el `MavenProject` del usuario (metadata, archivos, deps)
- Para acceder a las clases compiladas del usuario necesitas trabajo extra con classloaders

---

## 14. Información del MavenProject Disponible

Desde `@Parameter(defaultValue = "${project}") private MavenProject project;`:

```java
project.getArtifactId()           // ID del artefacto del usuario
project.getGroupId()              // grupo
project.getVersion()              // versión
project.getBuild().getSourceDirectory()      // src/main/java
project.getBuild().getOutputDirectory()      // target/classes
project.getBuild().getDirectory()            // target/
project.getDependencies()         // List<Dependency> declaradas en pom.xml
project.getDependencyArtifacts()  // Set<Artifact> resueltos
project.getArtifacts()           // todos los artefactos transitivos
project.getFile()                // ruta al pom.xml del proyecto
project.getProperties()          // propiedades del pom.xml
project.getModel()               // modelo completo del POM
```

---

## Resumen: Flujo Mínimo para Arrancar

```bash
# 1. Generar estructura
mvn archetype:generate -DarchetypeArtifactId=maven-archetype-plugin ...

# 2. Implementar el Mojo (extends AbstractMojo + @Mojo + execute())

# 3. Compilar e instalar localmente
mvn clean install

# 4. Probar en otro proyecto
mvn com.ejemplo:dependency-inspector-maven-plugin:1.0-SNAPSHOT:inspect
```

**Tiempo para tener un plugin funcional localmente: < 1 hora**
**Tiempo para publicar en Maven Central: 1-2 días (primera vez, por verificación del namespace)**

---

## Fuentes

- [Guide to Developing Java Plugins — Apache Maven](https://maven.apache.org/guides/plugin/guide-java-plugin-development.html)
- [Mojo API Specification — Apache Maven](https://maven.apache.org/developers/mojo-api-specification.html)
- [Maven Plugin Testing Harness](https://maven.apache.org/plugin-testing/maven-plugin-testing-harness/)
- [Maven Plugin Tool Annotations](https://maven.apache.org/plugin-tools/maven-plugin-tools-annotations/index.html)
- [Central Publisher Portal Guide — Sonatype](https://central.sonatype.org/publish/publish-portal-guide/)
- [Register a Namespace — Maven Central](https://central.sonatype.org/register/namespace/)
- [Maven Lifecycle Reference](https://maven.apache.org/guides/introduction/introduction-to-the-lifecycle.html)
- [Finding Dependencies Artifacts in your Maven Plugin](https://vzurczak.wordpress.com/2016/01/08/finding-dependencies-artifacts-in-your-maven-plug-in/)
