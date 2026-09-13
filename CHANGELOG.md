# Changelog

Todos los cambios notables de este proyecto se documentan aquí.

Formato: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
Versionado: [Semantic Versioning](https://semver.org/spec/v2.0.0.html)

---

## [Unreleased]

_Cambios en develop pendientes de release._

---

## [1.1.0] — 2026-09-13

### Added
- **Feature A — Grafo de dependencias en HTML** (`HtmlReportGenerator`)
  - Canvas 2D con layout radial de 3 anillos: ROOT → DIRECT (r=180) → TRANSITIVE/PLUGIN (r=340)
  - Nodos coloreados por estado: rojo (vulnerable), naranja (scope issue), verde (limpio), gris (saltado)
  - Tooltip flotante al hacer hover: coords, scope, CVSS, archivos que la usan
  - Click en nodo hace scroll hasta la tarjeta de la dependencia en la tabla
  - Leyenda de colores debajo del canvas
  - JSON de datos embebido inline (sin CDN externo)

- **Feature B — UsageScanner** (`service/UsageScanner`)
  - Escanea `src/main/java` y `src/test/java` buscando imports por dependencia
  - 47 mapeos hardcoded de `artifactId` a paquetes Java (log4j, jackson, spring, mockito, etc.)
  - Heurística fallback usando los últimos 2 segmentos del `groupId`
  - Nuevo model `UsageLocation` (fileName, lineNumber, importStatement)
  - Campo `List<UsageLocation> usages` en `AnalysisResult`
  - Sección "Clases que usan esta dependencia" en cada tarjeta del reporte HTML

- **Feature C — Consola interactiva en el goal `upgrade`**
  - Nuevo parámetro `-Dinteractive=true` en `UpgradeMojo`
  - `InteractiveConsole`: menú por dependencia con opciones a) Upgrade, b) Exclude, c) Skip
  - Timeout de 60 segundos con `ExecutorService.submit().get(60, SECONDS)` → auto-Skip
  - Hasta 3 reintentos ante input inválido
  - Sin flag: solo pregunta automáticamente por cambios de alto riesgo (UPGRADE_MAJOR, ALTERNATIVE_LIB)

- **`PomModifier.applyExclusions()`**: inserta `<exclusion>` via DOM XML en la dependencia padre
- **`InteractiveDecision` enum**: UPGRADE, EXCLUDE, SKIP
- **Gobernanza del proyecto**: CONTRIBUTING.md, PR template, issue templates, CI workflow (GitHub Actions)

### Changed
- `AnalyzeMojo.doExecute()`: llama a `UsageScanner.scan()` antes de generar el reporte
- `UpgradeMojo.doExecute()`: llama a `UsageScanner.scan()`, nuevo flujo interactivo, resumen extendido
- `HtmlReportGenerator`: refactorizado para incluir grafo Canvas y sección de usages por tarjeta; cada tarjeta tiene atributo `data-dep-id` para click-to-scroll

---

## [1.0.0] — 2026-09-12

### Added
- **Goal `analyze`**: audita dependencias directas, transitivas y plugins via OSV.dev
  - Batch de 50 deps por request a `POST /v1/querybatch`
  - `RetryExecutor`: 3 intentos con backoff exponencial (1s → 2s → 4s)
  - `VersionResolver`: busca en `maven-metadata.xml` la versión limpia más nueva
  - `CompatibilityChecker`: usa japicmp para detectar breaking changes binarios
  - `ScopeAnalyzer`: detecta librerías de test en scope compile/runtime
  - `HtmlReportGenerator`: reporte HTML auto-contenido con CSS embebido
  - Parámetros: `skipSslVerification`, `outputDirectory`

- **Goal `upgrade`**: aplica upgrades PATCH y MINOR automáticamente en el `pom.xml`
  - `PomModifier`: maneja versiones directas, `${propiedades}` y detecta rangos de versión
  - Backup automático en `target/dependency-inspector/pom.xml.bak`
  - Parámetros: `dryRun`, `artifact` (filtro selectivo)

- **Models**: `DependencyInfo`, `VulnerabilityInfo`, `UpgradeRecommendation`, `AnalysisResult`, `AnalysisReport`, `ScopeIssue`
- **Utils**: `HttpClientFactory` (con soporte `skipSslVerification`), `RetryExecutor`
- **Tests**: `OsvClientTest` (MockWebServer), `VersionResolverTest`, `AnalyzeMojoTest` — 9/9 pasan
- **`test-consumer`**: proyecto de prueba con log4j:1.2.17 y jackson-databind:2.9.10

---

[Unreleased]: https://github.com/Miguel-Sanchez241001/dependency-inspector-maven-plugin/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/Miguel-Sanchez241001/dependency-inspector-maven-plugin/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/Miguel-Sanchez241001/dependency-inspector-maven-plugin/releases/tag/v1.0.0
