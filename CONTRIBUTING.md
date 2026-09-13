# Contributing to dependency-inspector-maven-plugin

## Tabla de contenidos

1. [Flujo de ramas (Gitflow)](#1-flujo-de-ramas-gitflow)
2. [Formato de commits (Conventional Commits)](#2-formato-de-commits-conventional-commits)
3. [Proceso de Pull Request](#3-proceso-de-pull-request)
4. [Tests obligatorios](#4-tests-obligatorios)
5. [Estándares de código](#5-estándares-de-código)
6. [Entorno de desarrollo](#6-entorno-de-desarrollo)

---

## 1. Flujo de ramas (Gitflow)

```
main
 └── develop
      ├── feature/<nombre>
      ├── fix/<nombre>
      └── docs/<nombre>

release/<x.y.z>   (rama temporal desde develop → mergea a main y develop)
hotfix/<nombre>    (rama temporal desde main   → mergea a main y develop)
```

| Rama | Propósito | Origen | Destino merge |
|------|-----------|--------|---------------|
| `main` | Código listo para release. Solo recibe merges de `release/*` y `hotfix/*`. | — | — |
| `develop` | Integración. Base de trabajo diario. | `main` | — |
| `feature/<nombre>` | Nueva funcionalidad. | `develop` | `develop` |
| `fix/<nombre>` | Corrección de bug no urgente. | `develop` | `develop` |
| `docs/<nombre>` | Solo documentación. | `develop` | `develop` |
| `release/<x.y.z>` | Preparación de release: bump de versión, changelog. | `develop` | `main` + `develop` |
| `hotfix/<nombre>` | Fix urgente en producción. | `main` | `main` + `develop` |

### Naming de ramas

```
feature/usage-scanner
feature/canvas-dep-graph
fix/osv-timeout-retry
fix/pom-property-update
docs/contributing-guide
release/1.1.0
hotfix/null-pointer-version-resolver
```

Reglas:
- Minúsculas, palabras separadas con `-`
- Sin acentos ni espacios
- Descriptivo pero corto (máx 5 palabras)

---

## 2. Formato de commits (Conventional Commits)

Seguimos [Conventional Commits v1.0](https://www.conventionalcommits.org/).

### Estructura

```
<type>(<scope>): <descripción corta en imperativo>

[cuerpo opcional — explica el POR QUÉ, no el qué]

[footer opcional: BREAKING CHANGE, Closes #N]
```

### Tipos permitidos

| Tipo | Cuándo usarlo |
|------|---------------|
| `feat` | Nueva funcionalidad visible para el usuario del plugin |
| `fix` | Corrección de bug |
| `test` | Añadir o modificar tests (sin cambiar código de producción) |
| `refactor` | Cambio de código que no añade feature ni corrige bug |
| `docs` | Solo documentación (CONTRIBUTING, Javadoc, README) |
| `chore` | Mantenimiento: deps, CI, pom.xml sin feature |
| `perf` | Mejora de rendimiento |
| `revert` | Revertir un commit anterior |

### Scope (opcional pero recomendado)

```
feat(osv-client): add batch retry with exponential backoff
fix(pom-modifier): handle version ranges without crashing
test(analyze-mojo): add multi-module detection test
chore(deps): upgrade okhttp to 5.4.0
```

Scopes comunes: `analyze-mojo`, `upgrade-mojo`, `osv-client`, `version-resolver`,
`pom-modifier`, `html-report`, `usage-scanner`, `interactive-console`, `compat-checker`.

### Ejemplos correctos

```
feat(usage-scanner): add 47 library-to-package mappings

fix(pom-modifier): skip version ranges instead of writing garbage

test(osv-client): verify 3 retry attempts on timeout

docs: add CONTRIBUTING.md with gitflow and commit standards

chore: bump jackson-databind to 2.17.2

feat(html-report)!: replace table layout with canvas dependency graph

BREAKING CHANGE: HtmlReportGenerator.generate() now requires AnalysisReport
with non-null results list.
```

### Reglas

- Descripción en **imperativo presente** («add», «fix», «update» — no «added», «fixed»)
- Sin mayúscula inicial en la descripción corta
- Sin punto final
- Línea de asunto ≤ 72 caracteres
- `!` después del tipo/scope indica BREAKING CHANGE
- BREAKING CHANGE requiere descripción en el footer

---

## 3. Proceso de Pull Request

### Antes de abrir un PR

```bash
# 1. Asegúrate de que tu rama está actualizada con develop
git fetch origin
git rebase origin/develop

# 2. Compila sin errores
mvn clean compile -q

# 3. Todos los tests pasan
mvn test

# 4. El plugin se instala correctamente
mvn install -DskipTests -q

# 5. Verifica con el test-consumer
cd test-consumer
mvn io.github.Miguel-Sanchez241001:dependency-inspector-maven-plugin:1.0-SNAPSHOT:analyze
```

### Tamaño de PR

- Un PR = un propósito. No mezcles features con fixes no relacionados.
- Si el PR es mayor de ~400 líneas, considera partirlo.

### Revisión

- Al menos **1 aprobación** antes de mergear (incluso si eres el único maintainer: revísalo al día siguiente con ojos frescos).
- El CI debe estar en verde antes de mergear.
- Merge strategy: **Squash & Merge** para `feature/*` y `fix/*`. **Merge commit** para `release/*` y `hotfix/*`.

---

## 4. Tests obligatorios

### Regla general

**Todo código de producción nuevo debe tener al menos un test.**

| Qué añades | Test requerido |
|------------|----------------|
| Nuevo `Mojo` | `@MojoTest` en `src/test/java/.../mojo/` |
| Nuevo `Service` | Unit test con Mockito o MockWebServer |
| Nuevo método público en service existente | Test del método (happy path + error path) |
| Cambio en lógica de parseo | Test con input real o JSON fixture |
| Cambio en `HtmlReportGenerator` | Test que verifica que el HTML contiene el fragmento esperado |

### Cobertura mínima

No usamos un umbral numérico fijo, pero la regla es:
- Los **casos happy-path** de cada componente deben estar cubiertos.
- Los **caminos de error** críticos (timeout, respuesta malformada, POM corrupto) deben tener test.
- No se aceptan PRs que **eliminen tests** sin justificación en el cuerpo del PR.

### Estructura de tests

```
src/test/java/.../
├── mojo/
│   ├── AnalyzeMojoTest.java      ← @MojoTest, usa stub pom en test/resources
│   └── UpgradeMojoTest.java
└── service/
    ├── OsvClientTest.java         ← MockWebServer
    ├── VersionResolverTest.java   ← MockWebServer
    ├── UsageScannerTest.java
    └── PomModifierTest.java

src/test/resources/unit/test-project/
└── pom.xml                        ← stub con deps vulnerables conocidas
```

### Ejecutar tests

```bash
# Todos los tests
mvn test

# Solo un test
mvn test -Dtest=OsvClientTest

# Con output detallado
mvn test -pl . -Dsurefire.useFile=false
```

---

## 5. Estándares de código

### Java

- **Java 11** como target mínimo. No usar APIs de Java 12+.
- Sin dependencias de utilidad innecesarias. Preferir la API estándar de Java.
- Clases de servicio: **constructor injection**, sin campos estáticos mutables.
- Ningún `System.out.println` — usar el `Log` de Maven (`getLog()`).
- Ningún `e.printStackTrace()` — logear con `log.error(msg, e)`.
- Ningún `catch (Exception e) {}` vacío.

### Seguridad

- `DocumentBuilderFactory`: siempre con `disallow-doctype-decl = true` (previene XXE).
- HTTP con `OkHttpClient`: no pasar `skipSslVerification=true` por defecto.
- Ningún secreto, token o credencial en código fuente.

### Diseño

- **Composición sobre herencia** entre servicios y Mojos.
- Los Mojos nunca lanzan `MojoFailureException` (el plugin no rompe el build).
- Los servicios externos que fallen retornan `null` o lista vacía; nunca propagan la excepción al Mojo.
- Seguir el principio de **mínimo cambio necesario**: si el PR arregla un bug, no refactorizar código no relacionado en el mismo commit.

---

## 6. Entorno de desarrollo

### Requisitos

| Herramienta | Versión mínima |
|-------------|----------------|
| Java (JDK) | 11 |
| Maven | 3.6 |
| Git | 2.x |

### Setup inicial

```bash
git clone https://github.com/Miguel-Sanchez241001/dependency-inspector-maven-plugin.git
cd dependency-inspector-maven-plugin
git checkout develop

# Compilar e instalar el plugin localmente
mvn clean install

# Probar con el proyecto de prueba incluido
cd test-consumer
mvn io.github.Miguel-Sanchez241001:dependency-inspector-maven-plugin:1.0-SNAPSHOT:analyze
```

### Estructura del proyecto

```
dependency-inspector-maven-plugin/
├── src/
│   ├── main/java/.../depinspector/
│   │   ├── mojo/          ← AnalyzeMojo, UpgradeMojo
│   │   ├── model/         ← POJOs (DependencyInfo, VulnerabilityInfo, …)
│   │   ├── service/       ← OsvClient, VersionResolver, UsageScanner, …
│   │   ├── report/        ← HtmlReportGenerator
│   │   └── util/          ← HttpClientFactory, RetryExecutor
│   └── test/
│       ├── java/           ← OsvClientTest, AnalyzeMojoTest, …
│       └── resources/unit/ ← stub POM para tests de Mojo
├── test-consumer/          ← proyecto con CVEs conocidos para prueba manual
├── docs/                   ← requirements.md, research docs
├── .github/
│   ├── ISSUE_TEMPLATE/
│   ├── pull_request_template.md
│   └── workflows/ci.yml
├── CHANGELOG.md
└── CONTRIBUTING.md
```
