# Requerimientos — dependency-inspector-maven-plugin

> Score: 82/100 — CLARO
> Última actualización: 2026-09-12

---

## Contexto general

Plugin de Maven de **uso exclusivamente personal del desarrollador**. No forma parte
del flujo de build principal (CI/CD). No debe interrumpir ni bloquear ningún pipeline.
El desarrollador lo invoca manualmente cuando quiere auditar su proyecto.

- Proyecto target: **single-module únicamente** (no reactor/multi-módulo)
- Invocación: manual, desde línea de comandos
- Requiere: Maven 3.6+, Java 11+
- Sin tokens, sin cuentas externas, 100% open source

---

## Goal 1 — `analyze`

### Qué hace
Escanea **todas las dependencias del proyecto** (directas + transitivas, todos los
scopes: compile, runtime, test, provided, system) y también los **plugins de Maven**
declarados en `<build><plugins>`. Para cada una, consulta todas las fuentes de
vulnerabilidades disponibles y genera un reporte HTML.

### Fuentes de vulnerabilidades
- **OSV.dev** (primaria) — gratuita, sin token, cubre el ecosistema Maven
- Otras fuentes open source que apliquen (NVD feed, GitHub Advisory Database via OSV)
- Todas las fuentes se agregan; si la misma CVE aparece en varias, se deduplica

### Reporte HTML — campos por dependencia

| Campo | Descripción |
|-------|-------------|
| `groupId:artifactId:version` | Coordenadas de la dependencia |
| Tipo de uso | **Directa** o **Transitiva** |
| Origen transitivo | Si es transitiva: qué dependencia directa la trae |
| Origen de la vulnerabilidad | La dependencia raíz donde vive el problema |
| CVEs encontrados | ID, descripción, score CVSS, severidad |
| Fuente | De qué base de datos proviene el CVE |
| Versión de upgrade disponible | Última versión sin CVE conocido |
| Comandos de upgrade | Listos para copiar y ejecutar |
| Si no hay versión alternativa | Ver sección "Sin versión disponible" abajo |

### Si no hay versión sin CVE disponible

El reporte debe mostrar **una de estas tres opciones** según el caso:

1. **Librería alternativa** — sugerir una librería equivalente que cumpla la misma
   función, con ejemplo de uso y cambios necesarios en el código
2. **Exclusión** — si la dependencia vulnerable es una transitiva y no se usa
   directamente, mostrar cómo excluirla del POM
3. **Implementación propia** — si la funcionalidad es simple y la librería no está
   siendo usada activamente en el código, explicar cómo reemplazarla con lógica pura

### Criterio de aceptación
El goal `analyze` está **terminado** cuando:
- El HTML se genera en `${project.build.directory}/dependency-inspector/report.html`
- El build **no falla** (solo informa, nunca interrumpe)
- El reporte cubre 100% de las dependencias del proyecto (directas + transitivas)

---

## Goal 2 — `upgrade`

### Qué hace
Basado en el resultado del análisis, aplica o recomienda actualizaciones de versión
en el `pom.xml`. El criterio de aplicación automática es simple:

### Regla de aplicación

| Tipo de cambio | Acción |
|----------------|--------|
| **Patch** (x.y.Z → x.y.Z+n) | Aplica automáticamente |
| **Minor** (x.Y.z → x.Y+n.0) | Aplica automáticamente |
| **Major** (X.y.z → X+n.0.0) | Solo recomienda, no aplica |

> No hay score de bloqueo para patch y minor. Si hay versión más nueva sin CVE
> y el cambio es patch o minor, se aplica. Major siempre es manual.

### Modo `--dryRun`
Simula los cambios sin tocar el `pom.xml`. Imprime en consola exactamente qué
líneas cambiarían y muestra los comandos equivalentes.

### Comandos en el reporte
El reporte HTML del `analyze` debe incluir, por cada dependencia upgradeable,
el comando listo para ejecutar:
```
mvn dependency-inspector:upgrade -Dartifact=groupId:artifactId
```

### Criterio de aceptación
El goal `upgrade` está **terminado** cuando:
- Se ejecuta `analyze` nuevamente y la librería ya no aparece como vulnerable
- El `pom.xml` fue modificado correctamente (o el dry-run reporta los cambios esperados)

### Backup del pom.xml
Antes de modificar el `pom.xml`, el plugin guarda una copia en:
`${project.build.directory}/dependency-inspector/pom.xml.bak`

---

## Alcance — qué entra y qué NO

### Entra
- Dependencias directas del proyecto
- Dependencias transitivas (con trazabilidad al origen)
- Todos los scopes: `compile`, `runtime`, `test`, `provided`, `system`
- Plugins de Maven declarados en `<build><plugins>`

### NO entra
- Proyectos multi-módulo / reactor builds
- Análisis del código fuente del proyecto (solo se analiza el POM y los JARs)
- Integración con CI/CD (es una herramienta de desarrollador)
- Subir resultados a ningún servidor externo

---

## Casos límite y comportamiento ante fallos

### Servicios externos (OSV.dev, Maven Central, etc.)
- **Reintentos**: 3 intentos con backoff exponencial antes de fallar
- Si después de 3 intentos no hay respuesta: advertencia en consola + esa dependencia
  se marca como "no analizada" en el reporte (no falla el build)

### Sin versión nueva disponible
Ver sección "Si no hay versión sin CVE disponible" en Goal 1.

### Versiones SNAPSHOT
Se tratan igual que versiones estables. Se reportan sus CVEs si los tienen.
Se intenta upgrade igual. Si la versión de upgrade también es SNAPSHOT, se informa.

### JAR no descargable para análisis de compatibilidad (japicmp)
1. Intentar con el repositorio local (`~/.m2/repository`)
2. Intentar con los repositorios remotos configurados en el proyecto
3. Intentar con Maven Central directamente
4. Si ninguno funciona: informar en el reporte la URL de descarga manual y el
   procedimiento para instalarlo localmente con `mvn install:install-file`

### Flag para ignorar SSL
```xml
<configuration>
  <skipSslVerification>true</skipSslVerification>
</configuration>
```
O desde línea de comandos:
```
mvn dependency-inspector:analyze -DskipSslVerification=true
```
Aplica tanto para llamadas HTTP (OSV.dev) como para descarga de JARs via Aether.

---

## Stack técnico confirmado

| Componente | Librería | Versión |
|------------|----------|---------|
| HTTP client | OkHttp | 5.4.0 |
| CVEs | OSV.dev REST API | — |
| Resolución de artefactos | Eclipse Aether | via maven-core |
| Compatibilidad binaria | japicmp | 0.26.2 |
| Reporte | HTML generado con template Java | — |
| Tests | maven-plugin-testing-harness + JUnit 5 | — |

---

## Cadena de ejecución esperada

```
developer$ mvn dependency-inspector:analyze
  → resuelve dependencias del proyecto (Aether)
  → por cada dependencia: consulta OSV.dev (batch API)
  → genera reporte HTML en target/dependency-inspector/report.html
  → imprime resumen en consola (N vulnerabilidades encontradas)
  → NO falla el build

developer$ mvn dependency-inspector:upgrade
  → lee resultado previo del analyze (o ejecuta analyze primero)
  → para cada dep con CVE y upgrade disponible:
      si patch o minor → modifica pom.xml
      si major → imprime recomendación
  → guarda backup pom.xml.bak
  → imprime resumen de cambios aplicados
```

---

## Verificación final de completitud

| Dimensión | Score | Estado |
|-----------|-------|--------|
| Objetivo | 90 | ✓ Completo |
| Criterio de aceptación | 80 | ✓ Completo |
| Alcance | 85 | ✓ Completo |
| Contexto técnico | 80 | ✓ Completo |
| Casos límite | 75 | ✓ Completo |
| **Total** | **82** | **CLARO — listo para implementar** |
