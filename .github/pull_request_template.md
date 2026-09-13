## Descripción

<!-- Explica QUÉ cambia y POR QUÉ. No repitas el título. -->

## Tipo de cambio

<!-- Marca con [x] lo que aplique -->

- [ ] `feat` — Nueva funcionalidad
- [ ] `fix` — Corrección de bug
- [ ] `refactor` — Refactoring sin cambio funcional
- [ ] `test` — Tests nuevos o modificados
- [ ] `docs` — Solo documentación
- [ ] `chore` — Dependencias, CI, configuración
- [ ] `perf` — Mejora de rendimiento

## Issue relacionado

Closes # <!-- número de issue, o "N/A" -->

## Cómo probarlo

<!-- Pasos mínimos para verificar el cambio manualmente -->

```bash
mvn clean install
cd test-consumer
mvn io.github.Miguel-Sanchez241001:dependency-inspector-maven-plugin:1.0-SNAPSHOT:analyze
```

## Checklist obligatorio

- [ ] `mvn test` pasa con 0 fallos
- [ ] `mvn clean install` termina sin errores
- [ ] El código nuevo tiene al menos un test
- [ ] No hay `System.out.println` ni `e.printStackTrace()`
- [ ] No hay secretos ni tokens en el código
- [ ] Si hay BREAKING CHANGE: está documentado aquí y en `CHANGELOG.md`
- [ ] `CHANGELOG.md` actualizado bajo la sección `[Unreleased]`

## Capturas / evidencia (opcional)

<!-- Pega aquí la salida de consola relevante o el HTML generado si aplica -->
