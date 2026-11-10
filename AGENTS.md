# Domain Auditor

Herramienta web que audita un dominio o una IP desde el navegador: DNS, correo
(SPF, DKIM, DMARC, MTA-STS, DANE…), DNSSEC, CAA, superficie de ataque y registro.
No tiene servidor: consulta DNS sobre HTTPS (Cloudflare y Google), RDAP, RIPEstat
y crt.sh directamente desde el navegador. Proyecto de portfolio de Félix Llorente.
Este fichero lo lee cualquier chat abierto en esta carpeta. Responde siempre en
español. **No se versiona** (está en `.git/info/exclude`): el repositorio será
público y esto es de uso interno.

## Estado (2026-11-10)

- **Dos repositorios con el mismo contenido:**
  - `FelixLlorenteS/domain-auditor`: **público** (portfolio). Remoto `origin`.
  - `antr4xcyber/domain-auditor`: **privado**, el que se conecta a Cloudflare Pages
    para desplegar `audit.felixllorente.com`. Remoto `privado`.
- **Subir siempre a los dos** con `git subir main` (o `git subir <etiqueta>`): alias
  local de `.git/config` que cambia a `FelixLlorenteS`, sube a `origin`, vuelve a
  `antr4xcyber` y sube a `privado`. El ayudante de `gh` sólo usa la cuenta activa.
- **Historial reiniciado** el 2026-11-10 en un único commit (hoy `6cbbbf1`: se rehace con `--amend` y `git subir --force-with-lease`, etiqueta
  `v1.0.0`) para quitar un dominio de una persona particular del banco de pruebas.
  **Nunca** añadir dominios de particulares al corpus, a las pruebas ni a la
  documentación: sólo empresas, organismos o dominios de prueba públicos.
- El repositorio antiguo con el historial anterior quedó como
  `FelixLlorenteS/domain-auditor-antiguo` (privado) hasta que Félix lo borre.
- Despliegue automático activo: Cloudflare Pages publica cada push a `main` de
  `antr4xcyber/domain-auditor` en `audit.felixllorente.com`, con `dist/_headers`.

## Cómo trabajar

1. **Primero auditar, después cambiar.** Ante una mejora grande: revisar lo que
   hay, proponer un plan y esperar el OK de Félix.
2. **Fiabilidad por encima de todo.** Un «protegido» falso es el peor fallo
   posible. Cada comprobación:
   - se basa en su RFC, citando la sección («sección 4.6.4», nunca con el signo
     de sección);
   - tiene pruebas unitarias;
   - se contrasta con dominios reales en el banco de validación.

   Si el auditor y una herramienta de referencia (internet.nl, dns.google
   consultado aparte) no coinciden, se averigua el porqué antes de seguir.
3. **Sólo datos reales.** Los resultados salen de consultas en vivo; nada se
   deduce del contexto. No se inventan buzones, proveedores ni valores. Los
   consejos de un proveedor sólo aparecen si se detecta por sus NS/MX.
4. **Validar siempre** antes de proponer un commit: `pnpm check` (lint, tipos,
   pruebas, compilación) y, si se toca la lógica, `pnpm validate` (banco en vivo;
   ver `docs/validacion.md`). Si el cambio afecta a SPF, DMARC, DKIM, DNSSEC o
   DANE, también `pnpm validate:nl` (comparación con internet.nl, ~30 min).
5. **Nada se sube sin OK explícito** de Félix: ni commits, ni push, ni cambios de
   visibilidad del repositorio, ni despliegues.
6. **Bilingüe**: todo texto nuevo, en `src/messages/es.ts` y `en.ts` a la vez.

## Git y GitHub

- Commits firmados como **«Félix Llorente Sotillo <felixllorentesotillo@outlook.es>»**
  (ya configurado en `.git/config`). **Nunca** con la identidad de `antr4xcyber`.
- Mensajes en español (`feat:`, `fix:`, `docs:`…) con la línea
  `Co-Authored-By` que indique el sistema.
- `gh` tiene dos cuentas. Para este repositorio:
  `gh auth switch -u FelixLlorenteS`, trabajar, y **volver a `antr4xcyber`** al
  terminar (es la activa por defecto y la dueña del repositorio de la web).
- Para probar en un `git worktree`, no usar `git config`: escribe en la
  configuración compartida. Usar `git -c user.name=… -c user.email=… commit`.

## Estructura

| Dónde | Qué |
| --- | --- |
| `src/core/` | Lógica de análisis, sin interfaz: `audit.ts` (orquesta), `doh.ts` (resolvedor con respaldo Cloudflare → Google), `spf.ts`, `dmarc.ts`, `dkim.ts`, `mail.ts`, `dnsextra.ts`, `ct.ts`, `rdap.ts`, `ip.ts`, `integrations.ts`, `summary.ts` (veredictos), `types.ts` (un resultado es `{ id, status, params }`, el texto va aparte) |
| `src/ui/` | Interfaz: controles, MITRE ATT&CK, datos en crudo, Markdown de «Copiar detalle» |
| `src/messages/` | Textos ES y EN de cada resultado |
| `src/wiki/`, `wiki/` | Wiki: una entrada por registro o comprobación, con enlaces oficiales |
| `tests/` | Pruebas unitarias (Vitest) |
| `validation/` | Banco de validación en vivo contra dns.google (`pnpm validate`); los informes van a `validation/out/`, que no se versiona |
| `docs/como-esta-hecho.md` | Documentación técnica completa |
| `docs/validacion.md` | Cómo funciona el banco de validación y su corpus |

Stack: TypeScript + Vite sin framework, Vitest, ESLint, pnpm 10.34.5, Node 22.

## Fuera de esta carpeta

- `~/Documentos/Proyectos/Web-felixllorente.com/gestion/domain-auditor-defensa.md`:
  guía personal de Félix para entender y defender el proyecto en una entrevista.
  Si cambia algo importante del diseño, actualizarla.
- `~/Documentos/Proyectos/Web-felixllorente.com/gestion/proyectos-ideas.md`:
  historial del proyecto. Anotar ahí los hitos.
- **Ficha en la web de Félix**: está en la rama local `ficha-domain-auditor` de
  `~/Documentos/Proyectos/Web-felixllorente.com/WebFelix/` (commit `b6d5abc`,
  sobre una base antigua: rebasar sobre `web-felix` antes de usarla). Enlaza a
  `https://audit.felixllorente.com`. **No se publica** hasta que el auditor esté
  validado y el subdominio funcione. Publicar la web sigue las reglas del
  `AGENTS.md` de esa carpeta.

## App de escritorio (2026-11-10)

- Se queda tal cual, sin más desarrollo: **lo que interesa es la web.**
- Electron (`desktop/`), grupo «Web» sólo en escritorio (`src/core/web.ts`), `pnpm
  desktop`, `pnpm dist:linux`, `pnpm dist:win`, `pnpm e2e`. Instaladores de Windows
  con `.github/workflows/desktop.yml` al subir una etiqueta `v*`.
- Acceso directo instalado: `~/.local/opt/domain-auditor/Domain-Auditor.AppImage`.

## Mejoras propuestas (2026-11-10, antes de la app)

Hechas en `escritorio`: 1 (velocidad: fases y Cert Spotter), 2 (veredictos arriba),
5 (E2E). Quedan: 3 (resumen ejecutivo enlazado en pantalla), 4 (varios dominios),
6 (publicación) y 7 (VirusTotal/AbuseIPDB con clave del usuario, ahora posible en
la app de escritorio, que no tiene CORS).

## Pendiente conocido

- Cabeceras HTTP y TLS: hechas en la app de escritorio (rama `escritorio`); la web
  sigue sin poder verlas.
- Alojamiento decidido: Cloudflare Pages desde el repositorio privado.
