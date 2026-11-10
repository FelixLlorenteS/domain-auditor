# Domain Auditor para escritorio

La misma herramienta que la web, como aplicación para **Windows** y **Linux
(Fedora y otras)**. Además de todo lo que hace la web, se conecta a la web del
dominio, como lo haría un navegador, y comprueba lo que un navegador no deja leer:

| Control | Qué mira | Norma |
| --- | --- | --- |
| **HTTPS** | Que `http://` lleve a `https://` y que la web envíe HSTS (también el dominio sin `www`) | RFC 6797 |
| **Certificado y TLS** | Que el certificado sea de confianza, del nombre y no caduque pronto; que el servidor rechace TLS 1.0 y 1.1 | RFC 9525, RFC 8996 |
| **Cabeceras de seguridad** | Protección contra *clickjacking*, `nosniff`, CSP, `Referrer-Policy` y si el servidor anuncia su versión | RFC 7034, W3C CSP |
| **security.txt** | Que haya un contacto de seguridad vigente | RFC 9116 |
| **MTA-STS** | La política completa: modo `enforce` y todos los MX cubiertos (en la web sólo se ve que existe) | RFC 8461 |

Y el informe para el cliente se guarda **directamente en PDF** con «Guardar PDF».

## Instalar

### Fedora (recomendado: `.rpm`)

```bash
sudo dnf install ./domain-auditor-1.0.0.x86_64.rpm
```

Aparece como «Domain Auditor» en el menú de aplicaciones. Para desinstalar:
`sudo dnf remove domain-auditor`.

### Cualquier Linux (`.AppImage`, sin instalar)

```bash
chmod +x Domain-Auditor-1.0.0-x86_64.AppImage
./Domain-Auditor-1.0.0-x86_64.AppImage
```

### Windows (`.zip`, sin instalar)

1. Descomprime `Domain-Auditor-1.0.0-windows-x64.zip` en una carpeta (por ejemplo
   en Documentos).
2. Abre `Domain Auditor.exe`.
3. La primera vez Windows SmartScreen avisa de que la aplicación no está firmada
   («Windows protegió su PC»): pulsa **Más información → Ejecutar de todas
   formas**. Es normal en una aplicación sin certificado de firma de código.

El instalador clásico (`Domain-Auditor-Setup-1.0.0.exe`) y la versión portable
de un solo fichero se generan en GitHub Actions, en una máquina Windows
(`.github/workflows/desktop.yml`).

## Usar

1. Escribe un dominio (`empresa.com`), una dirección de correo o web, o una IP, y
   pulsa **Auditar**. Arriba aparece la insignia **ESCRITORIO**: las
   comprobaciones web están activas.
2. Lo primero son los **veredictos** (correo, DNS, web y registro) y la nota de
   los controles básicos. Debajo, **Qué arreglar primero**, ordenado por gravedad.
3. Cada control se despliega con la evidencia, el riesgo y el arreglo exacto.
   **Volver a comprobar** repite la auditoría tras un cambio.
4. **Guardar PDF** genera el informe para el cliente (resumen ejecutivo, estado
   de cada control, plan de acción y anexo) y lo abre.
5. **Ver datos en crudo** enseña cada petición con su respuesta original,
   incluidas las conexiones a la web (cabeceras y apretones de manos TLS).

## Privacidad y seguridad

- No hay servidor intermedio: las consultas van directamente a los servicios
  públicos (DNS sobre HTTPS de Cloudflare y Google, RDAP, RIPEstat, Certificate
  Transparency, Shodan InternetDB, AlienVault OTX), como en la web.
- La app **visita la web del dominio** (HTTP, HTTPS y TLS): ese servidor ve tu
  IP, igual que si la abrieras en un navegador. No se prueba ninguna
  vulnerabilidad.
- **Nunca se conecta a direcciones privadas** (192.168.x.x, 10.x.x.x,
  localhost…): un dominio que apunte a tu red local no puede usarse para
  escanearla.
- La página no tiene acceso al sistema: aislamiento de contexto y *sandbox* de
  Chromium activados, sin Node.js en la página, sin navegación fuera de la app
  (los enlaces externos se abren en tu navegador) y argumentos validados en el
  proceso principal.
- El último informe de cada dominio se guarda sólo en este equipo, para comparar.

## Para desarrollar

```bash
pnpm desktop      # compila la web y abre la app (desktop/main.mjs)
pnpm dist:linux   # AppImage, .rpm y .tar.gz en release/ (el .rpm necesita rpmbuild)
pnpm dist:win     # .zip para Windows en release/
```

- `desktop/main.mjs`: ventana, esquema propio `app://` que sirve `dist/`, PDF y
  manejadores IPC.
- `desktop/preload.cjs`: el único puente con la página (`window.desktop`).
- `desktop/probe.mjs`: las conexiones (HTTP sin seguir redirecciones, TLS con
  una versión concreta), con DNS sobre HTTPS y bloqueo de direcciones privadas.
- `src/core/web.ts`: la lógica de cada comprobación, sin red, probada en
  `tests/web.test.ts` con una sonda falsa.
