# Cómo está hecho Domain Auditor

Documento técnico: qué hace cada parte, por qué está hecha así y qué norma sigue.
Está pensado para leerse de arriba abajo la primera vez y para consultarse
después por secciones.

- [1. La idea en una frase](#1-la-idea-en-una-frase)
- [2. La decisión que lo condiciona todo: sin servidor](#2-la-decisión-que-lo-condiciona-todo-sin-servidor)
- [3. Mapa del proyecto](#3-mapa-del-proyecto)
- [4. El viaje de una auditoría](#4-el-viaje-de-una-auditoría)
- [5. El núcleo, fichero a fichero](#5-el-núcleo-fichero-a-fichero)
- [6. Textos e idiomas](#6-textos-e-idiomas)
- [7. La interfaz](#7-la-interfaz)
- [8. Seguridad de la propia web](#8-seguridad-de-la-propia-web)
- [9. Pruebas](#9-pruebas)
- [10. Compilación, CI y despliegue](#10-compilación-ci-y-despliegue)
- [11. Límites conocidos](#11-límites-conocidos)
- [12. Decisiones de diseño y alternativas descartadas](#12-decisiones-de-diseño-y-alternativas-descartadas)

---

## 1. La idea en una frase

Una página web que, dado un dominio o una IP, hace en vivo las mismas consultas
que haría un administrador de sistemas (DNS, registro, red) y convierte las
respuestas en un informe que se entiende sin saber DNS, con el arreglo exacto de
cada fallo y los datos originales para comprobarlo.

Qué **no** hace: no escanea puertos, no se conecta a los servidores del dominio,
no lee cabeceras HTTP ni certificados TLS y no guarda nada.

## 2. La decisión que lo condiciona todo: sin servidor

La herramienta es una web estática: HTML, CSS y JavaScript que se ejecutan en el
navegador de quien la usa. No hay backend.

**Por qué:**

- **Privacidad verificable.** Si no hay servidor propio, no hay dónde guardar qué
  dominios consulta cada persona.
- **Coste y mantenimiento cero.** Se sirve como ficheros estáticos.
- **Nada que atacar.** Sin servidor no hay proxy abierto ni SSRF posible.

**La consecuencia:** un navegador sólo puede leer respuestas de servicios que lo
permitan expresamente mediante CORS (`Access-Control-Allow-Origin`). Eso decide
qué se puede comprobar:

| Se puede (el servicio envía CORS) | No se puede |
| --- | --- |
| DNS por DoH de Cloudflare y Google | Consultas DNS normales (UDP/TCP 53): el navegador no tiene acceso |
| RDAP (índice de IANA, registros de TLD, RIR, registradores; rdap.org de respaldo) | Cabeceras HTTP de otras webs |
| RIPEstat (BGP) | Certificados TLS y versiones de protocolo |
| Certificate Transparency (crt.sh, Cert Spotter) | VirusTotal y AbuseIPDB (no envían CORS: quedan para la CLI) |
| Shodan InternetDB, AlienVault OTX | |
| | Contenido de la política MTA-STS (fichero HTTPS sin CORS) |

Todas las fuentes se comprobaron con peticiones reales antes de usarlas.

## 3. Mapa del proyecto

```
index.html            página de auditoría (sólo carga src/main.ts)
wiki/index.html       página de la wiki (carga src/wiki/main.ts)
public/               ficheros que se copian tal cual (favicon, CNAME)
vite.config.ts        compilación, CSP y configuración de las pruebas
src/
  core/               LÓGICA: no toca el DOM; se prueba en Node
    types.ts          modelo de datos: Finding, Section, Report, Identity…
    input.ts          interpreta lo que escribe el usuario
    ip.ts             utilidades de IP: validación, IPv6, zona inversa, rangos especiales
    doh.ts            cliente DNS sobre HTTPS con caché y respaldo
    raw.ts            registro de cada petición con su respuesta original
    spf.ts            análisis de SPF y recuento de consultas
    dmarc.ts          análisis de DMARC y búsqueda por el árbol DNS
    dkim.ts           búsqueda de claves DKIM y tamaño real de la clave
    mail.ts           MX, proveedor de correo, MTA-STS, TLS-RPT, BIMI
    rdap.ts           datos de registro (RDAP) y AS (RIPEstat)
    ct.ts             superficie de ataque: subdominios (crt.sh), CNAME colgantes y emisores frente al CAA
    web.ts            HTTPS, TLS, cabeceras, security.txt y política MTA-STS (sólo escritorio)
    intel.ts          exposición y reputación: Shodan InternetDB y AlienVault OTX
    providers.ts      proveedor DNS a partir de los NS
    audit.ts          orquesta todo y construye el informe
    summary.ts        veredictos por área («Bien / Mejorable / Riesgo»)
  messages/           TEXTOS de cada resultado, en es.ts y en.ts
  i18n.ts             textos de la interfaz y rellenado de mensajes
  main.ts             INTERFAZ de la página de auditoría
  desktop.ts          detecta la app de escritorio (window.desktop)
  ui/                 piezas de interfaz: cabecera, buscador, datos en crudo, «lo que hay / lo que debería»
  wiki/               contenido y página de la wiki
  style.css           estilos (paleta y escala de felixllorente.com)
desktop/              APP DE ESCRITORIO (Electron): ventana, puente y sonda de red
build/                iconos de los paquetes
tests/                pruebas con Vitest
.github/workflows/    CI: lint, tipos, pruebas, compilación y despliegue; paquetes de escritorio
```

La separación importante es **`core/` frente a todo lo demás**: `core/` recibe
un objetivo, hace consultas y devuelve datos. No sabe nada de HTML ni de
idiomas. Por eso se puede probar sin navegador y con un DNS falso.

## 4. El viaje de una auditoría

```
"https://www.Ejemplo.com/x"
        │ parseTarget()                       core/input.ts
        ▼
{ kind: "domain", name: "www.ejemplo.com" }
        │ audit()                             core/audit.ts
        ├─ 8 consultas DNS en paralelo: SOA NS A AAAA MX TXT CAA DS
        ├─ ¿NXDOMAIN o SERVFAIL? → informe de un solo resultado y fin
        ├─ Correo: MX + SPF + DMARC + DKIM (+ MTA-STS/TLS-RPT/BIMI si hay MX)
        ├─ DNS: NS, direcciones, CAA, DNSSEC, red del alojamiento
        ├─ Registro: RDAP del registro y, si hace falta, del registrador
        └─ Contraste: NS MX TXT CAA DS DMARC preguntados al otro resolvedor
        ▼
Report { identity, sections[{ findings, records }], resolverCheck }
        │ renderReport()                      main.ts
        ▼
Quién es → veredictos → «Qué arreglar primero» → secciones
```

Cada comprobación produce un **Finding**: un identificador, un estado y unos
parámetros. Por ejemplo:

```ts
{ id: "dmarc.p-none", status: "warn", suggest: [{ type: "TXT", name: "_dmarc.ejemplo.com", value: "v=DMARC1; p=quarantine; …" }] }
```

El núcleo **no escribe textos**. El texto de `dmarc.p-none` está en
`messages/es.ts` y `messages/en.ts`. Así la lógica se prueba comparando
identificadores, y los textos se pueden mejorar sin tocar la lógica.

## 5. El núcleo, fichero a fichero

### `input.ts`: qué ha escrito el usuario

`parseTarget()` acepta un dominio, una URL, un correo o una IP y devuelve un
objetivo limpio:

- De un correo se queda con lo que va detrás de la `@`.
- De una URL se queda con el nombre de host, usando el parser `URL` del propio
  navegador. Así los dominios internacionales pasan a punycode (`mañana.es` →
  `xn--maana-pta.es`).
- Valida cada etiqueta del nombre (1 a 63 caracteres, sin guion al principio ni
  al final, 253 como máximo en total).

### `ip.ts`: direcciones

- `reverseName()` construye el nombre de la zona inversa: `10.2.0.192.in-addr.arpa`
  para `192.0.2.10`; en IPv6, las 32 cifras hexadecimales al revés en `ip6.arpa`
  (RFC 1035, sección 3.5; RFC 3596, sección 2.5).
- `specialRange()` detecta rangos que no se enrutan en Internet (privados,
  CGNAT, documentación, ULA…). Con ellos no tiene sentido consultar nada más.

### `doh.ts`: DNS desde el navegador

Usa la **API JSON de DNS sobre HTTPS** de Cloudflare
(`cloudflare-dns.com/dns-query`) y de Google (`dns.google/resolve`). No es el
formato binario del RFC 8484, sino la variante JSON que ofrecen los dos
proveedores. Es más sencilla de leer y ambos la sirven con CORS.

- **Respaldo:** pregunta primero a Cloudflare y, si falla (error de red, HTTP no
  200 o SERVFAIL), a Google.
- **Fallar no es «no existe»:** una respuesta SERVFAIL (u otro error que no sea
  NOERROR ni NXDOMAIN) significa que no se sabe qué publica la zona.
  `lookupFailed()` la distingue, y MX, SPF (con sus `include`), DMARC y CAA la
  tratan como «no se pudo consultar» (`*.lookup-error`, «Sin verificar»), nunca
  como un registro ausente: si no, un fallo pasajero acabaría en consejos como
  publicar un null MX o quitar un `include` del SPF. DKIM, MTA-STS, TLS-RPT,
  BIMI y DS aún no lo distinguen; allí un fallo sólo puede dar un «no
  encontrado» informativo.
- **Caché:** una misma pregunta (nombre y tipo) se hace una sola vez por
  auditoría, aunque la necesiten varias comprobaciones.
- **Normalización:** los dos proveedores devuelven los TXT de forma distinta.
  Cloudflare los da entre comillas y partidos en trozos de 255 caracteres;
  Google, ya unidos. `decodeTxt()` los deja iguales, y también quita el punto
  final de los nombres y pasa a minúsculas los DS. Sin esto, el contraste entre
  resolvedores daría diferencias falsas.
- **DNSSEC:** los dos resolvedores validan DNSSEC y marcan las respuestas
  validadas con el bit `AD`. La herramienta lee ese bit; no valida las firmas
  por su cuenta.

### `raw.ts`: la prueba de que todo es real

`loggedFetch()` envuelve cada petición HTTP y guarda la URL, el código, el
tiempo y **el cuerpo tal cual llegó**, antes de interpretarlo. Es lo que muestra
la pestaña «Datos en crudo», con el comando `curl` equivalente para repetir la
consulta desde una terminal.

### `spf.ts`: SPF (RFC 7208)

1. `parseSpf()` separa el registro en mecanismos (`ip4`, `include`, `mx`…) con su
   calificador (`+ - ~ ?`) y comprueba la sintaxis completa: el valor de cada
   mecanismo (una IP y una máscara válidas en `ip4`/`ip6`, `all` sin argumento,
   secciones 5.1 a 5.7), los dominios y macros (`isDomainSpec()`, sección 7.1) y
   que `redirect` y `exp` aparezcan como mucho una vez (sección 6). Un error en
   cualquier parte hace que el SPF entero sea un `permerror` (sección 4.6).
2. `countLookups()` recorre `include` y `redirect` de forma recursiva y aplica
   los tres límites de la sección 4.6.4:
   - como mucho **10 términos que hacen consultas** DNS (`include`, `a`, `mx`,
     `ptr`, `exists` y `redirect`); por encima, error permanente;
   - como mucho **10 registros MX por cada mecanismo `mx`**;
   - como mucho **2 «consultas vacías»**, es decir, nombres que responden
     NXDOMAIN o sin registros. Las macros (`%{i}`) dependen del remitente y no se
     pueden resolver por adelantado, así que no se cuentan.

   Detecta además bucles y `include` que apuntan a dominios sin SPF. Un
   `include` cuyo dominio no responde (SERVFAIL) no es «sin SPF»: para el
   receptor es `temperror` (sección 2.6.6), así que se informa sin proponer
   quitarlo y sin dar el recuento por bueno. Pasadas 20 consultas deja de seguir
   `include`: el resultado ya es un error y un registro hostil no puede lanzar
   cientos de consultas desde el navegador de quien audita.
3. Las sugerencias reescriben el registro real: `mergeSpf()` une varios SPF en
   uno sin duplicados (un `redirect=` pasa a `include:`, porque junto a un `all`
   se ignoraría, sección 6.1), y `withSoftfail()` sustituye un `+all` o `?all`
   por `~all`.
   Si falta el SPF y se reconoce el proveedor de correo por sus MX, propone su
   `include` (los valores se comprobaron en el DNS de cada proveedor).

### `dmarc.ts`: DMARC (RFC 9989)

En mayo de 2026 el **RFC 9989 sustituyó al RFC 7489**. La herramienta sigue la
norma nueva:

- **Búsqueda por el árbol DNS (sección 4.10):** si `a.mail.ejemplo.com` no tiene
  DMARC, se prueba `mail.ejemplo.com`, `ejemplo.com` y `com`. Los nombres de más
  de 8 etiquetas se acortan primero a 7. Sustituye a la antigua Public Suffix
  List (`treeWalkTargets()`).
- **Versión estricta (secciones 4.7 y 4.8):** el registro empieza por `v` y su
  valor es exactamente `DMARC1`, en mayúsculas. Uno que empiece por `v=dmarc1`
  lo ignoran los receptores: se avisa como fallo (`dmarc.bad-version`) y se
  propone escrito bien, y la búsqueda sigue hacia arriba como haría un receptor.
- **Política aplicable:** un subdominio que hereda el registro usa `sp` si
  existe; si no, `p`. Sin `p`, el registro vale como `p=none`. Con un `p`, `sp` o
  `np` no válido, el receptor actúa como si dijera `p=none` (o no aplica DMARC),
  aunque `p` diga `reject` (sección 4.10.1): nunca se informa de la política
  escrita en ese caso.
- **Errores de DNS:** un SERVFAIL en `_dmarc` detiene la búsqueda y el resultado
  es «sin verificar»: un error temporal no equivale a «sin registro» (sección
  4.10.1).
- **Etiquetas eliminadas:** `pct`, `rf` y `ri` ya no existen; se avisa y se
  propone el registro sin ellas. El despliegue gradual se hace ahora con `t=y`.
- `editDmarc()` reescribe el registro cambiando sólo lo necesario y mantiene `v`
  primero y `p` segundo. El buzón de informes nunca se inventa: se deja un hueco
  `{mailbox}` que rellena el usuario.
- **Informes a otro dominio (RFC 9990, sección 4):** si `rua` apunta a otra
  organización, el receptor sólo envía los informes si esta publica
  `<dominio>._report._dmarc.<host>` con `v=DMARC1`. Se comprueba y se avisa si
  falta (bbva.es → bbva.com, o un buzón de Gmail). Sin lista de sufijos públicos,
  «misma organización» se aproxima: un nombre dentro del otro, o un padre común
  que no parezca un sufijo (`co.uk`, `com.es`…); ante la duda se comprueba en DNS.
  Si esa consulta falla no se avisa: no se afirma nada sobre una suposición.

### `dkim.ts`: DKIM (RFC 6376)

- **Los selectores no se pueden listar por DNS**, así que se prueban los 37 más
  habituales (`google`, `selector1`, `k1`, `s1`, `hs1`…). No encontrar ninguno no
  significa que no haya DKIM, y el informe lo dice. Además, se puede **escribir
  un selector concreto** (el `s=` de una cabecera `DKIM-Signature`): se añade a
  la búsqueda y se guarda en la dirección (`&sel=`). `cleanSelector()` sólo acepta
  caracteres válidos en un nombre DNS.
- **Tamaño real de la clave:** `rsaKeyBits()` decodifica la clave pública (base64
  → DER) y lee la longitud del módulo RSA, tanto en formato SubjectPublicKeyInfo
  como en RSAPublicKey. Menos de 1024 bits es un fallo; 1024 es un aviso, porque
  el RFC 8301 recomienda 2048.
- **Claves delegadas:** si el selector es un CNAME hacia otro servicio (por
  ejemplo, Mailchimp o SendGrid), la clave la gestiona ese servicio. El informe
  lo dice y cambia el consejo: no «genera una clave nueva», sino «si ya no usas
  el servicio, borra el alias».
- **Sin selector conocido (RFC 8020, sección 2):** si ninguno de los selectores
  responde, se pregunta por `_domainkey.<dominio>`. NXDOMAIN significa que no hay
  nada debajo: el dominio no publica ninguna clave (aviso). NOERROR significa que
  hay claves con un selector que no está en la lista («sin verificar», pide
  escribirlo). Un registro comodín lo haría siempre NOERROR, así que se compara
  con un nombre inventado y, si también existe, no se concluye nada.
- **Claves que no validan:** un tipo `k=` desconocido se ignora (RFC 6376,
  sección 3.6.1) y una clave limitada a `h=sha1` no puede validar firmas, porque
  rsa-sha1 ya no se acepta (RFC 8301, sección 3.1).

### `mail.ts`: MX y extras del correo

- **Proveedor de correo** por los nombres de los MX, con su `include` SPF. Sólo
  nombres que son del proveedor: `inbound-smtp.<región>.amazonaws.com` es Amazon
  SES, pero cualquier servidor EC2 también acaba en `amazonaws.com`. El MX con
  DNSSEC de Microsoft 365 (`*.mx.microsoft`) se reconoce, y si no se ha podido
  comprobar qué `include` corresponde (IONOS fuera de España y Alemania) se
  nombra el proveedor sin proponer ninguno.
- **Null MX** (`MX 0 .`, RFC 7505): la forma correcta de decir «este dominio no
  usa correo». Sólo se propone junto a `v=spf1 -all` y DMARC `reject` si el
  dominio tampoco envía correo, para no romper un envío que sí exista. Mezclado
  con otros MX es un fallo (sección 3).
- **Destinos de los MX (`checkMxHosts()`):** cada MX (hasta 10) debe resolver a
  direcciones (RFC 5321, sección 5.1) y no ser un alias (RFC 2181, sección
  10.3). Uno que no resuelve pierde el correo que le llega (fallo); un alias es un
  aviso. Si la consulta falla no se dice nada.
- **MTA-STS (RFC 8461):** además del TXT, comprueba que exista el servidor
  `mta-sts.<dominio>`. Sin él, el TXT no tiene efecto. Si hay que crearlo, genera
  el fichero de política con los MX reales y saltos de línea CRLF. Con el
  servidor presente el resultado es «sin verificar», nunca «bien»: la política no
  se puede leer desde el navegador, en modo `testing` no protege (sección 5) y con
  un comodín cualquier nombre resuelve. En la validación se encontraron
  fastmail.com y yahoo.com en `testing`.
- **TLS-RPT (RFC 8460)** y **BIMI:** presencia y campos obligatorios. Si hay más
  de un TLS-RPT que empiece por `v=TLSRPTv1;`, los remitentes los ignoran todos
  (sección 3) y se avisa.

### `rdap.ts`: registro y red

- **RDAP** es el sustituto estructurado (JSON) de WHOIS (RFC 9082, 9083).
  Se pregunta directamente al servidor que corresponde (Verisign para .com, ARIN o
  RIPE para IP…), localizado con los índices de IANA (`dns.json`, `ipv4.json`,
  `ipv6.json`; RFC 9224): coincidencia por etiquetas más larga para dominios
  (sección 4) y prefijo más largo para direcciones (sección 5). Un TLD que no está
  en el índice no tiene RDAP (.es, .de…) y no se pregunta a nadie. rdap.org, un
  redirector voluntario con un límite de peticiones estricto (en la validación
  respondió 429 en cuanto hubo varias auditorías), sólo se usa si el índice de
  IANA no responde. Todos estos servidores envían CORS (comprobado con
  peticiones reales en septiembre de 2026).
- **Titular del dominio:** los registros «delgados» como .com no lo publican; lo
  publica el registrador. Por eso se sigue el enlace `related` al RDAP del
  registrador. **Sólo se lee la organización**, nunca direcciones ni contactos, y
  si viene tapada (RGPD) se muestra «oculto por privacidad».
- **Estados del registro (`lockFindings()` en `audit.ts`):** se leen en su forma
  EPP (`clientTransferProhibited`, RFC 5731, sección 2.3) y RDAP (`client
  transfer prohibited`, RFC 8056, sección 2), incluidas las genéricas
  `transfer prohibited` y `locked` (RFC 9083, sección 10.2.2). Hay bloqueo de
  transferencia con cualquier estado que la impida; *registry lock* sólo con los
  tres `server*Prohibited` a la vez o con `locked` (el de SIDN en .nl). Un
  dominio en `redemption period`, `pending delete` o `client/server hold` es un
  fallo.
- **AS de una IP:** RIPEstat (`prefix-overview`) dice qué red anuncia la IP en
  BGP. Puede no coincidir con el titular del bloque: 1.1.1.1 es un bloque de APNIC
  que anuncia Cloudflare, y el informe muestra las dos cosas.

### `intel.ts`: exposición y reputación

- **Shodan InternetDB** (sin clave, con CORS): puertos abiertos, etiquetas y CVE
  que Shodan registró en su último escaneo de las dos primeras IP del dominio, o
  de la IP auditada. Las CVE las deduce de las versiones anunciadas: se dicen
  como dato de Shodan, nunca como fallo. Si la IP es de un CDN conocido (se
  comprueba su AS en RIPEstat, una por una), el resultado dice que los puertos
  son de la infraestructura compartida del CDN: rtve.es, en Fastly, aparecía con
  405 CVE que no son suyas.
- **AlienVault OTX** (sin clave, con CORS): número de «pulsos» de la comunidad
  que mencionan el dominio (o la IP), los tres más recientes y las listas blancas
  de OTX. Es contenido sin verificar y ruidoso (example.com aparece en 50
  pulsos), así que nunca es un aviso.
- Todo va al control informativo «Exposición y reputación» (no puntúa) con la
  técnica ATT&CK T1596.005 (Scan Databases, Reconnaissance). Si una fuente no
  responde, se dice (`intel.unavailable`) en lugar de leerlo como «nada».
- VirusTotal y AbuseIPDB no envían CORS ni se pueden usar sin clave desde una web
  pública: quedan para la CLI, con la clave de cada usuario.

- **Ubicación (`lookupGeo()` en `rdap.ts`):** país de la primera IP de la web, o
  de la IP auditada, según la geolocalización de RIPEstat (MaxMind GeoLite). Si
  la IP sirve desde varios países (anycast, CDN) se dice así, en lugar de un
  país único engañoso. No es el país del registro del bloque, que da RDAP.
- **Otras herramientas (`ui/external.ts`):** enlaces a VirusTotal, los tests de
  web y correo de internet.nl, SSL Labs, DNSViz, MXToolbox, AlienVault OTX,
  AbuseIPDB y Shodan para el mismo dominio o IP. No se consulta nada: cada
  servicio sólo recibe el dominio si se pulsa el enlace. Cubren lo que el
  navegador no puede leer (VirusTotal y AbuseIPDB no envían CORS; SSL Labs
  prueba TLS). AbuseIPDB no se ofrece para una IP de CDN: sus denuncias serían
  del proveedor.

### `web.ts`: la web del dominio (sólo en la app de escritorio)

Un navegador no deja leer las cabeceras de otra web, su apretón de manos TLS ni
un fichero servido sin CORS. La app de escritorio sí: aporta una **sonda**
(`WebProbe`, con dos funciones: una petición GET sin seguir redirecciones y un
apretón de manos TLS ofreciendo, si se pide, una sola versión). `web.ts` tiene la
lógica, sin red, y se prueba con una sonda falsa; la web no tiene sonda y estas
comprobaciones simplemente no se ejecutan.

- **HTTPS (RFC 6797):** `http://` debe redirigir a `https://` (sección 7.2) y la
  primera respuesta HTTPS del host debe traer HSTS con `max-age` de al menos un
  año (el mínimo de la lista de precarga). Sólo cuenta la primera cabecera
  (sección 8.1). Si el dominio sin `www` redirige a `www` y sólo `www` envía HSTS,
  se avisa aparte: quien escribe el dominio sin `www` queda sin protección.
- **Certificado y TLS:** cadena de confianza y nombre (RFC 9525), días hasta la
  caducidad (aviso por debajo de 14) y si el servidor acepta TLS 1.0 o 1.1
  (RFC 8996, secciones 4 y 5). Cada versión antigua se ofrece sola; sólo una
  alerta del servidor o un cierre de conexión cuentan como rechazo
  (`REFUSED`). Un tiempo agotado o un error de la propia biblioteca TLS dejan el
  resultado **sin verificar**, nunca «bien»: la OpenSSL del sistema en Fedora,
  por ejemplo, se niega a firmas SHA-1 en TLS 1.0 y daría un falso «rechaza TLS
  1.0». Por eso la app usa la biblioteca de Electron (BoringSSL), que sí ofrece
  esas versiones; se comprobó contra `tls-v1-0.badssl.com:1010` (acepta) y
  contra OpenSSL sin la política del sistema.
- **Cabeceras de la página de inicio:** protección contra *clickjacking*
  (`frame-ancestors` o `X-Frame-Options`), `nosniff`, CSP (su ausencia es
  información: mal puesta rompe la web) y `'unsafe-inline'`, `Referrer-Policy`
  con `unsafe-url` y versiones en `Server` o `X-Powered-By`. Si la respuesta es
  un reto antibots (401, 403, 429, 503 o la cabecera `cf-mitigated`), sus
  cabeceras no son las de la web: el control queda sin verificar.
- **security.txt (RFC 9116):** en `/.well-known/`, por HTTPS y como
  `text/plain` (una página HTML que responde a todo no cuenta), con `Contact`
  (sección 2.5.3) y un único `Expires` futuro (sección 2.5.5). Es opcional.
- **Política MTA-STS (RFC 8461):** la auditoría sustituye `mta-sts.unverified`
  por el resultado real: se pide la política sin seguir redirecciones y con
  certificado válido (sección 3.3), se valida su formato (sección 3.2) y se
  comprueba que cada MX encaje en algún patrón (`*.` cubre una sola etiqueta,
  sección 4.1). Sólo `mode: enforce` cubriendo todos los MX es «bien».
- Todo va al grupo «Web · HTTPS y cabeceras», con su veredicto. No entra en los
  8 controles básicos, para que la nota sea comparable entre la web y la app.
- Cada conexión queda en los datos en crudo (fuente «Web»), con sus cabeceras.

### `audit.ts`: el director de orquesta

- Lanza en paralelo todo lo que no depende de otra cosa.
- **CAA (RFC 8659):** si el nombre no tiene CAA, sube por el árbol hasta
  encontrarlo, porque los subdominios lo heredan. Agrupa `issue`, `issuewild` e
  `iodef` sin duplicados (`summarizeCaa()`).
- **DNSSEC:** bien si la respuesta viene validada (`AD`); fallo si hay DS pero no
  valida; aviso si no hay DS. Con el contraste, se exige además que **el segundo
  resolvedor también valide**: si los dos lo hacen, el resultado lo dice; si sólo
  uno, se avisa del desacuerdo (rotación de claves, DS desactualizado…).
- **DNSSEC roto frente a DNS caído:** un SERVFAIL en el SOA para la auditoría. Si
  el resolvedor adjunta un Extended DNS Error de DNSSEC (RFC 8914, secciones 4.2
  a 4.13; Cloudflare y Google lo dan en su JSON) o la misma consulta responde con
  la validación desactivada (`cd=1`), es `dns.dnssec-broken` y se dice cómo
  arreglar el DS; si no, `dns.servfail`. En los dos se muestra el código EDE.
- **Nombre que es un alias:** si el nombre auditado es un CNAME, todo lo que
  devuelven las consultas es del destino y en el alias no se puede publicar nada
  más (RFC 1034, sección 3.6.2; RFC 2181, sección 10.1). Se dice
  (`dns.alias`) y se quitan las sugerencias de registros en ese nombre.
- **CAA en Cloudflare sin datos de CT:** no se propone ningún valor. Cloudflare
  añade sus propias autoridades, pero no las de subdominios sin proxy servidos
  desde otro sitio (AWS, Google…), y el CAA se hereda: un valor a ciegas podría
  bloquear sus renovaciones.
- **Contraste entre resolvedores (`crossCheck()`):** repite NS, MX, TXT, CAA, DS y
  DMARC en el otro resolvedor y compara. **No** compara A/AAAA, porque las CDN
  responden distinto según la ubicación, ni el SOA, cuyo número de serie depende
  de la antigüedad de cada caché. Compararlos daría falsas alarmas. De los TXT del
  dominio sólo se compara el SPF: los de verificación o los que cambian solos
  (gov.uk publica un `#Timestamp`) daban avisos sin consecuencia alguna.
- **Identidad («Quién es»):** reúne lo que las comprobaciones ya han encontrado
  (PTR, titular, AS, registrador, proveedores). No hay listas fijas de «quién es
  quién».

### `summary.ts`: veredictos

Traduce los resultados en tres o cuatro frases por área. Por ejemplo, la
suplantación de correo es «Riesgo» si falta DMARC, si el SPF acepta a cualquiera
o si DMARC sólo observa; «Mejorable» si hay huecos, como un SPF roto que DKIM
compensa; y «Bien» si DMARC rechaza y SPF o DKIM funcionan.

### `providers.ts`: proveedor DNS

Reconoce el proveedor por los nombres de los NS (Cloudflare, Route 53, Azure,
OVH, IONOS…). **Sólo incluye patrones comprobados contra NS reales**, y ante un
nombre ambiguo prefiere no decir nada. Por ejemplo, `ns1.google.com` es la
infraestructura propia de Google, no su producto Cloud DNS. Si no reconoce el
proveedor, el informe muestra los nombres tal cual.

## 6. Textos e idiomas

- **Dos niveles por resultado:** título, «qué significa» y pasos, en lenguaje
  llano; y «detalle técnico», con la norma y la sección exacta. Una prueba impide
  que un resultado se quede sin detalle técnico.
- **Neutrales:** los textos hablan de «el dominio», no de «tu dominio», porque la
  herramienta sirve para dominios propios, de clientes o de terceros.
- **«Depende del contexto»:** en los resultados cuyo acierto depende de cosas que
  una revisión externa no ve (otros servicios que envían correo, una migración en
  curso, una decisión deliberada), se añade un bloque que lo explica. El informe
  lleva también una nota general: los datos son reales, pero hay que interpretarlos.
- **Paso «entra en el panel»:** se rellena con el proveedor DNS detectado
  («Entra en el panel de DNS de Cloudflare…») o con un texto genérico.
- Español e inglés tienen exactamente las mismas claves, capas y número de pasos
  (lo comprueban las pruebas).

## 7. La interfaz

TypeScript sin framework: el HTML se genera con plantillas de texto y se inserta
en la página. Es una aplicación pequeña y no necesita React ni similares.

- **`ui/controls.ts`:** organiza el informe por **controles**, como lo revisaría
  un administrador: un control por tema (SPF, DKIM, DMARC, MX, MTA-STS, TLS-RPT,
  BIMI, servidores DNS, direcciones, coherencia, DNSSEC, CAA, caducidad,
  bloqueo…) agrupado por áreas («Correo · autenticación», «DNS · integridad»…).
  Cada resultado de la auditoría va a un control según su identificador
  (`controlIdOf`); lo que no encaja va a «Otros», así nada se pierde. El estado
  del control es el más grave de sus resultados, con una regla: si alguna parte
  no se pudo comprobar, sale «Sin verificar» en lugar de «Bien» (un control sólo
  está bien cuando todo se verificó). Si sólo tiene informativos y el control es
  opcional (MTA-STS, TLS-RPT, BIMI), sale como «Opcional». No se vuelve a evaluar
  nada: sólo se agrupa.
- **Puntuación (`scoreOf`):** para poder comparar dominios, cuenta siempre los
  mismos **8 controles básicos** (SPF, DKIM, DMARC, servidores DNS, DNSSEC, CAA,
  caducidad y bloqueo). Si uno no se puede verificar (selector DKIM desconocido,
  extensión sin RDAP) cuenta como no superado y se dice «sin verificar». Las
  mejoras opcionales (MTA-STS, TLS-RPT, DANE, BIMI) se cuentan aparte. Los
  subdominios y certificados no puntúan: salen de Certificate Transparency, que
  sólo muestra una parte y cuyos servicios públicos fallan a menudo (en la
  validación de septiembre de 2026, crt.sh falló en 4 de 10 auditorías seguidas),
  así que el mismo dominio puntuaría distinto de un minuto a otro.
- **`ui/attack.ts`:** la vista del atacante. Para cada control, qué puede hacer
  un atacante si falla o qué evita si está bien, con las técnicas de MITRE
  ATT&CK implicadas (ID, nombre y táctica comprobados en attack.mitre.org en
  septiembre de 2026; la antigua T1656 es ahora T1684.001, táctica Stealth). Se
  muestra el aviso de copyright que exigen sus términos de uso.
- **Superficie de ataque (`core/ct.ts`):** consulta crt.sh (Certificate
  Transparency, RFC 6962; permite CORS) y, si falla o no ha respondido a los 6
  segundos, también Cert Spotter (SSLMate), que envía CORS; gana la primera
  respuesta útil y el informe dice de cuál vino. Sin clave, Cert Spotter admite pocas consultas por
  hora y devuelve una página de 100 certificados en vigor: si llega llena, la
  lista se marca como parcial (`ct.partial`) y no se propone un CAA a partir de
  ella, porque podría faltar una autoridad. Saca los subdominios que aparecen en
  certificados públicos, resuelve como mucho 40 y busca los que tienen un CNAME
  cuya cadena termina en NXDOMAIN (CNAME colgante: posible subdomain takeover).
  Si no encuentra ninguno lo dice como dato, con cuántos comprobó de cuántos,
  nunca como «bien»: es un inventario parcial. Agrupa los certificados en vigor
  por emisor y, si hay CAA, avisa de los emitidos por autoridades que el CAA no
  permite (sólo para autoridades cuya lista completa de identificadores CAA está
  documentada; el resto se lista sin juzgar). Si crt.sh no responde, se dice y
  los dos controles quedan «sin verificar».
- **Integraciones y alojamiento (`core/integrations.ts`):** inventario de
  terceros a partir de lo que publica el dominio: los TXT de verificación (sólo
  se pone nombre al servicio si su formato está documentado; el resto se muestra
  tal cual) y los `include:` del SPF. Además se resuelve `www.` y se busca el AS
  de su dirección, porque la web suele estar en un CDN u hosting distinto. Son
  controles informativos: no suman ni restan, pero muestran la superficie
  (ATT&CK T1199 Trusted Relationship).
- **CAA por nombre:** el aviso de certificados fuera del CAA usa el conjunto CAA
  que aplica a cada nombre (RFC 8659, sección 3): el suyo (siguiendo su CNAME), el
  del padre más cercano o el del dominio, y nombra los nombres afectados. Para un
  certificado comodín cuenta `issuewild` si existe (sección 4.3), y `issue ";"`
  prohíbe a todas. Cada autoridad tiene su lista completa de identificadores
  equivalentes según su documentación (DigiCert acepta `geotrust.com`,
  `thawte.com`, `quovadisglobal.com`…; Sectigo, `usertrust.com` o
  `comodoca.com`): con una lista incompleta, posteo.de salía con una falsa alarma.
- **CAA que no limita:** un CAA sin `issue` (sólo `iodef`, `contactemail` o
  `issuewild`) no restringe la emisión de certificados normales (sección 3): es
  un aviso, no un control superado. Si la consulta CAA falla, se avisa de que las
  autoridades pueden negarse a emitir (sección 6.3) en lugar de proponer un CAA.
- **Contexto antes de recomendar:** `audit.ts` deduce si el dominio usa correo
  (`mailUsage`): *deshabilitado* con null MX o `v=spf1 -all`; *activo* con MX
  reales, un SPF que autoriza remitentes o una clave DKIM; *desconocido* si no hay
  nada de eso. Con correo deshabilitado, DKIM sale «No aplica» y el DMARC propuesto
  es `p=reject` directamente; con correo activo o desconocido, se empieza por
  `p=none` (un dominio sin MX ni SPF puede enviar igualmente). Un DMARC sin `rua`
  es una recomendación informativa: los informes no cambian cómo tratan los
  receptores el correo (RFC 9989, sección 4.7), así que no restan. Sin MX
  no se dice que el correo esté desactivado (RFC 5321 permite entregar al A/AAAA).
- **Estados, severidad y confianza:** además de Bien/Aviso/Fallo/Info, un control
  puede estar «No aplica» (no cuenta en la puntuación) o «Sin verificar» (DKIM
  con selector desconocido, crt.sh sin respuesta). La severidad (alta, media,
  baja) es aparte del estado y ordena el plan de acción: no pesa lo mismo un CAA
  que un DMARC. La confianza es media en lo que se deduce de datos parciales
  (DKIM, subdominios, certificados, alojamiento, integraciones).
- **CDN no es alojamiento:** si las direcciones son de Cloudflare, Fastly, Akamai
  o Imperva (ASN comprobados en RIPEstat), se dice que la web se sirve a través de
  ese proxy/CDN, no que esté alojada allí.
- **CAA propuesto desde CT:** si falta CAA, se proponen las autoridades que emiten
  hoy los certificados del dominio según Certificate Transparency, para no romper
  renovaciones. Si alguna no tiene identificador conocido, no se propone registro.
- **ATT&CK sólo con relación directa:** CAA, TLS-RPT, servidores DNS y coherencia
  conservan su texto de riesgo sin técnica, para no inflar la gravedad.
- **Endurecimiento DNS (`core/dnsextra.ts`):**
  - *Calidad de DNSSEC*: algoritmo del DS y tipo de resumen según las tablas del
    **RFC 9904** (noviembre de 2025, sustituye al RFC 8624). Un SHA-1 junto a un
    SHA-256 no se marca: sólo si es el único resumen.
  - *DNS comodín*: se consulta un nombre aleatorio (`da-check-…`); si resuelve,
    hay `*.dominio`.
  - *SOA*: se muestra como dato. Con proveedores anycast no hay secundarios
    clásicos y sus valores no afectan (Google usa 900/900/1800 a propósito).
  - *Diversidad de NS*: AS de cada servidor DNS; todos en una red es informativo.
  - *DANE* (RFC 7672): TLSA en `_25._tcp.<mx>` de todos los MX (hasta 10). Cuenta
    el bit AD de esa respuesta, porque lo que importa es el DNSSEC de la zona del
    MX. Si sólo algunos MX lo tienen es un aviso: un atacante puede forzar la
    entrega por los otros (sección 2.2.1). Y si el MX del propio dominio no está
    firmado se anota, porque DANE protege la conexión pero no la elección del
    servidor.
- **DMARC según el RFC 9989:** los textos hablan de «preferencia de tratamiento»
  del propietario: el receptor decide y, según la sección 5.4, no debería rechazar
  sólo por `p=reject`. Las etiquetas eliminadas (`pct`, `rf`, `ri`) se avisan.
- **Cada fuente con su estado:** la evidencia de subdominios sólo muestra lo que
  vino de crt.sh (marcado con `source: "ct"`); si crt.sh falla, lo dice, y la
  propuesta de CAA sólo se atribuye a CT cuando de verdad sale de ahí.
- **CNAME colgante ≠ toma de control:** sólo es `ct.takeover` (fallo, severidad
  alta) si el destino pertenece a un espacio de nombres que cualquiera puede
  volver a crear y cuya huella es NXDOMAIN: Elastic Beanstalk y los dominios de
  Azure de can-i-take-over-xyz, y lo que AWS describe en «Threat tactic
  spotlight: subdomain takeover». Con destinos de ID asignado (ELB, CloudFront…)
  es `ct.dangling`: CNAME huérfano, aviso de severidad baja, sin afirmar que se
  pueda explotar. Nunca se intenta reclamar nada.
- **Direcciones privadas en DNS público:** subdominios que resuelven a RFC 1918,
  CGNAT, loopback o enlace local: fuga de información (RFC 1918, secciones 3 y 5).
- **Severidad según la carencia real:** SPF, DKIM, DMARC y subdominios sólo tienen
  severidad alta o media si falla la protección misma (`GAPS` en `controls.ts`);
  un DMARC en `reject` sin informes o una clave DKIM antigua junto a otras buenas
  quedan en baja, y su texto de riesgo pasa a «Qué aporta».
- **Fuera del alcance del navegador:** cabeceras HTTP, HSTS, TLS, cookies, CORS,
  métodos y security.txt exigen leer respuestas de otros dominios, que el
  navegador bloquea (CORS). Quedan para la CLI.
- **Dominio reciente:** con menos de 30 días desde el alta sale `reg.recent`, en
  azul (informativo): es un dato que afecta a la entrega del correo, no un fallo.
- **`main.ts`:** formulario, ficha «Quién es», veredictos, tres cifras (controles
  bien, acciones y fiabilidad de los datos: coincidencia Cloudflare/Google y
  DNSSEC), plan de acción y los controles. Cada control se despliega en tres
  partes, en este orden: **Evidencia** (la consulta, si los dos resolvedores
  coinciden, los registros tal como llegaron y un enlace a la respuesta
  original), **Comprobaciones** (cada resultado con su icono, su RFC y su
  explicación) y **Acción** (pasos y registro exacto para copiar, lo que pide la
  norma, o «Ninguna: cumple»). Primero los datos y después la interpretación, para
  que cualquiera pueda comprobar cada conclusión.
- **«Volver a comprobar» (`recheck()` en `main.ts`):** cada control tiene un
  botón que repite la auditoría desde cero (sin caché propia) y dice qué ha
  cambiado en ese control (`ui/compare.ts`). Si nada cambió y sigue habiendo un
  problema, da el TTL de sus registros: lo que un resolvedor puede seguir
  sirviendo la respuesta anterior tras un cambio.
- **Cambios desde la última auditoría (`ui/history.ts`):** el último informe de
  cada dominio (hasta 20) se guarda sólo en el `localStorage` del navegador. Al
  volver a auditarlo, un bloque dice qué controles mejoran, empeoran o cambian y
  la nota antes y después. Un control sin datos en una de las dos auditorías
  (crt.sh caído) no cuenta como cambio. Se puede olvidar, y sin almacenamiento
  (ventana privada) la página funciona igual.
- **Informe para cliente (`ui/client-report.ts`):** un documento propio, no la
  página impresa, siempre con la misma estructura: resumen ejecutivo (nota,
  veredictos, cinco prioridades, quién es), tabla con el estado de cada control,
  plan de acción de lo más grave a lo menos (qué pasa, riesgo, pasos, registro
  exacto y norma) y anexo (lo que está bien, lo no verificado, metodología). Se
  inserta en la página sólo al imprimir, maquetado en A4, y el navegador lo
  guarda como PDF. Usa los mismos resultados que la pantalla.
- **`ui/palette.ts`:** buscador (Ctrl+K). Busca en todas las palabras sin tener
  en cuenta tildes ni mayúsculas, y también en el identificador y el detalle
  técnico de cada resultado: «caa» encuentra el aviso de CAA aunque su título no
  lo diga.
- **`ui/raw.ts`:** peticiones con su respuesta original, filtro y comando `curl`,
  y la tabla del contraste Cloudflare/Google.
- **Barra de acciones (`toolbar()` en `main.ts`):** la misma en el informe y en
  «Datos en crudo»: cambiar de vista, copiar el enlace, copiar el detalle
  (Markdown), copiar o descargar el JSON completo (informe y cada petición con su
  respuesta original).
- **Buscador:** es siempre el de la portada. Con un informe en pantalla, la
  portada se reduce a ese buscador (con el nombre auditado escrito; al pulsar se
  selecciona para escribir otro) y los resultados quedan justo debajo, tanto en
  el informe como en «Datos en crudo».
- **`ui/markdown.ts`:** el botón «Copiar detalle». Copia el informe en Markdown
  con la misma estructura que la pantalla: plan de acción y, por áreas, cada
  control con su evidencia, sus comprobaciones y su acción, y al final el
  contraste entre resolvedores.
  No añade nada que no esté en pantalla. Las respuestas HTTP completas quedan en
  el JSON completo.
- **`ui/observed.ts`:** el bloque «Lo que hay / Lo que debería haber» del detalle
  técnico. «Lo que hay» son los registros que la auditoría recogió para ese
  resultado, tal como llegaron (nombre, TTL, tipo y valor); si no hay ninguno, lo
  dice y nombra la consulta. «Lo que debería haber» es el registro exacto
  sugerido, si la auditoría pudo construirlo; si no, lo que pide la norma, o que
  ya cumple. Los resultados que sólo identifican (proveedor DNS o de correo,
  alojamiento) muestran sólo «Lo que hay»: no hay nada que cumplir.
- **`wiki/`:** entradas (`content.ts`), «En pocas palabras», tablas y errores
  habituales (`extra.ts`), y recorridos y relaciones entre entradas (`links.ts`).
- **Escala:** la misma que felixllorente.com. La base es `0.9375vw` desde 1280 px,
  con un mínimo de 12,8 px en pantallas de densidad 1, y todo se mide en rem, así
  que el contenido ocupa la misma proporción en cualquier monitor.

## 8. Seguridad de la propia web

- **Todo dato externo se escapa** antes de insertarse (`escapeHtml()` en
  `ui/layout.ts`). Un TXT malicioso como `<script>` se muestra como texto.
- **Content Security Policy** en una etiqueta `<meta>`, que vale en cualquier
  alojamiento y en la app de escritorio: sólo scripts, estilos y fuentes propios;
  `connect-src https:` para las consultas; sin `form-action` ni `base-uri`. Vite
  no incrusta recursos como `data:` (`assetsInlineLimit: 0`) para no tener que
  relajar la política.
- **Cabeceras de verdad** en Cloudflare Pages: la compilación genera
  `dist/_headers` desde la misma CSP (`vite.config.ts`), más `frame-ancestors
  'none'` y `X-Frame-Options: DENY` (una `<meta>` no puede impedir que la web se
  incruste), HSTS de un año, `nosniff`, `Referrer-Policy: no-referrer`,
  `Permissions-Policy` y `Cross-Origin-Opener-Policy`. Una prueba
  (`tests/web.test.ts`) pasa esas cabeceras por las propias comprobaciones web
  del auditor: la web aprueba su propio examen.
- **Sin terceros:** las fuentes van alojadas en la propia web, no hay analítica y
  el `referrer` está desactivado.

### La app de escritorio (`desktop/`)

- **Electron**, con la misma compilación que la web servida desde un esquema
  propio (`app://domain-auditor/`), de modo que la CSP, el almacenamiento y las
  rutas funcionan igual. No hay código de interfaz duplicado: `src/desktop.ts`
  detecta `window.desktop` y la interfaz activa la sonda, el botón «Guardar PDF»
  y los textos de privacidad propios.
- **Aislamiento:** `contextIsolation`, `sandbox` y sin `nodeIntegration`; el
  *preload* expone tres funciones; el proceso principal valida cada argumento
  (sólo `http(s)` a nombres de dominio, versiones TLS de una lista); no se navega
  fuera de `app://` y los enlaces externos se abren en el navegador del sistema.
- **Sin escaneo de la red local:** la sonda resuelve por DNS sobre HTTPS (la misma
  vista que el resto de la auditoría, y no la de un DNS filtrado en casa o en la
  oficina) y rechaza direcciones privadas, de bucle local, de enlace local, CGNAT
  y multidifusión. Cuerpos limitados a 64 KB y 10 s por conexión.
- **PDF:** el informe para cliente se inserta en la página como al imprimir y
  `printToPDF` lo guarda donde elija el usuario.
- **Paquetes:** `electron-builder` genera AppImage, `.rpm` y `.tar.gz` para Linux
  y `.zip` para Windows desde Linux (el ejecutable lleva icono y versión). El
  instalador NSIS y la versión portable necesitan Windows o Wine: los genera
  `.github/workflows/desktop.yml` en `windows-latest`, a mano o con una etiqueta
  `v*`, como artefactos privados.

## 9. Pruebas

```bash
pnpm test        # Vitest
pnpm check       # lint + tipos + pruebas + compilación
```

- **Qué cubren:** todo `core/` (análisis, recuentos, sugerencias, veredictos,
  proveedores, identidad), el registro en crudo, el buscador y la coherencia de
  textos y wiki.
- **Cómo, sin Internet:** `tests/helpers.ts` define `fakeResolver()`, un DNS
  falso que responde a partir de una tabla, sigue los CNAME como uno real, aplica
  comodines y simula NXDOMAIN, SERVFAIL y consultas sin respuesta. Las peticiones
  RDAP y RIPEstat se sustituyen por funciones `fetch` falsas (`rdapFetch()` da
  los estados que se le pidan). Las claves DKIM de prueba se generan con
  `node:crypto`.
- **Fallos de la auditoría de septiembre de 2026:** cada uno tiene su prueba de
  regresión (`tests/phase3.test.ts` y las de cada módulo). Mientras hubo fallos
  sin corregir se describieron con `it.fails`, que pasa mientras el fallo existe
  y se pone en rojo al corregirlo.
- **Web y escritorio:** `tests/web.test.ts` prueba cada comprobación web con una
  sonda falsa (redirecciones, HSTS sólo en `www`, retos antibots, versiones TLS
  dudosas, security.txt, política MTA-STS) y la carrera crt.sh / Cert Spotter.
- **Qué no cubren:** la interfaz se ha probado a mano en el navegador y en la app,
  contra dominios reales y contrastando los resultados con fuentes independientes
  (`dns.google`, RDAP, OpenSSL). No hay pruebas automáticas de extremo a extremo.

## 10. Compilación, CI y despliegue

- **Vite** compila las dos páginas y **TypeScript** en modo estricto
  (`noUncheckedIndexedAccess` incluido) comprueba los tipos.
- **GitHub Actions** (`.github/workflows/ci.yml`) ejecuta lint, tipos, pruebas y
  compilación en cada push y pull request.
- **Despliegue:** Cloudflare Pages compila (`pnpm build`, salida `dist`) y publica
  `audit.felixllorente.com` en cada push a `main`. El trabajo de GitHub Pages del
  CI queda como alternativa y sólo se ejecuta si la variable del repositorio
  `DEPLOY_PAGES` vale `true`.

## 11. Límites conocidos

- **DKIM:** busca los selectores habituales y los que escriba el usuario; uno con
  otro nombre no se encuentra.
- **MTA-STS:** en la web comprueba el TXT y que exista el servidor; el contenido
  de la política (CORS) sólo lo lee la app de escritorio.
- **SPF:** las macros (`%{i}`, `%{d}`…) dependen del remitente y no se evalúan.
- **DNSSEC:** no valida las firmas por su cuenta; se apoya en la validación
  independiente de dos resolvedores (bit `AD` de Cloudflare y de Google).
- **Contexto:** es una revisión externa y automática; algunos avisos pueden ser
  decisiones correctas en su caso (cada uno lo explica en «Depende del contexto»).
- **RDAP:** algunos registros nacionales (como .es) no lo ofrecen.
- **Cabeceras HTTP y TLS:** no se pueden leer desde un navegador; las comprueba
  la app de escritorio, sólo en la página de inicio.
- **Proveedores:** se reconocen por patrones de nombre; uno no reconocido se
  muestra por sus NS o MX.

## 12. Decisiones de diseño y alternativas descartadas

| Decisión | Por qué | Alternativa descartada |
| --- | --- | --- |
| Web estática sin servidor | Privacidad, coste cero, nada que atacar | Backend propio: permitiría cabeceras y TLS, pero guarda consultas y es un proxy que proteger |
| DoH JSON de Cloudflare con Google de respaldo | CORS, validan DNSSEC, gran disponibilidad | DoH binario (RFC 8484): más complejo de decodificar sin ventaja aquí |
| Núcleo sin DOM y textos aparte | Pruebas sin navegador; textos editables sin riesgo | Mezclar lógica y HTML |
| Sin framework de interfaz | Aplicación pequeña; menos dependencias que auditar | React o similares |
| No inventar datos (buzones, proveedores) | Una sugerencia equivocada rompe cosas reales | Rellenar valores «razonables» |
| Contraste sólo de registros estables | Evita falsas alarmas | Comparar todo, incluidas A/AAAA |
| RFC 9989 para DMARC | Es la norma vigente desde mayo de 2026 | Seguir con el RFC 7489 obsoleto |
| App de escritorio con Electron | Reutiliza la web tal cual y su TLS (BoringSSL) aún habla TLS 1.0/1.1 para probarlos | Tauri: más ligero, pero exige Rust y usa el WebView del sistema; una CLI: no sirve a quien no usa terminal |
| crt.sh con Cert Spotter en paralelo a los 6 s | crt.sh tarda a menudo 10-20 s; el informe dice de qué fuente vienen los datos | Esperar siempre a crt.sh (20 s) o bajar su tiempo límite (más «CT no disponible») |
