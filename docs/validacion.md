# Validación con dominios reales

Domain Auditor sólo es útil si lo que afirma es cierto. Además de las pruebas
unitarias (`pnpm test`), hay un banco de validación en vivo (`pnpm validate`) que
audita dominios reales con el código de la aplicación y **contrasta cada
afirmación con una fuente independiente**.

## Cómo funciona

`validation/validate.test.ts` audita cada objetivo con el código de la
aplicación y lo contrasta con fuentes que no comparten nada con ella:

- **Dos resolvedores de referencia** (`truth.ts`): dns.google y NextDNS, este
  último ajeno al auditor (que usa Cloudflare y Google). Un valor sólo se toma
  como cierto si los dos coinciden; si no (un registro que acaba de cambiar), se
  anota en el resumen en lugar de juzgar.
- **Una segunda lectura de cada norma** (`independent.ts`), escrita aparte del
  código de `src/core` y sin compartir su lógica: política DMARC según el
  RFC 9989, conjunto CAA aplicable, estados del registro leídos del RDAP del
  propio registro (a través del índice de IANA, no de rdap.org) y la política
  MTA-STS leída por HTTPS, como haría un servidor de correo.

Comprueba:

1. **Invariantes de todos los informes**
   - Cada resultado tiene texto en español y en inglés.
   - «Copiar detalle» no deja marcadores sin rellenar ni `undefined`/`NaN`.
   - Ningún resultado de MTA-STS sale «bien»: la política no se puede leer desde
     el navegador.
2. **Valores, no sólo presencia**
   - SPF: el registro es el mismo que ven los dos resolvedores.
   - DMARC: la política que dice el informe es la que aplicaría un receptor según
     la lectura independiente (incluidos `sp`, `np` y registros mal escritos).
   - CAA: «limita», «no limita» y «no hay» cuadran con el conjunto aplicable.
   - Informes DMARC a otro dominio: cada dirección sin autorizar que encuentra la
     lectura independiente (RFC 9990, sección 4) está en el aviso del informe.
   - Null MX, ausencia de MX, DS y validación DNSSEC.
3. **Cada «bien» que se puede verificar desde fuera**
   - Bloqueo de transferencia y *registry lock*: los estados del registro lo
     prueban.
   - `mta-sts.no-host`: el nombre `mta-sts.<dominio>` no resuelve.
4. **Cada afirmación sobre terceros, una a una**
   - `ct.takeover`: el destino da NXDOMAIN **y** su proveedor está en la lista de
     espacios de nombres reclamables.
   - `ct.dangling`: el destino da NXDOMAIN.
   - `ct.private-ips`: cada nombre citado resuelve a una IP privada.
   - `mx.dane`: el TLSA existe y la respuesta está validada (bit AD) en los dos
     resolvedores.
   - Shodan InternetDB: los puertos del informe son los que da una consulta
     aparte; los resultados de Shodan y OTX son siempre informativos.
5. **Hechos conocidos de cada dominio**, comprobados a mano antes de escribir la
   prueba (por ejemplo, `dnssec-failed.org` da SERVFAIL).

El resumen (`validation/out/RESUMEN.md`) tiene una columna de notas con lo que no
se pudo validar (crt.sh o RDAP sin respuesta, resolvedores en desacuerdo), el
modo real de la política MTA-STS, para que nada pase por bueno en silencio. Los
informes completos quedan en `validation/out/` (no se versiona).

### Comparación con internet.nl

`pnpm validate:nl` pasa la prueba de correo de [internet.nl](https://internet.nl)
a una lista de dominios y compara, control a control, SPF, DMARC, DKIM, DNSSEC y
DANE (`validation/internetnl.test.ts`). Deben coincidir salvo por diferencias de
criterio ya explicadas; cualquier otra hace fallar la prueba. Cada prueba de
internet.nl tarda de uno a tres minutos, así que va aparte y guarda los
resultados un día en `validation/out/internetnl/`. El resumen queda en
`validation/out/INTERNETNL.md`.

Diferencias explicadas (auditoría del 30 de septiembre de 2026: 160
comprobaciones comparables, 146 coincidentes):

| Diferencia | Por qué |
| --- | --- |
| DKIM «sin verificar» donde internet.nl pasa | internet.nl da por buena la existencia de `_domainkey` (RFC 8020); el auditor también la detecta, pero sólo da DKIM por bueno si encuentra la clave |
| DMARC en aviso donde internet.nl pasa | El auditor avisa también con `sp=none` |
| DMARC «recomendación» en internet.nl | Exige `v=DMARC1;` con punto y coma en la autorización de un `rua` externo; el RFC 9990 (sección 4, paso 6) lo hace opcional |
| SPF en aviso donde internet.nl pasa | El auditor avisa de un SPF que no autoriza a nadie en un dominio con MX |
| DANE de nic.cz | internet.nl no vio el TLSA; los resolvedores y `delv` (validación local) sí. Si vuelven a diferir, el banco decide con el DNS |
| DANE «no probado» | internet.nl no pudo conectar con los MX |

## Corpus

| Tipo | Dominios |
| --- | --- |
| Bien configurados | internet.nl, nic.cz, sidn.nl, example.com, cloudflare.com, google.com, github.com, posteo.de |
| Casos que antes fallaban | microsoft.com (CAA sin `issue`), fastmail.com (MTA-STS en `testing`), posteo.de (CAA con `geotrust.com`), sidn.nl (`locked`), nic.cz (sólo `server transfer prohibited`) |
| Vulnerables o de prueba públicos | dnssec-failed.org (DNSSEC roto a propósito), zonetransfer.me (DigiNinja), vulnweb.com (Acunetix), testfire.net (IBM), hackthebox.com |
| Casos límite | rtve.es (`.es` sin RDAP, macros SPF), bbva.es (`rua` externo sin autorizar), pccomponentes.com (muchos subdominios), www.github.com (alias de github.com), dominio inexistente |
| IP | 8.8.8.8, 1.1.1.1, 192.168.1.1, 2001:4860:4860::8888 |

## Errores que encontró y se corrigieron

| Caso | Qué decía | Qué era en realidad | Corrección |
| --- | --- | --- | --- |
| pccomponentes.com | «Posible toma de control» de un CNAME a un balanceador ELB inexistente | Los nombres de ELB llevan un ID asignado por AWS: no se pueden reclamar (AWS; can-i-take-over-xyz) | Takeover sólo en espacios reclamables (Elastic Beanstalk, Azure); el resto es «CNAME huérfano», severidad baja |
| rtve.es | «El SPF apunta a un servicio que no existe» | Era una macro SPF (`%{ir}.%{v}.%{d}…`), que se expande en cada correo (RFC 7208, sección 7) | Las macros se cuentan pero no se resuelven; resultado informativo `spf.macros` |
| vulnweb.com | SPF correcto | `v=spf1 ~all` no autoriza a nadie y el dominio tiene el correo en Google: su propio correo falla SPF | Nuevo aviso `spf.no-senders` con el `include:` del proveedor |
| internet.nl | «Sin bloqueo de transferencia» | SIDN (.nl) no usa estados EPP ni publica la caducidad: las transferencias van con código de autorización | En ccTLD sin estados EPP, «Sin verificar» con explicación |
| example.com | Aviso por DMARC sin informes | Dominio sin correo: los informes son opcionales | Informativo si el correo está deshabilitado |
| pccomponentes.com | No lo señalaba | 8 subdominios públicos resuelven a IP privadas (fuga de información, RFC 1918, secciones 3 y 5) | Nuevo aviso `ct.private-ips` |
| Dominios inexistentes, DNSSEC roto, IP privadas | «0 de 10 bien» | No son evaluables | «No evaluable» |
| Todos | `{mailbox}` literal en «Copiar detalle» | Es un campo que se rellena en pantalla | Se muestra como `<buzón>` |
| fastmail.com, yahoo.com | «MTA-STS publicado · Bien» | Su política está en `mode: testing`, que no protege (RFC 8461, sección 5) | MTA-STS con servidor es «sin verificar», nunca «bien» |
| microsoft.com | CAA en verde | Su CAA sólo tiene `contactemail`: no limita la emisión (RFC 8659, sección 3) | Un CAA sin `issue` es un aviso |
| posteo.de | «Certificados de autoridades que el CAA no permite: DigiCert» | Su CAA autoriza a DigiCert con `geotrust.com`, que DigiCert acepta | Listas completas de identificadores de cada autoridad; `issuewild` para comodines |
| sidn.nl | «Sin bloqueo de transferencia» | Tiene el estado RDAP `locked`, el *registry lock* de SIDN (RFC 9083, sección 10.2.2) | Se leen `locked` y `transfer prohibited` |
| nic.cz | «Registry lock: ni el registrador puede cambiarlo» | Sólo tiene `server transfer prohibited` | *Registry lock* sólo con los tres `server*Prohibited` o con `locked` |
| nic.cz, uam.es | «Subdominios · Bien», y sumaba en la puntuación | Sólo se comprobaron 40 de 274 y 40 de 765 | Dato informativo con la cobertura; CT no puntúa |
| Varios | La misma auditoría puntuaba distinto de una vez a otra | crt.sh falló (404, 502, 429, tiempo agotado) en 4 de 10 auditorías seguidas | Subdominios y certificados fuera de la puntuación |
| Casos simulados | Un SERVFAIL se leía como «no existe»: se proponía un null MX o quitar un `include` del SPF | Un fallo de DNS no dice nada de la zona (RFC 7208, sección 2.6.6; RFC 9989, sección 4.10.1) | `*.lookup-error` «sin verificar»; Google como respaldo también ante SERVFAIL |
| Casos simulados | `v=dmarc1` o un `sp` mal escrito se daban por `reject` | Los receptores ignoran el registro o aplican `p=none` (RFC 9989, secciones 4.7 y 4.10.1) | DMARC estricto |
| Casos simulados | `ip4:1.2.3.0/33` o dos `redirect` pasaban por correctos | Son `permerror` (RFC 7208, secciones 4.6 y 6) | Sintaxis SPF completa |
| bbva.es | «Pide informes · Bien» | Su `rua` apunta a bbva.com, que no ha autorizado los informes: nunca llegan (RFC 9990, sección 4) | Aviso `dmarc.rua-unauthorized` |
| dnssec-failed.org | «El dominio no funciona», sin más | Su DS no coincide con ninguna DNSKEY: los resolvedores lo dicen con EDE 9 (RFC 8914) | `dns.dnssec-broken` con el código EDE y cómo arreglar el DS |
| testfire.net, vulnweb.com, zonetransfer.me | DKIM «sin verificar» | `_domainkey` da NXDOMAIN: no publican ninguna clave (RFC 8020, sección 2); internet.nl coincide | Aviso `dkim.no-domainkey` |
| posteo.de, bbva.es | DKIM «sin verificar» sin más | `_domainkey` existe: tienen claves con un selector desconocido | `dkim.selector-unknown`, que pide el selector |
| www.github.com | Proponía registros en el propio nombre | Es un alias (CNAME) de github.com: no admite otros registros (RFC 1034, sección 3.6.2) | `dns.alias` y sin sugerencias en el alias |
| posteo.de, mailbox.org | DANE «bien» mirando sólo 3 MX | Tienen 4 y 5 MX | Se comprueban todos y se avisa si sólo algunos tienen DANE |
| gov.uk, mercadona.es | «Coherencia · Aviso»: los resolvedores no coinciden | Un TXT que cambia solo (`#Timestamp`) o tokens de verificación en distinto momento de caché | Del TXT del dominio sólo se compara el SPF |
| sidn.nl | Proveedor de correo sin reconocer | Su MX es el nuevo de Microsoft 365 con DNSSEC (`*.mx.microsoft`) | Reconocido; y `amazonaws.com` sólo cuenta como Amazon SES en sus servidores de entrada |
| pccomponentes.com, proton.me, tuta.com | DMARC en `reject`/`quarantine` en aviso y sin puntuar por no tener `rua`, con el veredicto en «Bien» | Los informes no cambian el tratamiento del correo (RFC 9989, sección 4.7) | `dmarc.no-rua` informativo |
| Casos simulados | MX que no resuelven, MX alias, null MX mezclado, claves DKIM `k=` desconocido o `h=sha1` pasaban por correctos | RFC 5321, sección 5.1; RFC 2181, sección 10.3; RFC 7505, sección 3; RFC 6376, sección 3.6.1; RFC 8301, sección 3.1 | Fallo o aviso con su norma |

## Límites de la validación

- dns.google también es una de las fuentes del auditor (respaldo y contraste);
  por eso se exige que NextDNS dé lo mismo. Aun así, los tres son resolvedores
  públicos: si el DNS autoritativo responde distinto según quién pregunte, lo
  verían igual.
- `independent.ts` reimplementa las normas para contrastarlas, pero lo escribe la
  misma persona: una mala lectura común de un RFC pasaría. Por eso se compara
  además con internet.nl, una herramienta de referencia ajena.
- rdap.org rechaza peticiones de Node sin `User-Agent`; el banco envía uno como
  hace cualquier navegador. La aplicación no cambia.
- Los datos de Internet cambian: si un dominio del corpus cambia su configuración,
  hay que revisar sus hechos conocidos antes de dar la prueba por mala.
