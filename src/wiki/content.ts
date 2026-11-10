/**
 * Wiki: what each record or check is, with links to the official specification.
 * Texts use `code` spans like the findings. References point to RFC Editor, IANA,
 * ICANN, RIPE NCC or the service's own documentation.
 */
import type { Lang } from "../i18n";

type T = Record<Lang, string>;
type TList = Record<Lang, string[]>;

export interface WikiRef {
  label: string;
  /** Section of the document, rendered as "sección"/"section" in each language. */
  section?: string;
  url: string;
}

export type WikiGroup = "basics" | "security" | "mail" | "web" | "network" | "tool";

export interface WikiEntry {
  id: string;
  group: WikiGroup;
  title: T;
  summary: T;
  body: TList;
  example?: string;
  checks: TList;
  refs: WikiRef[];
}

export const GROUPS: Record<WikiGroup, T> = {
  basics: { es: "Fundamentos de DNS", en: "DNS basics" },
  security: { es: "Seguridad del DNS", en: "DNS security" },
  mail: { es: "Correo", en: "E-mail" },
  web: { es: "Web", en: "Website" },
  network: { es: "Red y registro", en: "Network and registration" },
  tool: { es: "Cómo funciona", en: "How it works" },
};

const rfc = (n: number, section?: string): WikiRef => ({
  label: `RFC ${n}`,
  ...(section ? { section } : {}),
  url: `https://www.rfc-editor.org/rfc/rfc${n}${section ? `#section-${section}` : ""}`,
});

const IANA_DNS: WikiRef = { label: "IANA · DNS Parameters", url: "https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml" };

export const WIKI: WikiEntry[] = [
  // ---------- Basics ----------
  {
    id: "a-aaaa",
    group: "basics",
    title: { es: "A y AAAA", en: "A and AAAA" },
    summary: {
      es: "Traducen un nombre a una dirección IP: `A` para IPv4 y `AAAA` para IPv6.",
      en: "Map a name to an IP address: `A` for IPv4 and `AAAA` for IPv6.",
    },
    body: {
      es: [
        "Son los registros que usa el navegador para saber a qué servidor conectarse. Un nombre puede tener varios, y el cliente elige uno.",
        "Tener `AAAA` no es obligatorio, pero cada vez más redes móviles y proveedores funcionan sólo con IPv6 y llegan a IPv4 a través de traducción.",
      ],
      en: [
        "They are what a browser uses to know which server to connect to. A name can have several, and the client picks one.",
        "`AAAA` is not mandatory, but more and more mobile networks and providers run IPv6-only and reach IPv4 through translation.",
      ],
    },
    example: "example.com.   300  IN  A     192.0.2.10\nexample.com.   300  IN  AAAA  2001:db8::10",
    checks: {
      es: ["Que el nombre resuelva a alguna dirección.", "Si tiene IPv6.", "Qué sistema autónomo (AS) aloja la primera IP."],
      en: ["Whether the name resolves to any address.", "Whether it has IPv6.", "Which autonomous system (AS) hosts the first IP."],
    },
    refs: [rfc(1035, "3.4.1"), rfc(3596)],
  },
  {
    id: "cname",
    group: "basics",
    title: { es: "CNAME", en: "CNAME" },
    summary: { es: "Convierte un nombre en alias de otro.", en: "Makes a name an alias of another one." },
    body: {
      es: [
        "Cuando un resolvedor encuentra un `CNAME`, repite la consulta con el nombre de destino. Es habitual en `www` o para apuntar a servicios de terceros.",
        "Un nombre con `CNAME` no puede tener ningún otro registro, por eso no se puede usar en la raíz del dominio (que siempre tiene `SOA` y `NS`). Un `MX` tampoco debe apuntar a un alias.",
      ],
      en: [
        "When a resolver finds a `CNAME`, it repeats the query with the target name. It is common for `www` or to point to third-party services.",
        "A name with a `CNAME` cannot hold any other record, so it cannot be used at the zone apex (which always has `SOA` and `NS`). An `MX` must not point to an alias either.",
      ],
    },
    example: "www.example.com.  300  IN  CNAME  example.com.",
    checks: {
      es: ["Se muestra la cadena de alias en los registros de la sección DNS."],
      en: ["The alias chain is shown in the DNS section records."],
    },
    refs: [rfc(1034, "3.6.2"), rfc(2181, "10.1"), rfc(1912, "2.4")],
  },
  {
    id: "ns",
    group: "basics",
    title: { es: "NS: servidores de nombres", en: "NS: name servers" },
    summary: {
      es: "Indican qué servidores tienen la información autoritativa de la zona.",
      en: "Say which servers hold the authoritative data for the zone.",
    },
    body: {
      es: [
        "El registro de la zona superior (por ejemplo `.com`) delega el dominio en estos servidores. Si ninguno responde, el dominio deja de existir a efectos prácticos: ni web ni correo.",
        "Se recomiendan al menos dos, en redes distintas, para que la caída de uno no deje el dominio sin servicio.",
      ],
      en: [
        "The parent zone (for example `.com`) delegates the domain to these servers. If none answers, the domain effectively stops existing: no web, no mail.",
        "At least two are recommended, on different networks, so the loss of one does not take the domain down.",
      ],
    },
    example: "example.com.  86400  IN  NS  ns1.example.net.\nexample.com.  86400  IN  NS  ns2.example.org.",
    checks: {
      es: ["Cuántos servidores de nombres hay.", "Qué proveedor gestiona el DNS."],
      en: ["How many name servers there are.", "Which provider hosts the DNS."],
    },
    refs: [rfc(1035, "3.3.11"), rfc(2182)],
  },
  {
    id: "soa",
    group: "basics",
    title: { es: "SOA", en: "SOA" },
    summary: {
      es: "Cabecera de la zona: servidor primario, contacto, número de serie y temporizadores.",
      en: "Zone header: primary server, contact, serial number and timers.",
    },
    body: {
      es: [
        "Sus campos son: servidor primario, buzón del responsable (con la `@` cambiada por un punto), número de serie, `refresh`, `retry`, `expire` y el TTL de las respuestas negativas.",
        "El número de serie debe aumentar con cada cambio para que los secundarios sepan que hay datos nuevos. El último valor indica cuánto se cachea un «no existe».",
      ],
      en: [
        "Its fields are: primary server, contact mailbox (with the `@` replaced by a dot), serial number, `refresh`, `retry`, `expire` and the TTL of negative answers.",
        "The serial must increase with every change so secondaries know there is new data. The last value sets how long a \"does not exist\" answer is cached.",
      ],
    },
    example: "example.com.  1800  IN  SOA  ns1.example.net. hostmaster.example.com. 2026092501 7200 3600 1209600 300",
    checks: {
      es: ["Si el nombre es una zona propia o un nombre dentro de otra.", "El SOA completo aparece en los registros."],
      en: ["Whether the name is a zone of its own or a name inside another zone.", "The full SOA is listed in the records."],
    },
    refs: [rfc(1035, "3.3.13"), rfc(2308)],
  },
  {
    id: "txt",
    group: "basics",
    title: { es: "TXT", en: "TXT" },
    summary: {
      es: "Texto libre asociado a un nombre. Lo usan SPF, DMARC, DKIM y las verificaciones de dominio.",
      en: "Free text attached to a name. SPF, DMARC, DKIM and domain verifications use it.",
    },
    body: {
      es: [
        "Cada cadena de un TXT tiene un máximo de 255 caracteres; los valores más largos (como una clave DKIM) se parten en varias cadenas que se leen seguidas.",
        "Es normal ver muchos TXT en la raíz: verificaciones de Google, Microsoft, Apple… No son peligrosos, pero conviene borrar los que ya no se usan.",
      ],
      en: [
        "Each TXT string is at most 255 characters; longer values (such as a DKIM key) are split into several strings that are read back to back.",
        "It is normal to see many TXT records at the apex: Google, Microsoft or Apple verifications… They are harmless, but unused ones should be removed.",
      ],
    },
    example: 'example.com.  300  IN  TXT  "v=spf1 include:_spf.example.net -all"',
    checks: {
      es: ["Los TXT que no son SPF se listan en la sección DNS; el SPF, en Correo."],
      en: ["TXT records other than SPF are listed in the DNS section; SPF goes under E-mail."],
    },
    refs: [rfc(1035, "3.3.14"), rfc(7208, "3.3")],
  },
  {
    id: "rcode",
    group: "basics",
    title: { es: "Códigos de respuesta", en: "Response codes" },
    summary: {
      es: "`NOERROR`, `NXDOMAIN` y `SERVFAIL`: cómo responde el DNS aunque no haya datos.",
      en: "`NOERROR`, `NXDOMAIN` and `SERVFAIL`: how DNS answers even when there is no data.",
    },
    body: {
      es: [
        "`NOERROR` sin registros significa que el nombre existe pero no tiene ese tipo. `NXDOMAIN` significa que el nombre no existe.",
        "`SERVFAIL` indica que el resolvedor no ha podido obtener una respuesta fiable: servidores caídos o, muy a menudo, una firma DNSSEC rota.",
      ],
      en: [
        "`NOERROR` with no records means the name exists but has no record of that type. `NXDOMAIN` means the name does not exist.",
        "`SERVFAIL` means the resolver could not get a trustworthy answer: servers down or, very often, a broken DNSSEC signature.",
      ],
    },
    checks: {
      es: ["Si el dominio no existe o su DNS falla, el informe se detiene ahí."],
      en: ["If the domain does not exist or its DNS fails, the report stops there."],
    },
    refs: [rfc(1035, "4.1.1"), IANA_DNS],
  },

  // ---------- Security ----------
  {
    id: "dnssec",
    group: "security",
    title: { es: "DNSSEC y DS", en: "DNSSEC and DS" },
    summary: {
      es: "Firma las respuestas DNS para que no se puedan falsificar.",
      en: "Signs DNS answers so they cannot be forged.",
    },
    body: {
      es: [
        "La zona publica sus claves (`DNSKEY`) y firma cada conjunto de registros (`RRSIG`). La zona superior publica un `DS`, el resumen de la clave, y así se forma una cadena de confianza desde la raíz.",
        "Un resolvedor que valida marca las respuestas correctas con el bit `AD` (datos autenticados). Si la firma no cuadra, devuelve `SERVFAIL` en lugar de datos falsos.",
        "El fallo más común es cambiar de proveedor DNS sin actualizar el `DS` en el registrador: el dominio deja de resolver para todos los que validan.",
      ],
      en: [
        "The zone publishes its keys (`DNSKEY`) and signs every record set (`RRSIG`). The parent zone publishes a `DS`, a digest of the key, building a chain of trust from the root.",
        "A validating resolver marks correct answers with the `AD` (authenticated data) bit. If a signature does not match, it returns `SERVFAIL` instead of forged data.",
        "The most common failure is moving DNS provider without updating the `DS` at the registrar: the domain stops resolving for everyone who validates.",
      ],
    },
    example: "example.com.  3600  IN  DS  2371 13 2 ab6b2606…b3cc",
    checks: {
      es: ["Si hay `DS` en la zona superior.", "Si el resolvedor valida la respuesta (bit `AD`)."],
      en: ["Whether there is a `DS` in the parent zone.", "Whether the resolver validates the answer (`AD` bit)."],
    },
    refs: [
      rfc(4033),
      rfc(4034),
      rfc(4035),
      { label: "ICANN · DNSSEC", url: "https://www.icann.org/resources/pages/dnssec-what-is-it-why-important-2019-03-05-en" },
    ],
  },
  {
    id: "caa",
    group: "security",
    title: { es: "CAA", en: "CAA" },
    summary: {
      es: "Dice qué autoridades de certificación pueden emitir certificados para el dominio.",
      en: "States which certificate authorities may issue certificates for the domain.",
    },
    body: {
      es: [
        "Antes de emitir un certificado, la autoridad está obligada a consultar el CAA. Si existe y no la incluye, debe negarse. Reduce el riesgo de certificados emitidos por error o con engaño.",
        "Las etiquetas son `issue` (certificados normales), `issuewild` (comodín) e `iodef` (dónde avisar de intentos rechazados). Si un nombre no tiene CAA se usa el del dominio superior más cercano.",
      ],
      en: [
        "Before issuing a certificate, the authority must check CAA. If it exists and does not list it, it must refuse. It reduces the risk of certificates issued by mistake or through deception.",
        "Tags are `issue` (regular certificates), `issuewild` (wildcards) and `iodef` (where to report refused attempts). A name without CAA uses the one of the closest parent domain.",
      ],
    },
    example: 'example.com.  3600  IN  CAA  0 issue "letsencrypt.org"\nexample.com.  3600  IN  CAA  0 iodef "mailto:security@example.com"',
    checks: {
      es: ["Si hay CAA, propio o heredado.", "Qué autoridades están autorizadas."],
      en: ["Whether there is CAA, own or inherited.", "Which authorities are allowed."],
    },
    refs: [rfc(8659)],
  },

  {
    id: "ct",
    group: "security",
    title: { es: "Certificate Transparency y subdominios", en: "Certificate Transparency and subdomains" },
    summary: {
      es: "Registros públicos de todos los certificados emitidos: muestran los subdominios expuestos y quién emitió cada certificado.",
      en: "Public logs of every issued certificate: they show the exposed subdomains and who issued each certificate.",
    },
    body: {
      es: [
        "Las autoridades de certificación publican cada certificado en registros abiertos (Certificate Transparency). Cualquiera puede consultarlos, por ejemplo en crt.sh, así que los subdominios que tienen HTTPS son públicos: es la superficie que ve un atacante.",
        "Un subdominio con un CNAME que apunta a un recurso borrado (una web de Azure, Heroku o S3 eliminada) queda «colgando». Si otra persona puede crear ese mismo recurso en el servicio, controla el subdominio: es el subdomain takeover.",
        "Comparar los emisores de los certificados vigentes con el CAA ayuda a detectar certificados emitidos sin autorización.",
      ],
      en: [
        "Certificate authorities publish every certificate in open logs (Certificate Transparency). Anyone can query them, for instance on crt.sh, so subdomains with HTTPS are public: it is the surface an attacker sees.",
        "A subdomain whose CNAME points to a deleted resource (a removed Azure, Heroku or S3 site) is left dangling. If someone else can create that same resource at the service, they control the subdomain: this is subdomain takeover.",
        "Comparing the issuers of certificates in force with the CAA helps to spot certificates issued without authorisation.",
      ],
    },
    example: "tienda.example.com.  300  IN  CNAME  tienda-antigua.azurewebsites.net.\n; tienda-antigua.azurewebsites.net → NXDOMAIN: CNAME colgante",
    checks: {
      es: ["Qué subdominios aparecen en certificados públicos.", "Si alguno tiene un CNAME a un destino que ya no existe.", "Qué autoridades han emitido certificados en vigor y si el CAA las permite."],
      en: ["Which subdomains appear in public certificates.", "Whether any has a CNAME to a target that no longer exists.", "Which authorities issued certificates in force and whether the CAA allows them."],
    },
    refs: [
      rfc(6962),
      { label: "crt.sh", url: "https://crt.sh/" },
      { label: "OWASP WSTG · Test for Subdomain Takeover", url: "https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover/" },
    ],
  },

  // ---------- Mail ----------
  {
    id: "mx",
    group: "mail",
    title: { es: "MX y Null MX", en: "MX and Null MX" },
    summary: {
      es: "Indica qué servidores reciben el correo del dominio y en qué orden.",
      en: "Says which servers receive the domain's mail, and in which order.",
    },
    body: {
      es: [
        "Cada MX lleva una prioridad: se intenta primero el número más bajo. Debe apuntar a un nombre con registro A/AAAA, nunca a una IP ni a un alias.",
        "Un dominio que no recibe correo puede decirlo con un «null MX» (`MX 0 .`): los remitentes fallan al momento en lugar de reintentar durante días.",
      ],
      en: [
        "Each MX has a priority: the lowest number is tried first. It must point to a name with an A/AAAA record, never to an IP or an alias.",
        "A domain that accepts no mail can say so with a null MX (`MX 0 .`): senders fail immediately instead of retrying for days.",
      ],
    },
    example: "example.com.  3600  IN  MX  10 mx1.example.net.\nexample.com.  3600  IN  MX  20 mx2.example.net.",
    checks: {
      es: ["Servidores de correo y proveedor.", "MX que apuntan a IP.", "Null MX."],
      en: ["Mail servers and provider.", "MX pointing to IP addresses.", "Null MX."],
    },
    refs: [rfc(1035, "3.3.9"), rfc(5321, "5.1"), rfc(7505), rfc(2181, "10.3")],
  },
  {
    id: "spf",
    group: "mail",
    title: { es: "SPF", en: "SPF" },
    summary: {
      es: "Lista los servidores autorizados a enviar correo en nombre del dominio.",
      en: "Lists the servers allowed to send mail on behalf of the domain.",
    },
    body: {
      es: [
        "Es un TXT en la raíz que empieza por `v=spf1`. Los mecanismos (`ip4`, `ip6`, `a`, `mx`, `include`…) describen quién puede enviar, y el final `all` dice qué hacer con el resto: `-all` rechazar, `~all` marcar como sospechoso, `?all` no opinar y `+all` aceptar a cualquiera.",
        "Sólo puede haber un registro SPF. Además, evaluarlo no puede costar más de 10 consultas DNS (cada `include`, `a`, `mx`, `ptr`, `exists` y `redirect`, incluidas las anidadas). Si se pasa, el SPF da error permanente y deja de proteger.",
        "SPF comprueba el remitente del sobre (`MAIL FROM`), no el `From:` que ve el usuario. Por eso se complementa con DMARC.",
      ],
      en: [
        "It is a TXT at the apex starting with `v=spf1`. Mechanisms (`ip4`, `ip6`, `a`, `mx`, `include`…) describe who may send, and the final `all` says what to do with everyone else: `-all` reject, `~all` flag as suspicious, `?all` no opinion and `+all` accept anyone.",
        "There can only be one SPF record. Evaluating it may not cost more than 10 DNS lookups (each `include`, `a`, `mx`, `ptr`, `exists` and `redirect`, nested ones included). Above that, SPF returns a permanent error and stops protecting.",
        "SPF checks the envelope sender (`MAIL FROM`), not the `From:` the user sees. That is why it is paired with DMARC.",
      ],
    },
    example: 'example.com.  300  IN  TXT  "v=spf1 ip4:192.0.2.0/24 include:_spf.example.net -all"',
    checks: {
      es: [
        "Que exista y sea único.",
        "Sintaxis de los mecanismos.",
        "El `all` final.",
        "Consultas DNS totales, siguiendo includes y redirect, con detección de bucles.",
        "Uso de `ptr`, desaconsejado.",
      ],
      en: [
        "That it exists and is unique.",
        "Mechanism syntax.",
        "The final `all`.",
        "Total DNS lookups, following includes and redirect, with loop detection.",
        "Use of the discouraged `ptr`.",
      ],
    },
    refs: [rfc(7208), rfc(7208, "4.6.4"), rfc(7208, "5.5")],
  },
  {
    id: "dkim",
    group: "mail",
    title: { es: "DKIM", en: "DKIM" },
    summary: {
      es: "Firma criptográfica del correo: prueba que el mensaje sale del dominio y no se ha modificado.",
      en: "Cryptographic signature of mail: proves the message comes from the domain and was not altered.",
    },
    body: {
      es: [
        "El servidor de envío firma cabeceras y cuerpo con una clave privada. La pública se publica en `<selector>._domainkey.<dominio>`, y el selector va en la cabecera `DKIM-Signature` (`s=`).",
        "Los selectores no se pueden listar por DNS, así que una herramienta externa sólo puede probar los nombres habituales de cada proveedor. Que no encuentre ninguno no significa que no haya DKIM.",
        "Las claves RSA deben tener al menos 1024 bits y se recomiendan 2048. También existe Ed25519. Un `p=` vacío indica una clave revocada.",
      ],
      en: [
        "The sending server signs headers and body with a private key. The public key is published at `<selector>._domainkey.<domain>`, and the selector travels in the `DKIM-Signature` header (`s=`).",
        "Selectors cannot be listed through DNS, so an outside tool can only probe each provider's usual names. Finding none does not mean there is no DKIM.",
        "RSA keys must be at least 1024 bits and 2048 is recommended. Ed25519 also exists. An empty `p=` marks a revoked key.",
      ],
    },
    example: 'google._domainkey.example.com.  300  IN  TXT  "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA…"',
    checks: {
      es: ["Unos 30 selectores habituales.", "Tamaño real de la clave RSA (leyendo su estructura DER).", "Claves revocadas y modo prueba (`t=y`)."],
      en: ["About 30 common selectors.", "Real RSA key size (parsing its DER structure).", "Revoked keys and test mode (`t=y`)."],
    },
    refs: [rfc(6376), rfc(8301), rfc(8463)],
  },
  {
    id: "dmarc",
    group: "mail",
    title: { es: "DMARC", en: "DMARC" },
    summary: {
      es: "Une SPF y DKIM con el `From:` visible y dice qué hacer con el correo que suplanta el dominio.",
      en: "Ties SPF and DKIM to the visible `From:` and says what to do with mail spoofing the domain.",
    },
    body: {
      es: [
        "Se publica en `_dmarc.<dominio>`. Un mensaje pasa DMARC si SPF o DKIM pasan y además están «alineados» con el dominio del `From:`. La política `p` indica qué hacer si no pasa: `none` (sólo observar), `quarantine` (a spam) o `reject` (rechazar).",
        "`rua` pide informes agregados diarios: son la forma de saber quién envía correo en nombre del dominio antes de endurecer la política. `sp` y `np` fijan la política de subdominios y de subdominios inexistentes; `t=y` activa el modo prueba.",
        "En mayo de 2026 el RFC 9989 sustituyó al RFC 7489. Elimina `pct`, `rf` y `ri`, añade `t`, `np` y `psd`, y cambia la búsqueda del registro en subdominios: ya no usa la Public Suffix List, sino un recorrido hacia arriba por el árbol DNS («DNS Tree Walk»).",
      ],
      en: [
        "It is published at `_dmarc.<domain>`. A message passes DMARC if SPF or DKIM passes and is \"aligned\" with the `From:` domain. The `p` policy says what to do when it fails: `none` (monitor only), `quarantine` (spam folder) or `reject`.",
        "`rua` requests daily aggregate reports: the way to learn who sends mail as the domain before tightening the policy. `sp` and `np` set the policy for subdomains and non-existent subdomains; `t=y` enables test mode.",
        "In May 2026 RFC 9989 replaced RFC 7489. It removes `pct`, `rf` and `ri`, adds `t`, `np` and `psd`, and changes how subdomains find their record: no more Public Suffix List, but a walk up the DNS tree (\"DNS Tree Walk\").",
      ],
    },
    example: '_dmarc.example.com.  300  IN  TXT  "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"',
    checks: {
      es: [
        "Que exista y sea único, siguiendo el DNS Tree Walk en subdominios.",
        "Política aplicable (`p` o `sp`).",
        "`sp=none`, modo prueba y etiquetas eliminadas.",
        "Si pide informes (`rua`).",
      ],
      en: [
        "That it exists and is unique, following the DNS Tree Walk for subdomains.",
        "Applicable policy (`p` or `sp`).",
        "`sp=none`, test mode and removed tags.",
        "Whether reports are requested (`rua`).",
      ],
    },
    refs: [rfc(9989), rfc(9989, "4.10"), rfc(9990), rfc(9991)],
  },
  {
    id: "mta-sts",
    group: "mail",
    title: { es: "MTA-STS", en: "MTA-STS" },
    summary: {
      es: "Obliga a que el correo que recibe el dominio llegue cifrado con TLS y a servidores verificados.",
      en: "Forces inbound mail to arrive encrypted with TLS and to verified servers.",
    },
    body: {
      es: [
        "El cifrado entre servidores de correo (STARTTLS) es opcional y un atacante en medio puede quitarlo. Con MTA-STS el dominio publica una política que los remitentes guardan en caché y respetan.",
        "Tiene dos partes: un TXT en `_mta-sts.<dominio>` con un identificador de versión, y el fichero de política en `https://mta-sts.<dominio>/.well-known/mta-sts.txt` con el modo (`enforce`, `testing` o `none`) y los MX permitidos.",
      ],
      en: [
        "Encryption between mail servers (STARTTLS) is optional and an attacker in the middle can strip it. With MTA-STS the domain publishes a policy that senders cache and honour.",
        "It has two parts: a TXT at `_mta-sts.<domain>` with a version id, and the policy file at `https://mta-sts.<domain>/.well-known/mta-sts.txt` with the mode (`enforce`, `testing` or `none`) and the allowed MX.",
      ],
    },
    example: '_mta-sts.example.com.  300  IN  TXT  "v=STSv1; id=20260925"',
    checks: {
      es: [
        "Si existe el TXT y el servidor de la política.",
        "En la app de escritorio, además, la política: sin redirecciones, con certificado válido, en modo `enforce` y cubriendo todos los MX (desde el navegador no se puede leer por CORS).",
      ],
      en: [
        "Whether the TXT and the policy server exist.",
        "In the desktop app, also the policy itself: no redirects, a valid certificate, `enforce` mode and every MX covered (a browser cannot read it because of CORS).",
      ],
    },
    refs: [rfc(8461)],
  },
  {
    id: "tls-rpt",
    group: "mail",
    title: { es: "TLS-RPT", en: "TLS-RPT" },
    summary: {
      es: "Pide informes cuando otros servidores no consiguen entregar correo al dominio por TLS.",
      en: "Requests reports when other servers fail to deliver mail to the domain over TLS.",
    },
    body: {
      es: ["Complementa a MTA-STS: sin informes, un fallo de TLS pasa desapercibido. Se publica en `_smtp._tls.<dominio>`."],
      en: ["It complements MTA-STS: without reports, a TLS failure goes unnoticed. It is published at `_smtp._tls.<domain>`."],
    },
    example: '_smtp._tls.example.com.  300  IN  TXT  "v=TLSRPTv1; rua=mailto:tlsrpt@example.com"',
    checks: { es: ["Si existe el registro."], en: ["Whether the record exists."] },
    refs: [rfc(8460)],
  },
  {
    id: "bimi",
    group: "mail",
    title: { es: "BIMI", en: "BIMI" },
    summary: {
      es: "Muestra el logotipo de la marca junto a los correos autenticados.",
      en: "Shows the brand logo next to authenticated messages.",
    },
    body: {
      es: [
        "Se publica en `default._bimi.<dominio>` con la URL de un logotipo SVG (`l=`) y, para algunos clientes como Gmail, un certificado de marca (`a=`).",
        "Exige DMARC en `quarantine` o `reject`. Todavía es un borrador del IETF, no un RFC.",
      ],
      en: [
        "It is published at `default._bimi.<domain>` with the URL of an SVG logo (`l=`) and, for some clients such as Gmail, a mark certificate (`a=`).",
        "It requires DMARC on `quarantine` or `reject`. It is still an IETF draft, not an RFC.",
      ],
    },
    example: 'default._bimi.example.com.  300  IN  TXT  "v=BIMI1; l=https://example.com/logo.svg"',
    checks: { es: ["Si existe el registro."], en: ["Whether the record exists."] },
    refs: [
      { label: "IETF · draft-brand-indicators-for-message-identification", url: "https://datatracker.ietf.org/doc/draft-brand-indicators-for-message-identification/" },
      { label: "BIMI Group", url: "https://bimigroup.org/" },
    ],
  },

  // ---------- Network and registration ----------
  {
    id: "ptr",
    group: "network",
    title: { es: "PTR y FCrDNS", en: "PTR and FCrDNS" },
    summary: {
      es: "DNS inverso: de una IP a un nombre. FCrDNS comprueba que ese nombre vuelve a la misma IP.",
      en: "Reverse DNS: from an IP to a name. FCrDNS checks that the name points back to the same IP.",
    },
    body: {
      es: [
        "Las IP se consultan en zonas especiales: `10.2.0.192.in-addr.arpa` para `192.0.2.10` e `ip6.arpa` para IPv6, cifra a cifra y al revés. El PTR lo gestiona quien tiene la IP (el proveedor de red o de hosting), no quien tiene el dominio.",
        "Para enviar correo es casi obligatorio: muchos servidores rechazan conexiones de IP sin PTR o cuyo PTR no vuelve a resolver a la misma IP (Forward-Confirmed reverse DNS).",
      ],
      en: [
        "IPs are looked up in special zones: `10.2.0.192.in-addr.arpa` for `192.0.2.10` and `ip6.arpa` for IPv6, digit by digit and reversed. The PTR is managed by whoever holds the IP (the network or hosting provider), not by the domain owner.",
        "It is almost mandatory for sending mail: many servers reject connections from IPs without a PTR, or whose PTR does not resolve back to the same IP (Forward-Confirmed reverse DNS).",
      ],
    },
    example: "10.2.0.192.in-addr.arpa.  3600  IN  PTR  mail.example.com.",
    checks: { es: ["Si la IP tiene PTR.", "Si el nombre vuelve a la IP (FCrDNS)."], en: ["Whether the IP has a PTR.", "Whether the name points back to the IP (FCrDNS)."] },
    refs: [rfc(1035, "3.5"), rfc(3596, "2.5"), rfc(1912, "2.1")],
  },
  {
    id: "asn",
    group: "network",
    title: { es: "AS y BGP", en: "AS and BGP" },
    summary: {
      es: "Qué red anuncia una IP en Internet y a quién pertenece.",
      en: "Which network announces an IP on the Internet and who it belongs to.",
    },
    body: {
      es: [
        "Internet es una red de redes. Cada una es un sistema autónomo (AS) con su número (ASN), y anuncia por BGP los bloques de direcciones (prefijos) que alcanza.",
        "Saber el AS dice quién aloja realmente un servicio: una web puede estar detrás de Cloudflare, en AWS o en un servidor propio.",
      ],
      en: [
        "The Internet is a network of networks. Each one is an autonomous system (AS) with its number (ASN), announcing through BGP the address blocks (prefixes) it can reach.",
        "The AS tells who actually hosts a service: a website may sit behind Cloudflare, on AWS or on its own server.",
      ],
    },
    checks: { es: ["AS, titular y prefijo anunciado, según RIPEstat."], en: ["AS, holder and announced prefix, from RIPEstat."] },
    refs: [
      rfc(4271),
      rfc(1930),
      { label: "RIPEstat · prefix-overview", url: "https://stat.ripe.net/docs/data-api/api-endpoints/prefix-overview" },
    ],
  },
  {
    id: "intel",
    group: "network",
    title: { es: "Exposición y reputación", en: "Exposure and reputation" },
    summary: {
      es: "Lo que servicios públicos de inteligencia (Shodan, AlienVault OTX) dicen de las IP y del dominio.",
      en: "What public intelligence services (Shodan, AlienVault OTX) say about the domain and its IPs.",
    },
    body: {
      es: [
        "Shodan escanea Internet de forma continua y publica qué puertos y servicios tiene abiertos cada IP. Es lo mismo que consulta un atacante antes de elegir por dónde entrar, sin tocar los servidores del dominio.",
        "AlienVault OTX reúne «pulsos»: listas de indicadores (dominios, IP, ficheros) que publican investigadores y usuarios. Aparecer en un pulso no es una prueba de nada: muchos citan dominios legítimos de pasada.",
      ],
      en: [
        "Shodan scans the Internet continuously and publishes which ports and services each IP has open. It is what an attacker looks up before choosing a way in, without touching the domain's servers.",
        "AlienVault OTX gathers \"pulses\": lists of indicators (domains, IPs, files) published by researchers and users. Being in a pulse proves nothing: many cite legitimate domains in passing.",
      ],
    },
    checks: {
      es: [
        "Puertos, etiquetas y CVE que Shodan InternetDB registra para las primeras IP del dominio, o para la IP auditada.",
        "Número de pulsos de OTX que mencionan el dominio (o la IP), los más recientes y las listas blancas de OTX. Todo es información atribuida a su fuente: nunca suma ni resta.",
      ],
      en: [
        "Ports, tags and CVEs that Shodan InternetDB records for the domain's first IPs, or for the audited IP.",
        "Number of OTX pulses mentioning the domain (or the IP), the most recent ones and OTX's allow-lists. All of it is information attributed to its source: it never adds or subtracts.",
      ],
    },
    refs: [
      { label: "Shodan InternetDB", url: "https://internetdb.shodan.io/" },
      { label: "AlienVault OTX · API", url: "https://otx.alienvault.com/api" },
      { label: "MITRE ATT&CK · T1596.005 Scan Databases", url: "https://attack.mitre.org/techniques/T1596/005/" },
    ],
  },
  {
    id: "rdap",
    group: "network",
    title: { es: "RDAP (el nuevo WHOIS)", en: "RDAP (the new WHOIS)" },
    summary: {
      es: "Datos de registro de dominios e IP en JSON: registrador, fechas, estado y titular.",
      en: "Registration data for domains and IPs in JSON: registrar, dates, status and holder.",
    },
    body: {
      es: [
        "RDAP sustituye a WHOIS con respuestas estructuradas por HTTPS. Cada registro de TLD y cada registro regional de IP (RIR) tiene su servidor; IANA publica cuál corresponde a cada uno.",
        "El estado `clientTransferProhibited` es el bloqueo de transferencia: impide que el dominio se mueva a otro registrador sin desbloquearlo antes.",
        "No todos los registros nacionales ofrecen RDAP todavía; `.es`, por ejemplo, sólo tiene WHOIS.",
      ],
      en: [
        "RDAP replaces WHOIS with structured answers over HTTPS. Every TLD registry and every regional IP registry (RIR) runs its own server; IANA publishes which one serves each.",
        "The `clientTransferProhibited` status is the transfer lock: it stops the domain being moved to another registrar without unlocking it first.",
        "Not every country registry offers RDAP yet; `.es`, for example, only has WHOIS.",
      ],
    },
    checks: {
      es: ["Registrador, alta y caducidad del dominio.", "Bloqueo de transferencia.", "Titular, red y país de una IP."],
      en: ["Registrar, creation and expiry of the domain.", "Transfer lock.", "Holder, network and country of an IP."],
    },
    refs: [
      rfc(9082),
      rfc(9083),
      rfc(9224),
      rfc(5731, "2.3"),
      { label: "ICANN · RDAP", url: "https://www.icann.org/rdap" },
      { label: "ICANN · EPP status codes", url: "https://www.icann.org/resources/pages/epp-status-codes-2014-06-16-en" },
    ],
  },
  {
    id: "special",
    group: "network",
    title: { es: "Direcciones de uso especial", en: "Special-purpose addresses" },
    summary: {
      es: "Rangos privados, de documentación o reservados que no se enrutan en Internet.",
      en: "Private, documentation or reserved ranges that are not routed on the Internet.",
    },
    body: {
      es: [
        "`10.0.0.0/8`, `172.16.0.0/12` y `192.168.0.0/16` son privadas; `100.64.0.0/10` es el espacio compartido de los operadores (CGNAT); `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` y `2001:db8::/32` están reservadas para documentación; `fc00::/7` es el equivalente privado en IPv6.",
        "No tienen PTR público ni datos de registro, así que la herramienta sólo las identifica.",
      ],
      en: [
        "`10.0.0.0/8`, `172.16.0.0/12` and `192.168.0.0/16` are private; `100.64.0.0/10` is carrier shared space (CGNAT); `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` and `2001:db8::/32` are reserved for documentation; `fc00::/7` is the IPv6 private equivalent.",
        "They have no public PTR or registration data, so the tool only identifies them.",
      ],
    },
    checks: { es: ["Qué tipo de rango es."], en: ["Which kind of range it is."] },
    refs: [
      rfc(1918),
      rfc(6598),
      rfc(5737),
      rfc(3849),
      rfc(4193),
      { label: "IANA · IPv4 Special-Purpose Registry", url: "https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml" },
      { label: "IANA · IPv6 Special-Purpose Registry", url: "https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml" },
    ],
  },

  // ---------- Tool ----------
  {
    id: "https",
    group: "web",
    title: { es: "HTTPS y HSTS", en: "HTTPS and HSTS" },
    summary: {
      es: "Que la web sólo se sirva cifrada y que los navegadores lo recuerden.",
      en: "That the site is only served encrypted, and that browsers remember it.",
    },
    body: {
      es: [
        "Una web con HTTPS cifra lo que viaja entre el visitante y el servidor. Pero si también responde por HTTP, quien escriba la dirección sin `https://` empieza sin cifrar, y alguien en medio (una wifi pública) puede impedir el salto.",
        "HSTS es una cabecera que dice al navegador «durante este tiempo, abre esta web sólo por HTTPS». Tras la primera visita ya no hay ventana sin cifrar.",
      ],
      en: [
        "A site with HTTPS encrypts what travels between visitor and server. But if it also answers over HTTP, whoever types the address without `https://` starts unencrypted, and someone in the middle (public Wi-Fi) can block the jump.",
        "HSTS is a header telling the browser \"for this long, open this site over HTTPS only\". After the first visit there is no unencrypted window left.",
      ],
    },
    example: "Strict-Transport-Security: max-age=31536000; includeSubDomains",
    checks: {
      es: ["Sólo en la app de escritorio: si `http://` redirige a `https://`.", "Si la respuesta HTTPS trae HSTS, con qué `max-age` y si cubre los subdominios."],
      en: ["Desktop app only: whether `http://` redirects to `https://`.", "Whether the HTTPS response carries HSTS, with which `max-age` and whether it covers subdomains."],
    },
    refs: [rfc(6797), rfc(6797, "7.2"), { label: "HSTS Preload List", url: "https://hstspreload.org/" }],
  },
  {
    id: "tls",
    group: "web",
    title: { es: "Certificado y versiones de TLS", en: "Certificate and TLS versions" },
    summary: {
      es: "Que el certificado de la web sea válido, de su nombre y no esté a punto de caducar, y que el servidor no acepte versiones obsoletas de TLS.",
      en: "That the site's certificate is valid, for its name and not about to expire, and that the server accepts no obsolete TLS versions.",
    },
    body: {
      es: [
        "El certificado demuestra que el servidor es quien dice ser. Si caduca, no es del nombre o no lo firmó una autoridad reconocida, el navegador muestra un aviso a pantalla completa.",
        "TLS 1.0 y 1.1 tienen debilidades conocidas y están declarados obsoletos desde 2021. Un servidor actual debería aceptar sólo TLS 1.2 y 1.3.",
      ],
      en: [
        "The certificate proves the server is who it claims to be. If it expires, is not for the name or was not signed by a recognised authority, the browser shows a full-page warning.",
        "TLS 1.0 and 1.1 have known weaknesses and have been deprecated since 2021. A current server should accept only TLS 1.2 and 1.3.",
      ],
    },
    checks: {
      es: ["Sólo en la app de escritorio: cadena de confianza, nombre y días hasta la caducidad.", "Apretones de manos ofreciendo sólo TLS 1.0 y sólo TLS 1.1: deben fallar."],
      en: ["Desktop app only: chain of trust, name and days to expiry.", "Handshakes offering only TLS 1.0 and only TLS 1.1: they must fail."],
    },
    refs: [rfc(8996), rfc(9525), rfc(9325), rfc(8446)],
  },
  {
    id: "headers",
    group: "web",
    title: { es: "Cabeceras de seguridad", en: "Security headers" },
    summary: {
      es: "Instrucciones que la web da al navegador para limitar lo que otra página o un código inyectado pueden hacer con ella.",
      en: "Instructions the site gives the browser to limit what another page or injected code can do with it.",
    },
    body: {
      es: [
        "No cambian la web: le dicen al navegador qué no permitir. `frame-ancestors` o `X-Frame-Options` impiden incrustarla en otra página (clickjacking); `nosniff` evita que un fichero se ejecute como código; la CSP limita de dónde se cargan scripts.",
        "La CSP es la más potente y la más delicada: mal configurada rompe la web. Por eso su ausencia se da como información, no como aviso.",
      ],
      en: [
        "They do not change the site: they tell the browser what not to allow. `frame-ancestors` or `X-Frame-Options` stop it being embedded in another page (clickjacking); `nosniff` stops a file running as code; the CSP limits where scripts load from.",
        "The CSP is the most powerful and the most delicate: misconfigured, it breaks the site. That is why its absence is information, not a warning.",
      ],
    },
    example: "Content-Security-Policy: default-src 'self'; frame-ancestors 'self'\nX-Content-Type-Options: nosniff\nReferrer-Policy: strict-origin-when-cross-origin",
    checks: {
      es: ["Sólo en la app de escritorio, en la página de inicio: protección contra incrustación, `nosniff`, CSP y `'unsafe-inline'`, `Referrer-Policy` y si el servidor anuncia su versión."],
      en: ["Desktop app only, on the home page: framing protection, `nosniff`, CSP and `'unsafe-inline'`, `Referrer-Policy` and whether the server announces its version."],
    },
    refs: [
      rfc(7034),
      { label: "W3C · Content Security Policy Level 3", url: "https://www.w3.org/TR/CSP3/" },
      { label: "WHATWG · Fetch (X-Content-Type-Options)", url: "https://fetch.spec.whatwg.org/#x-content-type-options-header" },
      { label: "OWASP Secure Headers Project", url: "https://owasp.org/www-project-secure-headers/" },
    ],
  },
  {
    id: "security-txt",
    group: "web",
    title: { es: "security.txt", en: "security.txt" },
    summary: {
      es: "Un fichero que dice a quién avisar si se encuentra una vulnerabilidad.",
      en: "A file saying whom to tell if a vulnerability is found.",
    },
    body: {
      es: ["Se publica en `/.well-known/security.txt`. Debe tener al menos un `Contact` (buzón o formulario) y un `Expires`, para que nadie use un contacto abandonado."],
      en: ["It is published at `/.well-known/security.txt`. It needs at least one `Contact` (mailbox or form) and one `Expires`, so nobody relies on an abandoned contact."],
    },
    example: "Contact: mailto:security@example.com\nExpires: 2027-11-01T00:00:00Z",
    checks: {
      es: ["Sólo en la app de escritorio: si existe como `text/plain` por HTTPS, si tiene `Contact` y un único `Expires`, y si ha caducado."],
      en: ["Desktop app only: whether it exists as `text/plain` over HTTPS, has `Contact` and a single `Expires`, and whether it has expired."],
    },
    refs: [rfc(9116), { label: "securitytxt.org", url: "https://securitytxt.org/" }],
  },
  {
    id: "doh",
    group: "tool",
    title: { es: "DNS sobre HTTPS", en: "DNS over HTTPS" },
    summary: {
      es: "Cómo consulta el DNS esta página sin servidor propio.",
      en: "How this page queries DNS without a server of its own.",
    },
    body: {
      es: [
        "Un navegador no puede enviar consultas DNS normales, pero sí peticiones HTTPS. Cloudflare y Google ofrecen una API de DNS sobre HTTPS en JSON que permite CORS, así que la página les pregunta directamente. Si Cloudflare falla, se reintenta con Google.",
        "Los dos resolvedores validan DNSSEC, por eso la herramienta puede leer el bit `AD`. Nada pasa por un servidor de Domain Auditor: sólo tu navegador y esos servicios.",
      ],
      en: [
        "A browser cannot send regular DNS queries, but it can make HTTPS requests. Cloudflare and Google offer a JSON DNS-over-HTTPS API that allows CORS, so the page asks them directly. If Cloudflare fails, Google is tried.",
        "Both resolvers validate DNSSEC, which is why the tool can read the `AD` bit. Nothing goes through a Domain Auditor server: only your browser and those services.",
      ],
    },
    checks: {
      es: [
        "Todas las consultas DNS del informe.",
        "Los registros clave (NS, MX, TXT, CAA, DS y DMARC) se preguntan también al otro resolvedor y se avisa si no coinciden.",
        "En «Datos en crudo» están todas las peticiones con su respuesta original y el comando `curl` para repetirlas.",
      ],
      en: [
        "Every DNS query in the report.",
        "Key records (NS, MX, TXT, CAA, DS and DMARC) are also asked to the other resolver, with a warning if they differ.",
        "\"Raw data\" lists every request with its original response and the `curl` command to repeat it.",
      ],
    },
    refs: [
      rfc(8484),
      { label: "Cloudflare · DNS over HTTPS (JSON)", url: "https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/dns-json/" },
      { label: "Google Public DNS · JSON API", url: "https://developers.google.com/speed/public-dns/docs/doh/json" },
    ],
  },
];

/** Wiki entry that explains a finding, by finding id prefix. */
export function wikiAnchor(findingId: string): string | undefined {
  const [area = "", rest = ""] = findingId.split(".");
  if (area === "dns") {
    if (rest.startsWith("ns") || rest === "provider" || rest === "no-zone") return "ns";
    if (rest.startsWith("caa")) return "caa";
    if (rest.startsWith("dnssec")) return "dnssec";
    if (rest === "hosting" || rest === "cdn") return "asn";
    if (rest.startsWith("soa")) return "soa";
    if (rest.startsWith("wildcard") || rest === "no-wildcard") return "cname";
    if (rest === "nxdomain" || rest === "servfail") return "rcode";
    if (rest.startsWith("resolvers")) return "doh";
    return "a-aaaa";
  }
  if (area === "reg") return "rdap";
  if (area === "int") return "txt";
  if (area === "web") return "cname";
  if (area === "hdr") return "headers";
  if (area === "sectxt") return "security-txt";
  if (area === "ip") {
    if (rest === "special") return "special";
    if (rest.includes("ptr") || rest.includes("fcrdns")) return "ptr";
    if (rest === "asn" || rest === "not-announced") return "asn";
    return "rdap";
  }
  return WIKI.some((e) => e.id === area) ? area : undefined;
}
