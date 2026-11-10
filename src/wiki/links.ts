/**
 * How the wiki entries fit together: two step-by-step journeys (a visit to a
 * website and an e-mail) and, for each entry, the related ones and why.
 */
import type { Lang } from "../i18n";

type T = Record<Lang, string>;

export interface JourneyStep {
  /** Wiki entry ids this step relies on. */
  ids: string[];
  text: T;
}

export interface Journey {
  id: string;
  title: T;
  intro: T;
  steps: JourneyStep[];
}

export const JOURNEYS: Journey[] = [
  {
    id: "web",
    title: { es: "Cuando alguien visita una web", en: "When someone visits a website" },
    intro: {
      es: "Antes de ver una sola página, el navegador resuelve una cadena de preguntas. Si falla cualquier eslabón, la web no carga o carga la de otro.",
      en: "Before a single page shows, the browser goes through a chain of questions. If any link fails, the site does not load, or someone else's does.",
    },
    steps: [
      {
        ids: ["rdap"],
        text: {
          es: "El dominio tiene que estar registrado y al día. El registro dice quién lo tiene, hasta cuándo y qué servidores DNS lo gestionan.",
          en: "The domain must be registered and current. The registry says who holds it, until when and which DNS servers manage it.",
        },
      },
      {
        ids: ["ns", "soa"],
        text: {
          es: "La zona superior (`.com`, `.es`…) remite al navegador a los servidores de nombres del dominio, que son los que tienen sus registros.",
          en: "The parent zone (`.com`, `.es`…) refers the browser to the domain's name servers, which hold its records.",
        },
      },
      {
        ids: ["dnssec"],
        text: {
          es: "Si el dominio usa DNSSEC, cada respuesta viene firmada y el resolvedor comprueba la firma desde la raíz hasta el dominio.",
          en: "If the domain uses DNSSEC, every answer is signed and the resolver checks the signature from the root down to the domain.",
        },
      },
      {
        ids: ["a-aaaa", "cname", "rcode"],
        text: {
          es: "Esos servidores devuelven la IP de la web (A/AAAA), a veces tras un alias (CNAME). Si el nombre no existe, la respuesta es NXDOMAIN.",
          en: "Those servers return the site's IP (A/AAAA), sometimes via an alias (CNAME). If the name does not exist, the answer is NXDOMAIN.",
        },
      },
      {
        ids: ["asn", "ptr"],
        text: {
          es: "Esa IP pertenece a una red (AS): un hosting, una CDN o un servidor propio. Su DNS inverso dice cómo se llama.",
          en: "That IP belongs to a network (AS): a hosting provider, a CDN or an own server. Its reverse DNS tells its name.",
        },
      },
      {
        ids: ["caa"],
        text: {
          es: "Al conectar por HTTPS, el navegador comprueba el certificado. CAA decidió antes qué autoridades podían emitirlo.",
          en: "When connecting over HTTPS, the browser checks the certificate. CAA decided beforehand which authorities could issue it.",
        },
      },
      {
        ids: ["https", "tls"],
        text: {
          es: "Se abre la conexión cifrada: el servidor presenta su certificado y ambos acuerdan una versión de TLS. HSTS hace que el navegador no vuelva a intentarlo sin cifrar.",
          en: "The encrypted connection opens: the server presents its certificate and both agree on a TLS version. HSTS makes the browser never try unencrypted again.",
        },
      },
      {
        ids: ["headers", "security-txt"],
        text: {
          es: "Con la página llegan sus normas para el navegador (cabeceras de seguridad) y, aparte, un contacto para quien encuentre un fallo.",
          en: "With the page come its rules for the browser (security headers) and, separately, a contact for whoever finds a flaw.",
        },
      },
      {
        ids: ["ct"],
        text: {
          es: "Ese certificado queda publicado en Certificate Transparency: cualquiera puede ver que existe, para qué nombres y quién lo emitió.",
          en: "That certificate is published in Certificate Transparency: anyone can see that it exists, for which names and who issued it.",
        },
      },
      {
        ids: ["intel"],
        text: {
          es: "Y los escáneres públicos, como Shodan, registran qué servicios responden en sus IP: lo mismo que mira un atacante antes de actuar.",
          en: "And public scanners such as Shodan record which services answer on its IPs: the same thing an attacker looks at before acting.",
        },
      },
    ],
  },
  {
    id: "mail",
    title: { es: "Cuando un dominio envía un correo", en: "When a domain sends an e-mail" },
    intro: {
      es: "El servidor que recibe el correo no se fía del remitente que aparece en el mensaje: lo comprueba en el DNS del dominio. Así se distingue el correo legítimo de uno que lo suplanta.",
      en: "The receiving server does not trust the sender shown in the message: it checks the domain's DNS. That is how genuine mail is told apart from a spoof.",
    },
    steps: [
      {
        ids: ["ptr"],
        text: {
          es: "El servidor de salida se conecta. El receptor mira el nombre de su IP (PTR) y que ese nombre vuelva a la IP (FCrDNS).",
          en: "The outgoing server connects. The receiver looks up its IP's name (PTR) and checks the name points back to the IP (FCrDNS).",
        },
      },
      {
        ids: ["spf", "txt"],
        text: {
          es: "SPF: ¿está esa IP en la lista de servidores autorizados del dominio?",
          en: "SPF: is that IP on the domain's list of authorised servers?",
        },
      },
      {
        ids: ["dkim"],
        text: {
          es: "DKIM: ¿la firma del mensaje coincide con la clave pública que publica el dominio? Así se sabe que no lo han modificado.",
          en: "DKIM: does the message signature match the public key the domain publishes? That proves it was not altered.",
        },
      },
      {
        ids: ["dmarc"],
        text: {
          es: "DMARC une las dos: basta con que SPF o DKIM pasen y coincidan con el dominio del `From:` visible. Si no, se aplica la política del dominio: entregar, spam o rechazar.",
          en: "DMARC ties both together: SPF or DKIM must pass and match the visible `From:` domain. If not, the domain's policy applies: deliver, spam or reject.",
        },
      },
      {
        ids: ["dmarc", "bimi"],
        text: {
          es: "Con DMARC aplicado, algunos clientes muestran el logo de la marca (BIMI). Cada día, el receptor envía al dominio un informe con lo que ha visto.",
          en: "With DMARC enforced, some clients show the brand's logo (BIMI). Every day the receiver sends the domain a report of what it saw.",
        },
      },
    ],
  },
  {
    id: "inbound",
    title: { es: "Cuando alguien escribe al dominio", en: "When someone writes to the domain" },
    intro: {
      es: "Recibir correo es el camino inverso: ahora es el remitente quien consulta el DNS del dominio para saber dónde y cómo entregarlo.",
      en: "Receiving mail is the reverse path: now the sender queries the domain's DNS to know where and how to deliver.",
    },
    steps: [
      {
        ids: ["mx"],
        text: {
          es: "El remitente busca los MX: los servidores que reciben el correo del dominio, por orden de prioridad.",
          en: "The sender looks up the MX: the servers that receive the domain's mail, by priority.",
        },
      },
      {
        ids: ["mta-sts"],
        text: {
          es: "Si el dominio publica MTA-STS, el remitente está obligado a cifrar la conexión y a comprobar el certificado de sus MX.",
          en: "If the domain publishes MTA-STS, the sender must encrypt the connection and check its MX's certificate.",
        },
      },
      {
        ids: ["tls-rpt"],
        text: {
          es: "Si algo falla en ese cifrado, TLS-RPT hace que el remitente avise al dominio.",
          en: "If that encryption fails, TLS-RPT makes the sender alert the domain.",
        },
      },
    ],
  },
];

export interface Related {
  id: string;
  why: T;
}

export const RELATED: Record<string, Related[]> = {
  "a-aaaa": [
    { id: "cname", why: { es: "Un alias lleva a otro nombre que es el que tiene el A/AAAA.", en: "An alias leads to another name that holds the A/AAAA." } },
    { id: "asn", why: { es: "Dice a qué red pertenece la IP a la que apunta el nombre.", en: "Tells which network the IP the name points to belongs to." } },
    { id: "ptr", why: { es: "Es el camino inverso: de la IP al nombre.", en: "It is the reverse path: from IP to name." } },
  ],
  cname: [
    { id: "a-aaaa", why: { es: "Al final de la cadena de alias siempre hay un A/AAAA.", en: "There is always an A/AAAA at the end of the alias chain." } },
    { id: "mx", why: { es: "Un MX no debe apuntar a un CNAME.", en: "An MX must not point to a CNAME." } },
    { id: "caa", why: { es: "El CAA del destino del alias también cuenta.", en: "The alias target's CAA also counts." } },
  ],
  ns: [
    { id: "rdap", why: { es: "Los NS se cambian en el registrador, que aparece en RDAP.", en: "NS are changed at the registrar, shown in RDAP." } },
    { id: "soa", why: { es: "El SOA identifica al servidor primario de la zona.", en: "The SOA names the zone's primary server." } },
    { id: "dnssec", why: { es: "Al cambiar de NS hay que actualizar el DS o el dominio deja de resolver.", en: "When changing NS the DS must be updated or the domain stops resolving." } },
  ],
  soa: [
    { id: "ns", why: { es: "Los NS reparten la zona que describe el SOA.", en: "NS serve the zone the SOA describes." } },
    { id: "rcode", why: { es: "Su último campo fija cuánto se recuerda un NXDOMAIN.", en: "Its last field sets how long an NXDOMAIN is remembered." } },
  ],
  txt: [
    { id: "spf", why: { es: "SPF es un TXT en la raíz del dominio.", en: "SPF is a TXT at the domain apex." } },
    { id: "dmarc", why: { es: "DMARC es un TXT en `_dmarc`.", en: "DMARC is a TXT at `_dmarc`." } },
    { id: "dkim", why: { es: "Las claves DKIM son TXT en `_domainkey`.", en: "DKIM keys are TXT at `_domainkey`." } },
  ],
  rcode: [
    { id: "dnssec", why: { es: "Una firma DNSSEC rota se manifiesta como SERVFAIL.", en: "A broken DNSSEC signature shows up as SERVFAIL." } },
    { id: "soa", why: { es: "Marca cuánto tiempo se guarda una respuesta negativa.", en: "Sets how long a negative answer is kept." } },
  ],
  dnssec: [
    { id: "ns", why: { es: "Las claves las publica el proveedor DNS.", en: "The DNS provider publishes the keys." } },
    { id: "rdap", why: { es: "El DS se publica a través del registrador.", en: "The DS is published through the registrar." } },
    { id: "rcode", why: { es: "Si la cadena no cuadra, el resultado es SERVFAIL.", en: "If the chain does not match, the result is SERVFAIL." } },
    { id: "doh", why: { es: "El bit AD que lee Domain Auditor lo pone el resolvedor DoH.", en: "The AD bit Domain Auditor reads is set by the DoH resolver." } },
  ],
  ct: [
    { id: "caa", why: { es: "Los emisores de los certificados vigentes se comparan con el CAA.", en: "Issuers of the certificates in force are compared with the CAA." } },
    { id: "a-aaaa", why: { es: "Cada subdominio se resuelve para ver si su destino existe.", en: "Each subdomain is resolved to see whether its target exists." } },
  ],
  caa: [
    { id: "ct", why: { es: "Certificate Transparency muestra qué autoridades han emitido de verdad.", en: "Certificate Transparency shows which authorities have actually issued." } },
    { id: "a-aaaa", why: { es: "Protege el HTTPS de la web a la que apunta el dominio.", en: "It protects HTTPS for the site the domain points to." } },
    { id: "dnssec", why: { es: "Sin DNSSEC, un CAA se podría falsificar en la respuesta.", en: "Without DNSSEC, a CAA answer could be forged." } },
    { id: "mta-sts", why: { es: "MTA-STS también depende de un certificado válido, en `mta-sts.`", en: "MTA-STS also relies on a valid certificate, on `mta-sts.`" } },
  ],
  mx: [
    { id: "spf", why: { es: "Con el mecanismo `mx`, los servidores de entrada también pueden enviar.", en: "With the `mx` mechanism, the inbound servers may also send." } },
    { id: "mta-sts", why: { es: "Su política enumera los MX permitidos.", en: "Its policy lists the allowed MX." } },
    { id: "dmarc", why: { es: "Un dominio sin MX y sin correo se protege con SPF `-all` y DMARC `reject`.", en: "A domain with no MX and no mail is protected with SPF `-all` and DMARC `reject`." } },
  ],
  spf: [
    { id: "dmarc", why: { es: "DMARC usa el resultado de SPF, pero sólo si está alineado con el `From:`.", en: "DMARC uses the SPF result, but only if aligned with `From:`." } },
    { id: "dkim", why: { es: "Es la otra comprobación: si SPF falla por un reenvío, DKIM puede salvar el mensaje.", en: "It is the other check: if SPF fails on a forward, DKIM can save the message." } },
    { id: "txt", why: { es: "Se publica como TXT, y sólo puede haber uno.", en: "It is published as a TXT, and there can only be one." } },
    { id: "mx", why: { es: "El proveedor de correo marca qué `include:` hace falta.", en: "The mail provider sets which `include:` is needed." } },
  ],
  dkim: [
    { id: "dmarc", why: { es: "DMARC exige que el dominio de la firma coincida con el del `From:`.", en: "DMARC requires the signing domain to match the `From:` domain." } },
    { id: "spf", why: { es: "Se complementan: DKIM sobrevive a los reenvíos, SPF no.", en: "They complement each other: DKIM survives forwarding, SPF does not." } },
  ],
  dmarc: [
    { id: "spf", why: { es: "Una de sus dos fuentes de verdad.", en: "One of its two sources of truth." } },
    { id: "dkim", why: { es: "La otra fuente, y la más fiable.", en: "The other source, and the more reliable one." } },
    { id: "bimi", why: { es: "Sólo funciona con DMARC en `quarantine` o `reject`.", en: "Only works with DMARC on `quarantine` or `reject`." } },
    { id: "txt", why: { es: "Se publica como TXT en `_dmarc`.", en: "Published as a TXT at `_dmarc`." } },
  ],
  "mta-sts": [
    { id: "mx", why: { es: "La política lista los MX; si cambia el proveedor, hay que actualizarla.", en: "The policy lists the MX; if the provider changes, it must be updated." } },
    { id: "tls-rpt", why: { es: "Avisa de los fallos: conviene activarlos a la vez.", en: "It reports failures: best enabled together." } },
    { id: "caa", why: { es: "El subdominio `mta-sts.` necesita un certificado válido.", en: "The `mta-sts.` subdomain needs a valid certificate." } },
  ],
  "tls-rpt": [
    { id: "mta-sts", why: { es: "Es su compañero natural: MTA-STS obliga, TLS-RPT informa.", en: "Its natural partner: MTA-STS enforces, TLS-RPT reports." } },
    { id: "dmarc", why: { es: "Funciona igual que los informes `rua` de DMARC, pero para el cifrado.", en: "Works like DMARC `rua` reports, but for encryption." } },
  ],
  bimi: [
    { id: "dmarc", why: { es: "Requisito imprescindible: DMARC aplicado.", en: "Hard requirement: DMARC enforced." } },
    { id: "dkim", why: { es: "Los mensajes deben ir firmados para pasar DMARC con fiabilidad.", en: "Messages must be signed to pass DMARC reliably." } },
  ],
  ptr: [
    { id: "a-aaaa", why: { es: "FCrDNS comprueba que el A/AAAA del nombre vuelve a la IP.", en: "FCrDNS checks the name's A/AAAA points back to the IP." } },
    { id: "asn", why: { es: "Quien gestiona el PTR es el dueño de la red de la IP.", en: "Whoever runs the IP's network manages the PTR." } },
    { id: "spf", why: { es: "Los receptores lo miran junto a SPF al recibir un correo.", en: "Receivers check it alongside SPF when mail arrives." } },
  ],
  asn: [
    { id: "a-aaaa", why: { es: "Parte de la IP a la que apunta el dominio.", en: "Starts from the IP the domain points to." } },
    { id: "rdap", why: { es: "RDAP da el titular y el rango de la IP.", en: "RDAP gives the IP's holder and range." } },
    { id: "special", why: { es: "Las direcciones privadas no pertenecen a ningún AS público.", en: "Private addresses belong to no public AS." } },
  ],
  intel: [
    { id: "asn", why: { es: "Las IP que se consultan son las del dominio; su AS dice de quién son.", en: "The IPs queried are the domain's; their AS tells whose they are." } },
    { id: "ct", why: { es: "Certificate Transparency es otra fuente pública que un atacante usa para reconocer el dominio.", en: "Certificate Transparency is another public source an attacker uses to map the domain." } },
  ],
  rdap: [
    { id: "ns", why: { es: "El registrador es donde se cambian los NS.", en: "The registrar is where the NS are changed." } },
    { id: "dnssec", why: { es: "El DS de DNSSEC también se publica a través del registrador.", en: "The DNSSEC DS is also published through the registrar." } },
    { id: "asn", why: { es: "Para una IP, RDAP da la red; el AS dice quién la anuncia.", en: "For an IP, RDAP gives the network; the AS says who announces it." } },
  ],
  special: [
    { id: "asn", why: { es: "Por eso no tienen AS ni datos públicos.", en: "That is why they have no AS or public data." } },
    { id: "ptr", why: { es: "Su DNS inverso sólo existe dentro de la red local.", en: "Their reverse DNS only exists inside the local network." } },
  ],
  doh: [
    { id: "dnssec", why: { es: "Los resolvedores DoH validan DNSSEC y devuelven el bit AD.", en: "DoH resolvers validate DNSSEC and return the AD bit." } },
    { id: "rcode", why: { es: "Las respuestas JSON incluyen el código de respuesta.", en: "JSON answers include the response code." } },
  ],
  https: [
    { id: "tls", why: { es: "HTTPS depende de un certificado válido.", en: "HTTPS relies on a valid certificate." } },
    { id: "headers", why: { es: "HSTS es una cabecera más; las demás protegen la página ya cifrada.", en: "HSTS is one more header; the others protect the already encrypted page." } },
  ],
  tls: [
    { id: "caa", why: { es: "CAA decide qué autoridades pueden emitir ese certificado.", en: "CAA decides which authorities may issue that certificate." } },
    { id: "ct", why: { es: "Cada certificado emitido queda en Certificate Transparency.", en: "Every issued certificate is logged in Certificate Transparency." } },
    { id: "https", why: { es: "Sin certificado válido no hay HTTPS útil.", en: "Without a valid certificate there is no useful HTTPS." } },
  ],
  headers: [
    { id: "https", why: { es: "Las cabeceras sólo protegen de verdad sobre HTTPS.", en: "Headers only truly protect over HTTPS." } },
    { id: "security-txt", why: { es: "Otra forma de que la web hable de su seguridad.", en: "Another way for the site to speak about its security." } },
  ],
  "security-txt": [
    { id: "headers", why: { es: "Ambos se comprueban sobre la web, por HTTPS.", en: "Both are checked on the site, over HTTPS." } },
    { id: "https", why: { es: "El fichero debe servirse por HTTPS.", en: "The file must be served over HTTPS." } },
  ],
};
