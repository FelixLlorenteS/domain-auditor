import type { Lang } from "../i18n";

/**
 * What an attacker can do when a control is missing or weak, and what it
 * prevents when it is in place, with the MITRE ATT&CK techniques involved.
 * IDs, names and tactics checked against attack.mitre.org (September 2026):
 * T1656 Impersonation is now T1684.001, under the Stealth tactic.
 */

export interface Technique {
  id: string;
  name: string;
  tactic: string;
}

const T: Record<string, Technique> = {
  T1566: { id: "T1566", name: "Phishing", tactic: "Initial Access" },
  "T1684.001": { id: "T1684.001", name: "Social Engineering: Impersonation", tactic: "Stealth" },
  T1557: { id: "T1557", name: "Adversary-in-the-Middle", tactic: "Credential Access, Collection" },
  T1040: { id: "T1040", name: "Network Sniffing", tactic: "Credential Access, Discovery" },
  "T1588.004": { id: "T1588.004", name: "Obtain Capabilities: Digital Certificates", tactic: "Resource Development" },
  "T1583.001": { id: "T1583.001", name: "Acquire Infrastructure: Domains", tactic: "Resource Development" },
  "T1584.001": { id: "T1584.001", name: "Compromise Infrastructure: Domains", tactic: "Resource Development" },
  "T1584.002": { id: "T1584.002", name: "Compromise Infrastructure: DNS Server", tactic: "Resource Development" },
  T1498: { id: "T1498", name: "Network Denial of Service", tactic: "Impact" },
  T1199: { id: "T1199", name: "Trusted Relationship", tactic: "Initial Access" },
  "T1596.005": { id: "T1596.005", name: "Search Open Technical Databases: Scan Databases", tactic: "Reconnaissance" },
};

export const techniqueUrl = (id: string) => `https://attack.mitre.org/techniques/${id.replace(".", "/")}/`;

interface Risk {
  techniques: string[];
  es: { risk: string; prevents: string };
  en: { risk: string; prevents: string };
}

/**
 * Techniques are only listed where the link is direct (a gap an attacker can
 * use as such); defence-in-depth controls (CAA, TLS-RPT…) keep their risk text
 * without a technique, so severity is not inflated.
 */
const RISKS: Record<string, Risk> = {
  spf: {
    techniques: ["T1566", "T1684.001"],
    es: {
      risk: "Con un SPF ausente, permisivo (`+all`) o incompleto, los receptores no pueden distinguir los servidores legítimos de los de un tercero que use el dominio: facilita la suplantación o hace fallar el correo propio. SPF protege el remitente del sobre; el que ve el usuario lo protege DMARC.",
      prevents: "Los receptores saben qué servidores pueden enviar en nombre del dominio. Junto con DMARC, lo que llega desde otros servidores se marca o se rechaza.",
    },
    en: {
      risk: "With a missing, permissive (`+all`) or incomplete SPF, receivers cannot tell legitimate servers from those of a third party using the domain: it makes spoofing easier or makes the domain's own mail fail. SPF protects the envelope sender; the one users see is protected by DMARC.",
      prevents: "Receivers know which servers may send for the domain. Together with DMARC, mail from other servers is flagged or rejected.",
    },
  },
  dkim: {
    techniques: ["T1566", "T1684.001"],
    es: {
      risk: "Si el dominio envía correo sin una firma DKIM verificable, el receptor no puede comprobar que el mensaje no se ha alterado, y sólo podría superar DMARC con SPF alineado, que puede fallar en reenvíos y otros flujos indirectos. Por eso, cuando se usa correo, se recomiendan SPF y DKIM a la vez.",
      prevents: "Cada mensaje va firmado: se detecta cualquier alteración y el correo supera DMARC aunque se reenvíe.",
    },
    en: {
      risk: "If the domain sends mail without a verifiable DKIM signature, the receiver cannot check that the message was not altered, and it could only pass DMARC through aligned SPF, which may fail on forwarding and other indirect flows. That is why SPF and DKIM together are recommended when mail is used.",
      prevents: "Every message is signed: any alteration is detected and mail passes DMARC even when forwarded.",
    },
  },
  dmarc: {
    techniques: ["T1566", "T1684.001"],
    es: {
      risk: "Sin DMARC aplicado (`p=none` o sin registro), el propietario no expresa ninguna preferencia de tratamiento para el correo que usa el dominio en el remitente visible y falla la validación. Un atacante puede intentar usarlo en phishing, fraude del CEO o facturas falsas; que llegue a la bandeja depende sólo de los filtros de cada receptor.",
      prevents: "Con `quarantine` o `reject`, el dominio declara no legítimo el correo que lo suplanta en el remitente visible, y los receptores usan esa preferencia para mandarlo a spam o rechazarlo. Los informes muestran quién intenta enviar en su nombre.",
    },
    en: {
      risk: "Without DMARC enforced (`p=none` or no record), the owner expresses no handling preference for mail that uses the domain in the visible sender and fails validation. An attacker can try to use it for phishing, CEO fraud or fake invoices; whether it reaches the inbox depends only on each receiver's filters.",
      prevents: "With `quarantine` or `reject`, the domain declares mail spoofing its visible sender not legitimate, and receivers use that preference to send it to spam or reject it. Reports show who tries to send on its behalf.",
    },
  },
  "mta-sts": {
    techniques: ["T1557", "T1040"],
    es: {
      risk: "Sin MTA-STS, el cifrado entre servidores de correo es oportunista: quien logre situarse en la ruta de red podría eliminar STARTTLS y leer o modificar el correo entrante. Exige una posición privilegiada en la red.",
      prevents: "Obliga a entregar con TLS y certificado válido a los MX publicados: un intento de rebaja hace fallar la entrega en lugar de enviarla en claro.",
    },
    en: {
      risk: "Without MTA-STS, encryption between mail servers is opportunistic: whoever manages to sit on the network path could strip STARTTLS and read or alter incoming mail. It requires a privileged network position.",
      prevents: "Delivery must use TLS with a valid certificate to the published MX: a downgrade attempt makes delivery fail instead of going out in clear text.",
    },
  },
  dane: {
    techniques: ["T1557"],
    es: {
      risk: "Sin DANE ni MTA-STS, el cifrado del correo entrante es oportunista y un intermediario en la red podría rebajarlo. DANE es la alternativa basada en DNSSEC a MTA-STS.",
      prevents: "Los remitentes que admiten DANE sólo entregan si el certificado del MX coincide con el TLSA firmado.",
    },
    en: {
      risk: "Without DANE or MTA-STS, inbound mail encryption is opportunistic and an on-path attacker could downgrade it. DANE is the DNSSEC-based alternative to MTA-STS.",
      prevents: "Senders that support DANE only deliver if the MX certificate matches the signed TLSA.",
    },
  },
  wildcard: {
    techniques: [],
    es: {
      risk: "Con un comodín, cualquier nombre inventado resuelve al mismo destino. Si ese destino es un servicio de terceros (por ejemplo, un CNAME comodín a una plataforma), quien pueda dar de alta nombres allí podría servir contenido bajo cualquier subdominio. También dificulta ver qué subdominios existen de verdad.",
      prevents: "Sólo resuelven los nombres que existen.",
    },
    en: {
      risk: "With a wildcard, any made-up name resolves to the same target. If that target is a third-party service (for instance, a wildcard CNAME to a platform), whoever can register names there could serve content under any subdomain. It also makes it harder to see which subdomains really exist.",
      prevents: "Only names that exist resolve.",
    },
  },
  "tls-rpt": {
    techniques: [],
    es: {
      risk: "Sin TLS-RPT nadie recibe aviso de los fallos de cifrado: un intento de rebaja o un certificado caducado en el MX pasan inadvertidos.",
      prevents: "Los remitentes envían informes diarios de fallos TLS, que ayudan a detectar intentos de interceptación.",
    },
    en: {
      risk: "Without TLS-RPT nobody is told about encryption failures: a downgrade attempt or an expired MX certificate goes unnoticed.",
      prevents: "Senders deliver daily reports of TLS failures, which help to detect interception attempts.",
    },
  },
  ns: {
    techniques: [],
    es: {
      risk: "Con un único servidor DNS, su caída o una denegación de servicio deja sin resolver la web y el correo.",
      prevents: "Varios servidores, a ser posible en redes distintas, mantienen el dominio accesible si uno cae.",
    },
    en: {
      risk: "With a single DNS server, an outage or a denial of service leaves the website and mail unresolvable.",
      prevents: "Several servers, preferably on different networks, keep the domain reachable if one fails.",
    },
  },
  dnssec: {
    techniques: ["T1557"],
    es: {
      risk: "Sin DNSSEC, las respuestas no llevan firma. Un envenenamiento de caché o una manipulación del tráfico DNS no se puede detectar, y podría desviar la web o el correo. Son ataques difíciles de ejecutar hoy, pero DNSSEC elimina esa posibilidad en los resolvedores que validan.",
      prevents: "Añade integridad criptográfica: un resolvedor que valida DNSSEC descarta las respuestas manipuladas.",
    },
    en: {
      risk: "Without DNSSEC, answers carry no signature. Cache poisoning or tampering with DNS traffic cannot be detected and could divert the website or mail. These attacks are hard to carry out today, but DNSSEC removes the possibility on validating resolvers.",
      prevents: "It adds cryptographic integrity: a DNSSEC-validating resolver discards tampered answers.",
    },
  },
  caa: {
    techniques: [],
    es: {
      risk: "Sin CAA, cualquier autoridad de certificación puede emitir para el dominio, aunque siempre tras validar que quien lo pide lo controla. CAA es defensa en profundidad: reduce el riesgo de una emisión por error o por una validación engañada en una autoridad que no se usa.",
      prevents: "Sólo las autoridades indicadas pueden emitir certificados; las demás deben negarse.",
    },
    en: {
      risk: "Without CAA, any certificate authority may issue for the domain, though always after validating that the requester controls it. CAA is defence in depth: it reduces the risk of a mistaken issuance, or one obtained by fooling validation, at an authority that is not used.",
      prevents: "Only the listed authorities may issue certificates; the rest must refuse.",
    },
  },
  expiry: {
    techniques: ["T1583.001"],
    es: {
      risk: "Si el dominio caduca, cualquiera puede registrarlo: recibiría su correo, podría restablecer contraseñas de cuentas asociadas a esas direcciones y servir su web.",
      prevents: "Mientras esté vigente, y mejor con renovación automática, nadie más puede registrarlo.",
    },
    en: {
      risk: "If the domain expires, anyone can register it: they would receive its mail, could reset passwords of accounts tied to its addresses and serve its website.",
      prevents: "While it is current, ideally with auto-renewal, nobody else can register it.",
    },
  },
  lock: {
    techniques: ["T1584.001"],
    es: {
      risk: "Sin bloqueo de transferencia, quien consiga acceso a la cuenta del registrador (o engañe a su soporte) puede llevarse el dominio y controlar su DNS.",
      prevents: "Para transferirlo hay que desbloquearlo antes, lo que da margen para detectar el intento.",
    },
    en: {
      risk: "Without a transfer lock, whoever gains access to the registrar account (or tricks its support) can move the domain away and control its DNS.",
      prevents: "It has to be unlocked before a transfer, which leaves time to spot the attempt.",
    },
  },
  exposure: {
    techniques: ["T1596.005"],
    es: {
      risk: "Los servicios que escanean Internet publican qué puertos y versiones tiene abiertos cada IP. Un atacante los consulta antes de atacar para elegir por dónde entrar, sin tocar los servidores del dominio.",
      prevents: "Revisar lo mismo que ve un atacante permite cerrar los servicios que no deberían estar expuestos.",
    },
    en: {
      risk: "Services that scan the Internet publish which ports and versions each IP has open. An attacker looks them up before attacking to choose a way in, without touching the domain's servers.",
      prevents: "Reviewing what an attacker sees lets you close services that should not be exposed.",
    },
  },
  integrations: {
    techniques: ["T1199"],
    es: {
      risk: "Cada servicio verificado o autorizado a enviar correo es un tercero de confianza: si se compromete su cuenta, o queda una verificación de un servicio abandonado, puede servir para enviar correo legítimo del dominio o acceder a sus datos.",
      prevents: "El inventario permite revisar que cada tercero siga en uso y retirar los que no.",
    },
    en: {
      risk: "Each verified service or service allowed to send mail is a trusted third party: if its account is compromised, or a verification of an abandoned service remains, it can be used to send legitimate mail for the domain or reach its data.",
      prevents: "The inventory lets you check that each third party is still in use and remove the rest.",
    },
  },
  subdomains: {
    techniques: ["T1584.001"],
    es: {
      risk: "Un subdominio con un CNAME que apunta a un recurso borrado puede reclamarlo cualquiera en ese servicio: serviría páginas de phishing con el nombre del dominio, recibiría correo o leería cookies de sesión.",
      prevents: "Ningún subdominio publicado apunta a un recurso que otro pueda registrar.",
    },
    en: {
      risk: "A subdomain whose CNAME points to a deleted resource can be claimed by anyone at that service: it would serve phishing pages under the domain's name, receive mail or read session cookies.",
      prevents: "No published subdomain points to a resource someone else could register.",
    },
  },
  certificates: {
    techniques: ["T1588.004"],
    es: {
      risk: "Un certificado válido emitido sin autorización permite suplantar la web o un subdominio con HTTPS, sin avisos en el navegador.",
      prevents: "Todo certificado en vigor procede de las autoridades que el dominio permite.",
    },
    en: {
      risk: "A valid certificate issued without authorisation lets someone impersonate the website or a subdomain over HTTPS, with no browser warning.",
      prevents: "Every certificate in force comes from the authorities the domain allows.",
    },
  },
  resolvers: {
    techniques: [],
    es: {
      risk: "Si dos resolvedores independientes dan respuestas distintas, puede ser un cambio que se está propagando, pero también un DNS alterado o secuestrado.",
      prevents: "Que coincidan descarta que un único proveedor esté devolviendo datos alterados.",
    },
    en: {
      risk: "If two independent resolvers give different answers, it may be a change still propagating, but also altered or hijacked DNS.",
      prevents: "Agreement rules out a single provider returning altered data.",
    },
  },
};

export interface RiskView {
  text: string;
  techniques: Technique[];
}

/** Risk when the control is not fine; what it prevents when it is. */
export function riskOf(controlId: string, fine: boolean, lang: Lang): RiskView | null {
  const r = RISKS[controlId];
  if (!r) return null;
  return { text: fine ? r[lang].prevents : r[lang].risk, techniques: r.techniques.map((id) => T[id]!) };
}

export const ATTACK_NOTICE =
  "© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. MITRE ATT&CK® and ATT&CK® are registered trademarks of The MITRE Corporation.";
