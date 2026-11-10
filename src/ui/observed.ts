import type { Finding, RecordRow, Section } from "../core/types";
import type { Lang } from "../i18n";

/**
 * "What is there / what should be there" for the technical detail of a finding.
 * What is there comes from the records the audit collected for that section
 * (live answers, nothing rewritten); what should be there is the fix the audit
 * suggested or, failing that, what the standard asks for.
 */

type Key = "spf" | "dmarc" | "dkim" | "mx" | "mta-sts" | "tls-rpt" | "bimi" | "ns" | "caa" | "dnssec" | "address" | "ipv6" | "ptr" | "subdomains" | "hosting" | "txt" | "dane" | "wildcard";

interface Rule {
  /** Record queried, as shown when nothing was found. `{d}` is the domain. */
  where: string;
  match: (r: RecordRow, domain: string) => boolean;
}

const RULES: Record<Key, Rule> = {
  spf: { where: "{d} TXT", match: (r, d) => r.type === "TXT" && r.name === d && /^v=spf1(\s|$)/i.test(r.data) },
  dmarc: { where: "_dmarc.{d} TXT", match: (r) => r.type === "TXT" && r.name.startsWith("_dmarc.") },
  dkim: { where: "<selector>._domainkey.{d} TXT", match: (r) => r.name.includes("._domainkey.") },
  mx: { where: "{d} MX", match: (r) => r.type === "MX" },
  "mta-sts": { where: "_mta-sts.{d} TXT", match: (r) => r.name.startsWith("_mta-sts.") },
  "tls-rpt": { where: "_smtp._tls.{d} TXT", match: (r) => r.name.startsWith("_smtp._tls.") },
  bimi: { where: "default._bimi.{d} TXT", match: (r) => r.name.includes("._bimi.") },
  ns: { where: "{d} NS", match: (r) => r.type === "NS" },
  caa: { where: "{d} CAA", match: (r) => r.type === "CAA" },
  dnssec: { where: "{d} DS", match: (r) => r.type === "DS" },
  address: { where: "{d} A / AAAA", match: (r, d) => r.name === d && (r.type === "A" || r.type === "AAAA" || r.type === "CNAME") },
  ipv6: { where: "{d} AAAA", match: (r, d) => r.name === d && r.type === "AAAA" },
  hosting: { where: "{d} / www.{d} A", match: (r, d) => (r.name === d || r.name === `www.${d}`) && ["A", "AAAA", "CNAME"].includes(r.type) },
  dane: { where: "_25._tcp.<mx> TLSA", match: (r) => r.type === "TLSA" },
  wildcard: { where: "da-check-….{d} A", match: (r) => r.name.startsWith("da-check-") },
  txt: { where: "{d} TXT", match: (r, d) => r.name === d && r.type === "TXT" },
  subdomains: { where: "Certificate Transparency → DNS A", match: (r) => r.source === "ct" },
  ptr: { where: "PTR", match: (r) => r.type === "PTR" },
};

function keyOf(id: string): Key | null {
  const prefix = id.split(".")[0];
  if (prefix === "spf" || prefix === "dmarc" || prefix === "dkim" || prefix === "mx" || prefix === "mta-sts" || prefix === "tls-rpt" || prefix === "bimi") return prefix;
  if (/^dns\.(ns|ns-single|provider)$/.test(id)) return "ns";
  if (id.startsWith("dns.caa")) return "caa";
  if (id.startsWith("dns.dnssec")) return "dnssec";
  if (/^dns\.(address|no-address|hosting)$/.test(id)) return "address";
  if (/^dns\.(ipv6|no-ipv6)$/.test(id)) return "ipv6";
  if (/^ip\.(ptr|no-ptr|fcrdns|no-fcrdns)$/.test(id)) return "ptr";
  return null;
}

/** What the standard asks for, when the audit has no exact record to suggest. */
const EXPECTED: Record<Lang, Record<Key, string>> = {
  es: {
    spf: "Un único TXT en {d} que empiece por v=spf1, incluya todos los servicios que envían correo en nombre del dominio, no pase de 10 consultas DNS y termine en -all o ~all (RFC 7208).",
    dmarc: "Un único TXT en _dmarc.{d} que empiece por v=DMARC1, con p=quarantine o p=reject una vez que todo el correo legítimo pasa SPF o DKIM alineado (RFC 9989).",
    dkim: "Por cada servicio que envía correo, un TXT en <selector>._domainkey.{d} (o un CNAME al proveedor) con v=DKIM1 y una clave pública p= de 2048 bits; 1024 es el mínimo (RFC 8301).",
    mx: "Uno o varios MX que apunten a nombres de servidor (no a direcciones IP) que existan y acepten correo. Si el dominio no recibe correo, un MX nulo: 0 . (RFC 7505).",
    "mta-sts": "Un TXT en _mta-sts.{d} con v=STSv1; id=… y la política publicada en https://mta-sts.{d}/.well-known/mta-sts.txt (RFC 8461).",
    "tls-rpt": "Un TXT en _smtp._tls.{d} con v=TLSRPTv1; rua= seguido de una dirección mailto: o https: que reciba los informes (RFC 8460).",
    bimi: "Opcional. Un TXT en default._bimi.{d} con v=BIMI1; l= (logotipo en SVG) y, para Gmail, a= (certificado VMC o CMC). Exige DMARC en quarantine o reject.",
    ns: "Al menos dos servidores de nombres (NS), a ser posible en redes distintas (RFC 1034 y RFC 2182).",
    caa: "Un CAA issue por cada autoridad de certificación que emite certificados para el dominio y, si se quiere recibir avisos, un CAA iodef (RFC 8659).",
    dnssec: "Un DS en la zona padre que coincida con una clave DNSKEY de la zona, y respuestas que los resolvedores validan (bit AD) (RFC 4033).",
    address: "Registros A o AAAA si el dominio sirve una web u otros servicios. Si no los tiene, no es un error.",
    ipv6: "Un AAAA además del A, para que el servicio sea accesible por IPv6.",
    ptr: "Un PTR en la zona inversa que apunte a un nombre, y que ese nombre resuelva de vuelta a la misma IP (FCrDNS).",
    subdomains: "Cada subdominio publicado debe estar en uso y bajo control: ningún CNAME puede apuntar a un recurso que ya no existe.",
    hosting: "Direcciones o alias hacia un alojamiento que la organización controle y mantenga al día.",
    dane: "Opcional. Un TLSA en `_25._tcp.<servidor MX>` con la huella del certificado del MX, en una zona firmada con DNSSEC (RFC 7672).",
    wildcard: "Sin registro comodín, salvo que se necesite: sólo resuelven los nombres que existen de verdad.",
    txt: "Sólo las verificaciones y remitentes de servicios que se sigan usando; las de servicios abandonados se borran.",
  },
  en: {
    spf: "A single TXT at {d} that starts with v=spf1, includes every service sending mail for the domain, needs no more than 10 DNS lookups and ends in -all or ~all (RFC 7208).",
    dmarc: "A single TXT at _dmarc.{d} that starts with v=DMARC1, with p=quarantine or p=reject once all legitimate mail passes aligned SPF or DKIM (RFC 9989).",
    dkim: "For each service sending mail, a TXT at <selector>._domainkey.{d} (or a CNAME to the provider) with v=DKIM1 and a 2048-bit public key in p=; 1024 is the minimum (RFC 8301).",
    mx: "One or more MX pointing to server names (not IP addresses) that exist and accept mail. If the domain receives no mail, a null MX: 0 . (RFC 7505).",
    "mta-sts": "A TXT at _mta-sts.{d} with v=STSv1; id=… and the policy published at https://mta-sts.{d}/.well-known/mta-sts.txt (RFC 8461).",
    "tls-rpt": "A TXT at _smtp._tls.{d} with v=TLSRPTv1; rua= followed by a mailto: or https: address that receives the reports (RFC 8460).",
    bimi: "Optional. A TXT at default._bimi.{d} with v=BIMI1; l= (SVG logo) and, for Gmail, a= (VMC or CMC certificate). Requires DMARC at quarantine or reject.",
    ns: "At least two name servers (NS), preferably on different networks (RFC 1034 and RFC 2182).",
    caa: "A CAA issue for each certificate authority that issues certificates for the domain and, to receive alerts, a CAA iodef (RFC 8659).",
    dnssec: "A DS in the parent zone matching a DNSKEY of the zone, and answers the resolvers validate (AD bit) (RFC 4033).",
    address: "A or AAAA records if the domain serves a website or other services. Having none is not an error.",
    ipv6: "An AAAA besides the A, so the service is reachable over IPv6.",
    ptr: "A PTR in the reverse zone pointing to a name, and that name resolving back to the same IP (FCrDNS).",
    subdomains: "Every published subdomain should be in use and under control: no CNAME may point to a resource that no longer exists.",
    hosting: "Addresses or aliases pointing to hosting the organisation controls and keeps up to date.",
    dane: "Optional. A TLSA at `_25._tcp.<MX server>` with the MX certificate fingerprint, in a DNSSEC-signed zone (RFC 7672).",
    wildcard: "No wildcard record unless it is needed: only names that really exist resolve.",
    txt: "Only verifications and senders of services still in use; those of abandoned services are removed.",
  },
};

const TEXT = {
  es: {
    seen: "Lo que hay",
    expected: "Lo que debería haber",
    nothing: "Nada: la consulta no devolvió ningún registro.",
    fine: "Lo que hay ya cumple: no hace falta cambiarlo.",
    add: "Añadir",
    replace: "Sustituir por",
    optional: "opcional",
  },
  en: {
    seen: "What is there",
    expected: "What should be there",
    nothing: "Nothing: the query returned no records.",
    fine: "What is there already complies: nothing to change.",
    add: "Add",
    replace: "Replace with",
    optional: "optional",
  },
};

export interface Observed {
  labels: { seen: string; expected: string };
  where: string;
  rows: RecordRow[];
  nothing: string;
  /** Exact records to publish, when the audit could build them. */
  suggest: { verb: string; line: string }[];
  /** Otherwise, what the standard asks for (or that it already complies). */
  expected?: string;
  /** Only "what is there": the finding identifies something, it does not assess it. */
  identifyOnly: boolean;
}

export function observedFor(f: Finding, section: Section, domain: string, lang: Lang): Observed | null {
  const key = keyOf(f.id);
  if (!key) return null;
  const rule = RULES[key];
  const t = TEXT[lang];
  const rows = section.records.filter((r) => rule.match(r, domain));
  const suggest = (f.suggest ?? []).map((s) => ({
    verb: `${s.action === "replace" ? t.replace : t.add}${s.optional ? ` (${t.optional})` : ""}`,
    line: `${s.name} ${s.type} ${s.value}`,
  }));
  const complies = f.status === "ok";
  // Findings that only identify a provider have nothing to comply with.
  const identifyOnly = /^(dns\.provider|dns\.hosting|mx\.provider)$/.test(f.id);
  return {
    labels: { seen: t.seen, expected: t.expected },
    where: rule.where.replaceAll("{d}", domain),
    rows,
    nothing: t.nothing,
    suggest,
    identifyOnly,
    expected: suggest.length ? undefined : complies ? t.fine : EXPECTED[lang][key].replaceAll("{d}", domain),
  };
}

export type EvidenceKey = Key;

/** Records collected for a topic, and the query they answer (`{d}` filled in). */
export function evidenceFor(key: EvidenceKey, section: Section, domain: string): { where: string; rows: RecordRow[] } {
  const rule = RULES[key];
  return { where: rule.where.replaceAll("{d}", domain), rows: section.records.filter((r) => rule.match(r, domain)) };
}

/** What the standard asks for on a topic. */
export function expectedFor(key: EvidenceKey, domain: string, lang: Lang): string {
  return EXPECTED[lang][key].replaceAll("{d}", domain);
}
