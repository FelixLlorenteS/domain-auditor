import type { Finding, Report, ResolverCheck, Section, Status } from "../core/types";
import type { Lang } from "../i18n";
import type { EvidenceKey } from "./observed";

/**
 * The report organised as an administrator reviews a domain: one control per
 * topic (SPF, DMARC, CAA…), grouped by area. Each control gathers the findings
 * about its topic, so a topic is read in one place with its evidence, its checks
 * and the action it needs. Nothing is re-evaluated here: the state of a control
 * is the most severe state among its findings.
 */

export type GroupId = "mail-auth" | "mail-transport" | "mail-brand" | "dns-infra" | "dns-integrity" | "web" | "surface" | "registration" | "ip";
export type ControlState = "fail" | "warn" | "ok" | "info" | "optional" | "na" | "unknown";
export type Severity = "high" | "medium" | "low";
export type Confidence = "high" | "medium";

interface ControlDef {
  id: string;
  group: GroupId;
  /** Nice-to-have hardening: absent is "optional", not a problem. */
  optional?: boolean;
  /** Records that prove the result (see observed.ts). */
  evidence?: EvidenceKey;
  /** Query compared between both resolvers, as `name TYPE` with `{d}` for the domain. */
  crossCheck?: string;
  /** Text to find its responses in the raw data view. */
  rawFilter?: string;
}

const DEFS: ControlDef[] = [
  { id: "spf", group: "mail-auth", evidence: "spf", crossCheck: "{d} TXT", rawFilter: "{d} TXT" },
  { id: "dkim", group: "mail-auth", evidence: "dkim", rawFilter: "_domainkey" },
  { id: "dmarc", group: "mail-auth", evidence: "dmarc", crossCheck: "_dmarc.{d} TXT", rawFilter: "_dmarc" },
  { id: "mx", group: "mail-transport", evidence: "mx", crossCheck: "{d} MX", rawFilter: "{d} MX" },
  { id: "mta-sts", group: "mail-transport", optional: true, evidence: "mta-sts", rawFilter: "mta-sts" },
  { id: "tls-rpt", group: "mail-transport", optional: true, evidence: "tls-rpt", rawFilter: "_smtp._tls" },
  { id: "dane", group: "mail-transport", optional: true, evidence: "dane", rawFilter: "_25._tcp" },
  { id: "bimi", group: "mail-brand", optional: true, evidence: "bimi", rawFilter: "_bimi" },
  { id: "ns", group: "dns-infra", evidence: "ns", crossCheck: "{d} NS", rawFilter: "{d} NS" },
  { id: "address", group: "dns-infra", evidence: "address", rawFilter: "{d} A" },
  { id: "wildcard", group: "dns-infra", evidence: "wildcard", rawFilter: "da-check" },
  { id: "resolvers", group: "dns-infra", rawFilter: "google" },
  { id: "dnssec", group: "dns-integrity", evidence: "dnssec", crossCheck: "{d} DS", rawFilter: "{d} DS" },
  { id: "caa", group: "dns-integrity", evidence: "caa", crossCheck: "{d} CAA", rawFilter: "CAA" },
  { id: "https", group: "web", rawFilter: "web GET http" },
  { id: "tls", group: "web", rawFilter: "web TLS" },
  { id: "headers", group: "web", rawFilter: "web GET https" },
  { id: "security-txt", group: "web", optional: true, rawFilter: "security.txt" },
  { id: "hosting", group: "surface", evidence: "hosting", rawFilter: "{d} A" },
  { id: "integrations", group: "surface", evidence: "txt", rawFilter: "{d} TXT" },
  { id: "subdomains", group: "surface", evidence: "subdomains", rawFilter: "Certificate Transparency" },
  { id: "certificates", group: "surface", rawFilter: "Certificate Transparency" },
  { id: "exposure", group: "surface", rawFilter: "intel" },
  { id: "expiry", group: "registration", rawFilter: "rdap" },
  { id: "lock", group: "registration", rawFilter: "rdap" },
  { id: "registration", group: "registration", rawFilter: "rdap" },
  { id: "special", group: "ip" },
  { id: "ptr", group: "ip", evidence: "ptr", rawFilter: "PTR" },
  { id: "network", group: "ip", rawFilter: "rdap" },
];

export const GROUP_ORDER: GroupId[] = ["mail-auth", "mail-transport", "mail-brand", "dns-infra", "dns-integrity", "web", "surface", "registration", "ip"];

/** Which control a finding belongs to. */
export function controlIdOf(findingId: string): string {
  const prefix = findingId.split(".")[0] ?? "";
  if (/^mx\.(dane|dane-unsigned|dane-partial|dane-insecure-mx|no-dane)$/.test(findingId)) return "dane";
  if (prefix === "dnssec") return "dnssec";
  if (/^dns\.(wildcard|no-wildcard)$/.test(findingId)) return "wildcard";
  if (/^dns\.(soa|soa-inconsistent|ns-networks|ns-one-network)$/.test(findingId)) return "ns";
  if (["spf", "dkim", "dmarc", "mx", "mta-sts", "tls-rpt", "bimi", "https", "tls"].includes(prefix)) return prefix;
  if (prefix === "hdr") return "headers";
  if (prefix === "sectxt") return "security-txt";
  if (/^dns\.(nxdomain|servfail|no-zone|ns|ns-single|ns-parent|provider)$/.test(findingId)) return "ns";
  if (findingId === "dns.hosting" || findingId === "dns.cdn" || prefix === "web") return "hosting";
  if (prefix === "int") return "integrations";
  if (prefix === "intel") return "exposure";
  if (/^dns\.(address|no-address|ipv6|no-ipv6|alias)$/.test(findingId)) return "address";
  if (findingId.startsWith("dns.resolvers")) return "resolvers";
  if (findingId.startsWith("dns.dnssec")) return "dnssec";
  if (findingId.startsWith("dns.caa")) return "caa";
  if (/^ct\.(issuers|issuer-not-caa|issuers-caa-ok)$/.test(findingId)) return "certificates";
  if (prefix === "ct") return "subdomains";
  if (/^reg\.(expires|expires-soon|expired|expiry-unknown|redemption|pending-delete)$/.test(findingId)) return "expiry";
  if (/^reg\.(transfer-lock|registry-lock|no-transfer-lock|lock-unknown)$/.test(findingId)) return "lock";
  if (prefix === "reg") return "registration";
  if (findingId === "ip.special") return "special";
  if (/^ip\.(ptr|no-ptr|fcrdns|no-fcrdns)$/.test(findingId)) return "ptr";
  if (prefix === "ip") return "network";
  return "other";
}

export interface ControlFinding {
  f: Finding;
  section: Section;
}

export interface Control extends ControlDef {
  state: ControlState;
  findings: ControlFinding[];
  /** Resolver comparison for the control's key query, when there is one. */
  check?: ResolverCheck;
}

export interface ControlGroup {
  id: GroupId;
  controls: Control[];
}

const SEVERITY: Status[] = ["fail", "warn", "ok", "info"];
export const bySeverity = (a: ControlFinding, b: ControlFinding) => SEVERITY.indexOf(a.f.status) - SEVERITY.indexOf(b.f.status);

/** Findings that say the check does not apply, or could not reach a conclusion. */
const NOT_APPLICABLE = new Set(["dkim.not-applicable"]);
const INCONCLUSIVE = new Set([
  "dkim.not-found",
  "dkim.selector-unknown",
  "ct.unavailable",
  "ct.wildcard-only",
  "ct.partial",
  "reg.error",
  "reg.unavailable",
  "reg.expiry-unknown",
  "reg.lock-unknown",
  "mta-sts.unverified",
  "mx.lookup-error",
  "spf.lookup-error",
  "spf.include-error",
  "dmarc.lookup-error",
  "tls.unreachable",
  "ct.pending",
  "intel.pending",
  "tls.legacy-unknown",
  "https.unresolved",
  "hdr.blocked",
  "sectxt.unavailable",
]);

/**
 * The most severe state among the findings. A part that could not be checked
 * outweighs "ok": a control is only "ok" when everything in it was verified.
 */
export function stateOf(findings: Finding[], optional = false): ControlState {
  const worst = SEVERITY.find((s) => findings.some((f) => f.status === s)) ?? "info";
  const inconclusive = findings.some((f) => INCONCLUSIVE.has(f.id));
  if (worst === "fail" || worst === "warn") return worst;
  if (inconclusive) return "unknown";
  if (worst === "ok") return worst;
  if (findings.some((f) => NOT_APPLICABLE.has(f.id))) return "na";
  if (optional) return "optional";
  return "info";
}

/**
 * How much a failing control matters, apart from its state: a missing CAA and a
 * missing DMARC are both warnings or failures, but not equally serious.
 */
const SEVERITY_OF: Record<string, Severity> = {
  // SPF protects the envelope sender; the visible sender is DMARC's job (RFC 9989).
  spf: "medium",
  dmarc: "high",
  subdomains: "high",
  expiry: "high",
  dkim: "medium",
  mx: "medium",
  ns: "medium",
  dnssec: "medium",
  lock: "medium",
  // Only a domain on hold fails here: it has left the DNS.
  registration: "high",
  certificates: "medium",
  resolvers: "medium",
  ptr: "medium",
  caa: "low",
  "mta-sts": "low",
  "tls-rpt": "low",
  dane: "low",
  wildcard: "low",
  bimi: "low",
  https: "high",
  tls: "high",
  headers: "low",
  "security-txt": "low",
};
export function severityOf(c: Control): Severity {
  // A name that sends no mail but lacks `v=spf1 -all`, under a DMARC at reject that
  // already rejects spoofing of the visible sender: hardening, not an open door.
  if (c.id === "spf" && c.findings.every(({ f }) => f.status !== "warn" || f.id === "spf.missing-nomail") && c.findings[0]?.section.findings.some((f) => f.id === "dmarc.p-reject")) return "low";
  // When the protection itself is in place, what is left (no DMARC reports, an old
  // DKIM key, an orphan CNAME, leaked private addresses) is minor.
  if (GAPS[c.id] && !hasGap(c)) return "low";
  return SEVERITY_OF[c.id] ?? "low";
}

/**
 * Findings that mean the control's protection itself is missing or weak. A
 * control can be in warning for a side issue (DMARC at reject without reports,
 * an old 1024-bit DKIM next to good ones): then its risk text would not apply.
 */
const GAPS: Record<string, RegExp> = {
  spf: /^spf\.(missing|missing-provider|missing-nomail|multiple|syntax|all-pass|all-neutral|no-all|no-senders|too-many-lookups|void-lookups|mx-too-many|include-missing|loop)$/,
  dkim: /^dkim\.(not-found|selector-unknown|no-domainkey|bad-key|unknown-type|sha1)$/,
  dmarc: /^dmarc\.(missing|missing-nomail|multiple|bad-version|p-none|p-missing|invalid-policy|testing)$/,
  subdomains: /^ct\.takeover$/,
};
export function hasGap(c: Control): boolean {
  const re = GAPS[c.id];
  if (!re) return c.state !== "ok";
  return c.findings.some(({ f }) => re.test(f.id)) || (c.id === "dkim" && !c.findings.some(({ f }) => f.status === "ok"));
}

/**
 * Whether the result is read directly from DNS or registry data (high), or
 * inferred from partial data such as a list of selectors or of logged
 * certificates (medium).
 */
const INFERRED = new Set(["dkim", "subdomains", "certificates", "hosting", "integrations", "registration", "exposure"]);
export const confidenceOf = (c: Control): Confidence => (INFERRED.has(c.id) ? "medium" : "high");

/**
 * The benchmark: the same basic controls for every domain, so two scores can be
 * compared. A basic control that could not be checked (unknown DKIM selector, no
 * RDAP for the TLD) counts as not passed and is reported as "not verified".
 * Optional hardening is counted apart. Subdomains and certificates stay out: they
 * come from Certificate Transparency, which only shows part of the picture and
 * whose public services often fail, so the same domain would score differently
 * from one minute to the next.
 */
export const BASELINE: Record<Report["kind"], string[]> = {
  domain: ["spf", "dkim", "dmarc", "ns", "dnssec", "caa", "expiry", "lock"],
  ip: ["ptr"],
};
export const EXTRAS = ["mta-sts", "tls-rpt", "dane", "bimi"];

export interface Score {
  passed: number;
  /** Basic controls that apply to this target. */
  total: number;
  notApplicable: number;
  unverified: number;
  extras: number;
  extrasTotal: number;
}

export function scoreOf(report: Report, groups: ControlGroup[]): Score {
  const byId = new Map(groups.flatMap((g) => g.controls).map((c) => [c.id, c]));
  // A name that does not resolve, or a private/reserved IP, cannot be scored at all.
  const blocked = report.sections.some((s) => s.findings.some((f) => ["dns.nxdomain", "dns.servfail", "dns.dnssec-broken", "ip.special"].includes(f.id)));
  const base = blocked ? [] : BASELINE[report.kind];
  const state = (id: string) => byId.get(id)?.state;
  const applicable = base.filter((id) => state(id) !== "na");
  return {
    passed: applicable.filter((id) => state(id) === "ok").length,
    total: applicable.length,
    notApplicable: base.length - applicable.length,
    unverified: applicable.filter((id) => !state(id) || state(id) === "info" || state(id) === "unknown").length,
    extras: report.kind === "domain" ? EXTRAS.filter((id) => state(id) === "ok").length : 0,
    extrasTotal: report.kind === "domain" ? EXTRAS.length : 0,
  };
}

/** Controls that pass judgement (not purely informational or optional). */
export const isAssessed = (c: Control) => c.state === "ok" || c.state === "warn" || c.state === "fail";
export const needsAction = (c: Control) => c.state === "warn" || c.state === "fail";

export function buildControls(report: Report): ControlGroup[] {
  const domain = report.query;
  const byId = new Map<string, ControlFinding[]>();
  for (const section of report.sections) {
    for (const f of section.findings) {
      const id = controlIdOf(f.id);
      byId.set(id, [...(byId.get(id) ?? []), { f, section }]);
    }
  }
  const controls: Control[] = [];
  for (const def of DEFS) {
    const findings = byId.get(def.id);
    if (!findings?.length) continue;
    const key = def.crossCheck?.replace("{d}", domain);
    const check = key ? report.resolverCheck?.find((c) => `${c.name} ${c.type}` === key) : undefined;
    controls.push({
      ...def,
      rawFilter: def.rawFilter?.replace("{d}", domain),
      findings: [...findings].sort(bySeverity),
      state: stateOf(
        findings.map((x) => x.f),
        def.optional,
      ),
      ...(check ? { check } : {}),
    });
  }
  // Anything not mapped still shows up, in the group of its section.
  const other = byId.get("other");
  if (other?.length) {
    const sectionGroup: Record<Section["id"], GroupId> = { mail: "mail-auth", dns: "dns-infra", web: "web", registration: "registration", ip: "ip" };
    const group = sectionGroup[other[0]!.section.id];
    controls.push({ id: "other", group, findings: [...other].sort(bySeverity), state: stateOf(other.map((x) => x.f)) });
  }
  return GROUP_ORDER.map((id) => ({ id, controls: controls.filter((c) => c.group === id) })).filter((g) => g.controls.length);
}

export const TEXT = {
  es: {
    groups: {
      "mail-auth": "Correo · autenticación",
      "mail-transport": "Correo · transporte",
      "mail-brand": "Correo · marca",
      "dns-infra": "DNS · infraestructura",
      "dns-integrity": "DNS · integridad",
      web: "Web · HTTPS y cabeceras",
      surface: "Superficie de ataque",
      registration: "Registro del dominio",
      ip: "Dirección IP",
    } satisfies Record<GroupId, string>,
    controls: {
      spf: "SPF",
      dkim: "DKIM",
      dmarc: "DMARC",
      mx: "MX",
      "mta-sts": "MTA-STS",
      "tls-rpt": "TLS-RPT",
      dane: "DANE",
      bimi: "BIMI",
      ns: "Servidores DNS",
      wildcard: "Comodín",
      address: "Direcciones",
      resolvers: "Coherencia",
      dnssec: "DNSSEC",
      caa: "CAA",
      subdomains: "Subdominios",
      https: "HTTPS",
      tls: "Certificado y TLS",
      headers: "Cabeceras de seguridad",
      "security-txt": "security.txt",
      hosting: "Web y alojamiento",
      integrations: "Integraciones",
      exposure: "Exposición y reputación",
      certificates: "Certificados",
      expiry: "Caducidad",
      lock: "Bloqueo",
      registration: "Datos",
      special: "Rango",
      ptr: "DNS inverso",
      network: "Red",
      other: "Otros",
    } as Record<string, string>,
    states: { fail: "Fallo", warn: "Aviso", ok: "Bien", info: "Info", optional: "Opcional", na: "No aplica", unknown: "Sin verificar" } satisfies Record<ControlState, string>,
    severity: { high: "Severidad alta", medium: "Severidad media", low: "Severidad baja" } satisfies Record<Severity, string>,
    confidence: { high: "Confianza alta", medium: "Confianza media" } satisfies Record<Confidence, string>,
    metricNa: "{n} no aplica",
    groupOk: "{n} de {total} bien",
    groupOptional: "{n} opcionales",
    groupOptionalOne: "1 opcional",
    metricControls: "Controles básicos",
    metricControlsValue: "{ok} de {total} bien",
    metricNotEvaluable: "No evaluable",
    metricUnverified: "{n} sin verificar",
    metricExtras: "Mejoras opcionales: {n} de {total}",
    metricActions: "Acciones",
    metricActionsNone: "Ninguna",
    metricActionsValue: "{n} recomendadas",
    metricActionsOne: "1 recomendada",
    metricTrust: "Fiabilidad de los datos",
    trustAgree: "Cloudflare = Google ({same}/{total})",
    trustDiffer: "Cloudflare ≠ Google en {n} de {total}",
    trustDnssec: "DNSSEC validado",
    trustNoDnssec: "Sin DNSSEC: sin firma que validar",
    trustIp: "RDAP y RIPEstat, en vivo",
    trustCt: "Certificate Transparency: consultado",
    trustCtDown: "Certificate Transparency: sin respuesta",
    trustCtPending: "Certificate Transparency: consultando…",
    ctFailed: "Ni crt.sh ni Cert Spotter respondieron: no hay lista de subdominios",
    evMore: "Ver las {n} líneas",
    plan: "Plan de acción",
    planNone: "Nada que corregir: todos los controles evaluados están bien.",
    evidence: "Evidencia",
    risk: "Riesgo",
    prevents: "Qué aporta",
    related: "Técnicas MITRE ATT&CK relacionadas:",
    checks: "Comprobaciones",
    action: "Acción",
    actionNone: "Ninguna: cumple.",
    actionInfo: "Nada que corregir.",
    actionOptional: "Opcional. Si se quiere activar:",
    expected: "Lo que pide la norma:",
    empty: "sin registros",
    emptyNoerror: "Sin registros: el DNS respondió NOERROR, sin datos de este tipo.",
    emptyNxdomain: "Sin registros: el nombre no existe (NXDOMAIN).",
    emptyNone: "Sin registros.",
    emptyExpected: " Es lo esperado.",
    agree: "Cloudflare y Google coinciden",
    differ: "Cloudflare y Google NO coinciden",
    single: "consultado a {primary}",
    viewRaw: "ver respuesta",
    source: "Fuente",
    showAll: "Todos",
    showActions: "Sólo con acción",
    records: "Todos los registros recogidos",
  },
  en: {
    groups: {
      "mail-auth": "Mail · authentication",
      "mail-transport": "Mail · transport",
      "mail-brand": "Mail · brand",
      "dns-infra": "DNS · infrastructure",
      "dns-integrity": "DNS · integrity",
      web: "Web · HTTPS and headers",
      surface: "Attack surface",
      registration: "Domain registration",
      ip: "IP address",
    } satisfies Record<GroupId, string>,
    controls: {
      spf: "SPF",
      dkim: "DKIM",
      dmarc: "DMARC",
      mx: "MX",
      "mta-sts": "MTA-STS",
      "tls-rpt": "TLS-RPT",
      dane: "DANE",
      bimi: "BIMI",
      ns: "Name servers",
      wildcard: "Wildcard",
      address: "Addresses",
      resolvers: "Consistency",
      dnssec: "DNSSEC",
      caa: "CAA",
      subdomains: "Subdomains",
      https: "HTTPS",
      tls: "Certificate and TLS",
      headers: "Security headers",
      "security-txt": "security.txt",
      hosting: "Web and hosting",
      integrations: "Integrations",
      exposure: "Exposure and reputation",
      certificates: "Certificates",
      expiry: "Expiry",
      lock: "Lock",
      registration: "Details",
      special: "Range",
      ptr: "Reverse DNS",
      network: "Network",
      other: "Other",
    } as Record<string, string>,
    states: { fail: "Failure", warn: "Warning", ok: "Good", info: "Info", optional: "Optional", na: "Not applicable", unknown: "Not verified" } satisfies Record<ControlState, string>,
    severity: { high: "High severity", medium: "Medium severity", low: "Low severity" } satisfies Record<Severity, string>,
    confidence: { high: "High confidence", medium: "Medium confidence" } satisfies Record<Confidence, string>,
    metricNa: "{n} not applicable",
    groupOk: "{n} of {total} good",
    groupOptional: "{n} optional",
    groupOptionalOne: "1 optional",
    metricControls: "Basic controls",
    metricControlsValue: "{ok} of {total} good",
    metricNotEvaluable: "Not assessable",
    metricUnverified: "{n} not verified",
    metricExtras: "Optional hardening: {n} of {total}",
    metricActions: "Actions",
    metricActionsNone: "None",
    metricActionsValue: "{n} recommended",
    metricActionsOne: "1 recommended",
    metricTrust: "Data reliability",
    trustAgree: "Cloudflare = Google ({same}/{total})",
    trustDiffer: "Cloudflare ≠ Google in {n} of {total}",
    trustDnssec: "DNSSEC validated",
    trustNoDnssec: "No DNSSEC: no signature to validate",
    trustIp: "RDAP and RIPEstat, live",
    trustCt: "Certificate Transparency: queried",
    trustCtDown: "Certificate Transparency: no answer",
    trustCtPending: "Certificate Transparency: querying…",
    ctFailed: "Neither crt.sh nor Cert Spotter answered: no subdomain list",
    evMore: "Show all {n} lines",
    plan: "Action plan",
    planNone: "Nothing to fix: every assessed control is fine.",
    evidence: "Evidence",
    risk: "Risk",
    prevents: "What it adds",
    related: "Related MITRE ATT&CK techniques:",
    checks: "Checks",
    action: "Action",
    actionNone: "None: it complies.",
    actionInfo: "Nothing to fix.",
    actionOptional: "Optional. To set it up:",
    expected: "What the standard asks for:",
    empty: "no records",
    emptyNoerror: "No records: the DNS answered NOERROR, with no data of this type.",
    emptyNxdomain: "No records: the name does not exist (NXDOMAIN).",
    emptyNone: "No records.",
    emptyExpected: " As expected.",
    agree: "Cloudflare and Google agree",
    differ: "Cloudflare and Google DO NOT agree",
    single: "queried from {primary}",
    viewRaw: "view response",
    source: "Source",
    showAll: "All",
    showActions: "Only with action",
    records: "All records collected",
  },
} satisfies Record<Lang, unknown>;
