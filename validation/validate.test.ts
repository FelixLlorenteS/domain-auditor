import { mkdirSync, writeFileSync } from "node:fs";
import { afterAll, describe, expect, it } from "vitest";
import { audit } from "../src/core/audit";
import { claimableProvider, isPrivateIPv4 } from "../src/core/ct";
import { createResolver, queryProvider } from "../src/core/doh";
import { parseTarget } from "../src/core/input";
import type { RawLog } from "../src/core/raw";
import type { Finding, Report } from "../src/core/types";
import { MESSAGES } from "../src/i18n";
import { buildControls, scoreOf } from "../src/ui/controls";
import { reportMarkdown } from "../src/ui/markdown";
import { dmarcPolicy, lockOf, mtaStsMode, registryStatus, relevantCaa, restrictsIssue, unauthorisedRua } from "./independent";
import { browserFetch, consensus, norm, truth } from "./truth";

/**
 * Corpus: well-run domains, deliberately broken or vulnerable test domains, and
 * edge cases. Each report is checked against independent DNS answers (dns.google
 * and NextDNS) and independent re-implementations of the checks (independent.ts),
 * and every claim the auditor makes about a third-party resource is re-verified.
 */
const CORPUS = [
  "internet.nl",
  "nic.cz",
  "sidn.nl",
  "example.com",
  "cloudflare.com",
  "google.com",
  "github.com",
  "microsoft.com",
  "fastmail.com",
  "posteo.de",
  "hackthebox.com",
  "zonetransfer.me",
  "vulnweb.com",
  "testfire.net",
  "dnssec-failed.org",
  "rtve.es",
  "bbva.es",
  "pccomponentes.com",
  "felixllorente.com",
  "www.github.com",
  "this-domain-does-not-exist-da2026.com",
  "8.8.8.8",
  "1.1.1.1",
  "192.168.1.1",
  "2001:4860:4860::8888",
];

const OUT = "validation/out";
mkdirSync(OUT, { recursive: true });
const summary: string[] = [];
const all = (r: Report): Finding[] => r.sections.flatMap((s) => s.findings);
const ids = (r: Report) => all(r).map((f) => f.id);
const find = (r: Report, id: string) => all(r).find((f) => f.id === id);

async function run(q: string): Promise<{ report: Report; md: { es: string; en: string } }> {
  const log: RawLog = [];
  const report = await audit(parseTarget(q), {
    fetch: browserFetch,
    resolver: createResolver({ log }),
    secondOpinion: (p, n, t) => queryProvider(p, n, t, { log }),
    checkingDisabled: (n, t) => queryProvider("cloudflare", n, t, { log, cd: true }),
    log,
  });
  const md = {
    es: reportMarkdown(report, "es", [], {}, `local:${q}`),
    en: reportMarkdown(report, "en", [], {}, `local:${q}`),
  };
  const safe = q.replace(/[^a-z0-9.-]/gi, "_");
  writeFileSync(`${OUT}/${safe}.es.md`, md.es);
  writeFileSync(`${OUT}/${safe}.json`, JSON.stringify(report, null, 2));
  return { report, md };
}

/** Notes about what could not be checked or is known to be pending, for the summary. */
type Notes = string[];

/** Checks that hold for every report, whatever the domain. */
async function invariants(q: string, report: Report, md: { es: string; en: string }, notes: Notes) {
  // Every finding has text in both languages and nothing is left unfilled.
  for (const f of all(report)) {
    expect(MESSAGES.es[f.id], `${q}: falta texto ES de ${f.id}`).toBeDefined();
    expect(MESSAGES.en[f.id], `${q}: falta texto EN de ${f.id}`).toBeDefined();
  }
  for (const [lang, text] of Object.entries(md)) {
    expect(text, `${q} ${lang}: marcador sin rellenar`).not.toMatch(/(?<!%)\{[a-z]+\}/i);
    expect(text, `${q} ${lang}: undefined/NaN`).not.toMatch(/\bundefined\b|\bNaN\b|\[object Object\]/);
  }
  // Nothing the browser cannot see is ever reported as fine.
  for (const f of all(report).filter((x) => x.id.startsWith("mta-sts."))) expect(f.status, `${q}: MTA-STS en verde sin leer la política`).not.toBe("ok");

  if (report.kind !== "domain" || ids(report).some((i) => ["dns.nxdomain", "dns.servfail", "dns.dnssec-broken"].includes(i))) return;
  const d = report.query;

  // SPF, null MX and DNSSEC: what the report says must match both independent resolvers.
  const [txt, mx, soa, ds] = await Promise.all([consensus(d, "TXT"), consensus(d, "MX"), truth(d, "SOA"), consensus(d, "DS")]);
  if (txt.agree) {
    const spf = txt.data.filter((t) => /^v=spf1(\s|$)/i.test(t));
    const spfFound = find(report, "spf.found");
    if (spf.length === 1) expect(norm(String(spfFound?.params?.record ?? "")), `${q}: SPF distinto de dns.google/NextDNS`).toBe(norm(spf[0]!));
    if (spf.length === 0) expect(spfFound, `${q}: dice que hay SPF y los resolvedores no lo ven`).toBeUndefined();
  } else notes.push("TXT inestable");
  if (mx.agree) {
    const nullMx = mx.data.length === 1 && /^0 \.?$/.test(mx.data[0]!);
    expect(Boolean(find(report, "mx.null")), `${q}: null MX`).toBe(nullMx);
    if (!mx.data.length && mx.status === 0) expect(find(report, "mx.none"), `${q}: sin MX`).toBeDefined();
  }
  if (soa.ad) expect(ids(report).some((i) => i === "dns.dnssec" || i === "dns.dnssec-both"), `${q}: DNSSEC validado y no lo dice`).toBe(true);
  if (ds.agree && !ds.data.length && !soa.ad) expect(ids(report).some((i) => i.startsWith("dns.dnssec-off")), `${q}: sin DS y no avisa`).toBe(true);

  // DMARC: the policy the report states is the one an independent RFC 9989 reading gives.
  const dm = await dmarcPolicy(d);
  const stated = ids(report).find((i) => /^dmarc\.(p-(none|quarantine|reject|missing)|invalid-policy|missing|missing-nomail|lookup-error)$/.test(i));
  const expected: Record<string, string> = {
    "dmarc.p-none": "none",
    "dmarc.p-missing": "none",
    "dmarc.p-quarantine": "quarantine",
    "dmarc.p-reject": "reject",
    "dmarc.invalid-policy": "invalid",
    "dmarc.missing": "absent",
    "dmarc.missing-nomail": "absent",
  };
  if (dm.policy === "unknown" || stated === "dmarc.lookup-error") notes.push("DMARC sin respuesta");
  else if (ids(report).includes("dmarc.bad-version") && !find(report, "dmarc.found")) expect(dm.policy, `${q}: DMARC ignorado`).toBe("absent");
  else expect(expected[stated ?? ""], `${q}: política DMARC (independiente: ${dm.policy})`).toBe(dm.policy);
  // External report addresses without authorisation (RFC 9990, section 4): each one
  // the independent check finds must be in the report's warning.
  if (dm.at && dm.record) {
    const bad = await unauthorisedRua(dm.at, dm.record);
    const flagged = String(find(report, "dmarc.rua-unauthorized")?.params?.hosts ?? "");
    for (const h of bad) expect(flagged, `${q}: rua sin autorizar no señalado (${h})`).toContain(h);
  }

  // CAA: "restricts issuance", "does not restrict" and "missing" agree with the relevant RRset.
  const caa = await relevantCaa(d);
  if (caa && !find(report, "dns.caa-lookup-error")) {
    if (find(report, "dns.caa")) expect(restrictsIssue(caa.records), `${q}: CAA en verde sin issue`).toBe(true);
    if (find(report, "dns.caa-no-issue")) expect(caa.records.length > 0 && !restrictsIssue(caa.records), `${q}: dice que el CAA no limita`).toBe(true);
    expect(ids(report).some((i) => i.startsWith("dns.caa-missing")), `${q}: CAA ausente/presente`).toBe(caa.records.length === 0);
  }

  // Registration locks against the registry's own RDAP (IANA bootstrap, not rdap.org).
  const status = ids(report).some((i) => i.startsWith("reg.")) ? await registryStatus(d) : null;
  if (status) {
    const lock = lockOf(status);
    if (find(report, "reg.registry-lock")) expect(lock.registry, `${q}: registry lock sin estados que lo prueben (${status.join(", ")})`).toBe(true);
    if (find(report, "reg.transfer-lock")) expect(lock.transfer, `${q}: bloqueo sin estado que lo pruebe (${status.join(", ")})`).toBe(true);
    if (find(report, "reg.no-transfer-lock")) expect(lock.transfer, `${q}: dice sin bloqueo pero el registro lo tiene (${status.join(", ")})`).toBe(false);
  } else if (ids(report).some((i) => i.startsWith("reg."))) notes.push("RDAP del registro sin datos");

  // MTA-STS: what the browser cannot read, read here for the record.
  if (find(report, "mta-sts.unverified")) notes.push(`MTA-STS mode: ${await mtaStsMode(d)}`);
  if (find(report, "mta-sts.no-host")) {
    const [a, aaaa] = await Promise.all([consensus(`mta-sts.${d}`, "A"), consensus(`mta-sts.${d}`, "AAAA")]);
    expect(a.data.length + aaaa.data.length, `${q}: dice que no existe mta-sts.${d}`).toBe(0);
  }

  // Third-party intelligence is context, never a verdict, and says what the source says.
  for (const f of all(report).filter((x) => x.id.startsWith("intel."))) {
    expect(f.status, `${q}: ${f.id} no puede ser aviso ni fallo`).toBe("info");
    if (f.id === "intel.shodan" || f.id === "intel.shodan-cdn") {
      const res = await browserFetch(`https://internetdb.shodan.io/${encodeURIComponent(String(f.params?.ip))}`, { signal: AbortSignal.timeout(15_000) });
      const j = (await res.json()) as { ports?: number[] };
      expect(String(f.params?.ports), `${q}: puertos distintos de los de Shodan`).toBe((j.ports ?? []).join(", ") || "—");
    }
  }

  // Claims about third parties are re-verified one by one.
  if (find(report, "ct.unavailable")) notes.push("crt.sh sin respuesta: CT sin validar");
  for (const f of all(report).filter((x) => x.id === "ct.takeover")) {
    const target = String(f.params?.target);
    const t = await truth(target, "A");
    expect(t.status, `${q}: dice takeover pero ${target} existe`).toBe(3);
    expect(claimableProvider(target), `${q}: takeover en proveedor no reclamable`).toBeDefined();
  }
  for (const f of all(report).filter((x) => x.id === "ct.dangling")) {
    const t = await truth(String(f.params?.target), "A");
    expect(t.status, `${q}: CNAME huérfano cuyo destino sí existe`).toBe(3);
  }
  for (const f of all(report).filter((x) => x.id === "ct.private-ips")) {
    const hosts = String(f.params?.hosts).replace(/…$/, "").split(", ");
    for (const h of hosts) {
      const t = await truth(h, "A");
      expect(t.data.some(isPrivateIPv4), `${q}: ${h} no resuelve a IP privada`).toBe(true);
    }
  }
  for (const f of all(report).filter((x) => x.id === "mx.dane")) {
    for (const h of String(f.params?.hosts).split(", ")) {
      const t = await consensus(`_25._tcp.${h}`, "TLSA");
      expect(t.data.length > 0 && t.ad, `${q}: DANE no confirmado en ${h}`).toBe(true);
    }
  }
}

/** The invariants plus known facts of specific domains, checked by hand before writing them here. */
async function check(q: string, report: Report, md: { es: string; en: string }, notes: Notes) {
  await invariants(q, report, md, notes);
  // Internet data changes: if a known fact fails, check the domain before the code.
  const has = (id: string) => ids(report).includes(id);
  // dnssec-failed.org: DS with no matching DNSKEY, on purpose. Both resolvers say EDE 9.
  if (q === "dnssec-failed.org") expect(has("dns.dnssec-broken")).toBe(true);
  if (q === "this-domain-does-not-exist-da2026.com") expect(has("dns.nxdomain")).toBe(true);
  if (q === "example.com") {
    expect(report.identity?.mailUsage).toBe("disabled");
    expect(has("dkim.not-applicable") && has("mx.null") && has("dmarc.p-reject")).toBe(true);
    expect(find(report, "dmarc.no-rua")?.status ?? "info").toBe("info");
  }
  if (q === "nic.cz") expect(has("dmarc.removed-tags")).toBe(true);
  // nic.cz: only "server transfer prohibited": a transfer lock, not a registry lock.
  if (q === "nic.cz" && has("reg.transfer-lock")) expect(has("reg.registry-lock")).toBe(false);
  // sidn.nl: RDAP status "locked" (SIDN's registry lock), which used to read as "no lock".
  if (q === "sidn.nl") expect(has("reg.no-transfer-lock")).toBe(false);
  if (q === "internet.nl") expect(has("dns.caa") && has("dmarc.p-reject")).toBe(true);
  if (q === "zonetransfer.me") expect(has("dmarc.missing") && ids(report).some((i) => i.startsWith("spf.missing"))).toBe(true);
  if (q === "vulnweb.com") expect(has("spf.no-senders")).toBe(true);
  if (q === "rtve.es") expect(has("spf.macros") && !has("spf.include-missing")).toBe(true);
  // posteo.de: DigiCert certificates authorised through geotrust.com, which used to raise a false alarm.
  if (q === "posteo.de") expect(String(find(report, "ct.issuer-not-caa")?.params?.issuers ?? "")).not.toMatch(/digicert/i);
  if (["google.com", "felixllorente.com", "nic.cz"].includes(q)) expect(has("reg.expires") || has("reg.expires-soon") || has("reg.error"), `${q}: RDAP`).toBe(true);
  // SIDN (.nl) publishes neither expiry nor EPP lock statuses: never a missing-lock warning.
  if (q === "internet.nl") expect(!has("reg.no-transfer-lock") && (has("reg.expiry-unknown") || has("reg.error"))).toBe(true);
  if (q === "rtve.es") expect(has("reg.unavailable")).toBe(true);
  if (q === "192.168.1.1") expect(has("ip.special")).toBe(true);
  if (q === "8.8.8.8") expect(report.identity?.ptr).toBe("dns.google");
}

describe.each(CORPUS)("%s", (q) => {
  it("se audita y cada afirmación cuadra con fuentes independientes", async () => {
    const { report, md } = await run(q);
    const notes: Notes = [];
    try {
      await check(q, report, md, notes);
    } finally {
      const groups = buildControls(report);
      const s = scoreOf(report, groups);
      const flagged = groups
        .flatMap((g) => g.controls)
        .filter((c) => c.state === "fail" || c.state === "warn")
        .map((c) => `${c.id}:${c.state}`)
        .join(", ");
      const score = s.total ? `${s.passed}/${s.total}${s.unverified ? ` (${s.unverified} sin verif.)` : ""}${s.notApplicable ? ` (${s.notApplicable} N/A)` : ""}` : "no evaluable";
      summary.push(`| ${q} | ${score} | ${flagged} | ${notes.join("; ")} |`);
    }
  });
});


afterAll(() => {
  writeFileSync(`${OUT}/RESUMEN.md`, ["| Objetivo | Básicos | Avisos y fallos | Notas |", "| --- | --- | --- | --- |", ...summary].join("\n") + "\n");
});
