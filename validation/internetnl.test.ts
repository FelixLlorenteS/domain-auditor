import { writeFileSync } from "node:fs";
import { afterAll, describe, expect, it } from "vitest";
import { audit } from "../src/core/audit";
import { createResolver, queryProvider } from "../src/core/doh";
import type { Report } from "../src/core/types";
import { buildControls, type ControlState } from "../src/ui/controls";
import { internetNl, type NlStatus } from "./internetnl";
import { browserFetch, consensus } from "./truth";

/**
 * The auditor against internet.nl, check by check (`pnpm validate:nl`). They must
 * agree unless the difference is one of the explained criteria below; any other
 * difference fails and has to be understood before going on.
 */
const CORPUS = [
  "internet.nl",
  "nic.cz",
  "sidn.nl",
  "posteo.de",
  "tuta.com",
  "google.com",
  "microsoft.com",
  "cloudflare.com",
  "paypal.com",
  "boe.es",
  "correos.es",
  "elpais.com",
  "mercadona.es",
  "pccomponentes.com",
  "felixllorente.com",
  "example.com",
];

type Check = "SPF" | "DMARC" | "DKIM" | "DNSSEC" | "DANE";
const rows: string[] = [];

/**
 * Differences that are a matter of criterion, each found and explained in the
 * audit of 2026-09-30 (docs/validacion.md). Returns the reason, or null.
 */
function explained(check: Check, nl: NlStatus, state: ControlState, report: Report): string | null {
  const has = (id: string) => report.sections.some((s) => s.findings.some((f) => f.id === id));
  if (check === "DKIM" && nl === "pass" && state === "unknown") return "internet.nl mira si existe `_domainkey` (RFC 8020); el auditor sólo lo da por bueno si encuentra la clave";
  if (check === "DKIM" && state === "info" && has("dkim.revoked")) return "sólo se encontraron claves revocadas";
  if (check === "DMARC" && nl === "pass" && state === "warn" && (has("dmarc.no-rua") || has("dmarc.sp-none"))) return "el auditor avisa también sin `rua` o con `sp=none`";
  if (check === "DMARC" && nl === "reco" && state === "ok") return "internet.nl exige `v=DMARC1;` con `;` en la autorización externa; RFC 9990, sección 4, paso 6, lo hace opcional";
  if (check === "SPF" && nl === "pass" && state === "warn" && has("spf.no-senders")) return "el auditor avisa de un SPF que no autoriza a nadie";
  return null;
}

async function auditOf(domain: string): Promise<Report> {
  return audit({ kind: "domain", name: domain }, { fetch: browserFetch, resolver: createResolver(), secondOpinion: (p, n, t) => queryProvider(p, n, t) });
}

describe.each(CORPUS)("%s", (domain) => {
  it("coincide con internet.nl o la diferencia está explicada", async () => {
    const [nl, report] = await Promise.all([internetNl(domain), auditOf(domain)]);
    const state = (id: string): ControlState => buildControls(report).flatMap((g) => g.controls).find((c) => c.id === id)?.state ?? "na";
    const t = nl.tests;
    const checks: Array<[Check, NlStatus | undefined, ControlState, (n: NlStatus, a: ControlState) => boolean]> = [
      ["SPF", t["SPF policy"], state("spf"), (n, a) => (n === "pass") === (a === "ok")],
      ["DMARC", t["DMARC policy"], state("dmarc"), (n, a) => (n === "pass") === (a === "ok")],
      ["DKIM", t["DKIM existence"], state("dkim"), (n, a) => (n === "pass") === (a === "ok" || a === "warn") || a === "na"],
      ["DNSSEC", t["DNSSEC existence"] === "pass" ? t["DNSSEC validity"] : t["DNSSEC existence"], state("dnssec"), (n, a) => (n === "pass") === (a === "ok")],
      ["DANE", t["DANE existence"] === "pass" ? t["DANE validity"] : t["DANE existence"], state("dane"), (n, a) => (n === "pass") === (a === "ok")],
    ];
    const unexplained: string[] = [];
    const cells: string[] = [];
    for (const [check, nlStatus, auditorState, same] of checks) {
      if (!nlStatus || nlStatus === "not-tested" || nlStatus === "error") {
        cells.push(`${check}: internet.nl no lo probó`);
        continue;
      }
      if (same(nlStatus, auditorState)) continue;
      let reason = explained(check, nlStatus, auditorState, report);
      // DANE: when they differ, the DNS itself decides (nic.cz, 2026-09-30: internet.nl saw no TLSA that delv validated).
      if (!reason && check === "DANE") {
        const mail = report.sections.find((s) => s.id === "mail")?.records ?? [];
        const hosts = mail.filter((r) => r.type === "MX").map((r) => r.data.split(" ")[1] ?? "").filter(Boolean);
        const tlsa = await Promise.all(hosts.map((h) => consensus(`_25._tcp.${h}`, "TLSA")));
        if (hosts.length && tlsa.every((x) => x.data.length > 0 && x.ad) === (auditorState === "ok")) reason = "el DNS (dos resolvedores, TLSA validado) da la razón al auditor";
      }
      cells.push(`${check}: internet.nl ${nlStatus}, auditor ${auditorState}${reason ? ` (${reason})` : " ≠"}`);
      if (!reason) unexplained.push(`${check}: internet.nl ${nlStatus} ≠ auditor ${auditorState}`);
    }
    rows.push(`| ${domain} | ${cells.join("<br>") || "coinciden"} | ${nl.url} |`);
    expect(unexplained, `${domain}: diferencias sin explicar con internet.nl`).toEqual([]);
  });
});

afterAll(() => {
  writeFileSync("validation/out/INTERNETNL.md", ["| Dominio | Diferencias | Informe de internet.nl |", "| --- | --- | --- |", ...rows].join("\n") + "\n");
});
