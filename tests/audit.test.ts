import { describe, expect, it } from "vitest";
import { audit, lockFindings, summarizeCaa } from "../src/core/audit";
import { MESSAGES } from "../src/i18n";
import { buildControls } from "../src/ui/controls";
import { fakeResolver, noFetch, rdapFetch } from "./helpers";

const zone = {
  "example.com SOA": ["ns1.example.net. hostmaster.example.com. 1 7200 3600 1209600 300"],
  "example.com NS": ["ns1.example.net", "ns2.example.net"],
  "example.com A": ["192.0.2.10"],
  "example.com MX": ["10 mx.example.com"],
  "example.com TXT": ["v=spf1 mx -all"],
  "example.com DS": ["2371 13 2 ab"],
  "_dmarc.example.com TXT": ["v=DMARC1; p=reject; rua=mailto:d@example.com"],
};

describe("audit", () => {
  it("builds a domain report", async () => {
    const report = await audit({ kind: "domain", name: "example.com" }, { resolver: fakeResolver(zone, { ad: true }), fetch: noFetch });
    expect(report.sections.map((s) => s.id)).toEqual(["mail", "dns", "registration"]);
    const ids = report.sections.flatMap((s) => s.findings.map((f) => f.id));
    expect(ids).toEqual(
      expect.arrayContaining(["mx.found", "spf.all-fail", "dmarc.p-reject", "dkim.not-found", "dns.ns", "dns.dnssec", "dns.caa-missing", "dns.no-ipv6", "reg.unavailable"]),
    );
  });

  it("never suggests an invented mailbox", async () => {
    const report = await audit({ kind: "domain", name: "example.com" }, { resolver: fakeResolver({ "example.com MX": ["10 mx.example.com"] }), fetch: noFetch });
    for (const f of report.sections.flatMap((s) => s.findings)) {
      for (const sug of f.suggest ?? []) {
        expect(sug.value, f.id).not.toMatch(/mailto:(?!\{mailbox\})/);
        if (sug.value.includes("{mailbox}")) expect(sug.input, f.id).toBe("mailbox");
      }
    }
  });

  it("stops at NXDOMAIN", async () => {
    const report = await audit({ kind: "domain", name: "nope.example" }, { resolver: fakeResolver({}, { nxdomain: ["nope.example"] }), fetch: noFetch });
    expect(report.sections).toEqual([{ id: "dns", findings: [{ id: "dns.nxdomain", status: "fail", params: { name: "nope.example" } }], records: [] }]);
  });

  it("checks reverse DNS of an IP", async () => {
    const resolver = fakeResolver({
      "10.0.2.198.in-addr.arpa PTR": ["mail.example.com"],
      "mail.example.com A": ["198.0.2.10"],
    });
    const report = await audit({ kind: "ip", ip: "198.2.0.10", version: 4 }, { resolver, fetch: noFetch });
    const ids = report.sections[0]?.findings.map((f) => f.id);
    // No RDAP answer in this test: the missing holder is said, not left out.
    expect(ids).toEqual(["ip.ptr", "ip.no-fcrdns", "ip.not-announced", "ip.registry-unknown", "intel.shodan-none", "intel.unavailable"]);
  });

  it("skips special-purpose addresses", async () => {
    const report = await audit({ kind: "ip", ip: "192.168.1.1", version: 4 }, { resolver: fakeResolver({}), fetch: noFetch });
    expect(report.sections[0]?.findings[0]?.id).toBe("ip.special");
  });
});

describe("i18n", () => {
  it("has the same keys in both languages", () => {
    expect(Object.keys(MESSAGES.en).sort()).toEqual(Object.keys(MESSAGES.es).sort());
  });

  it("gives every finding a technical detail, so the fold is never empty", () => {
    const missing = Object.entries(MESSAGES.es).filter(([, m]) => !m.tech).map(([id]) => id);
    expect(missing).toEqual([]);
  });

  it("has the same layers and number of steps in both languages", () => {
    for (const [id, es] of Object.entries(MESSAGES.es)) {
      const en = MESSAGES.en[id];
      expect(Boolean(en?.what), id).toBe(Boolean(es.what));
      expect(Boolean(en?.tech), id).toBe(Boolean(es.tech));
      expect(en?.steps?.length ?? 0, id).toBe(es.steps?.length ?? 0);
      expect(Boolean(en?.context), id).toBe(Boolean(es.context));
    }
  });
});

describe("summarizeCaa", () => {
  it("groups by tag and removes duplicates", () => {
    const caa = summarizeCaa([
      '0 iodef "mailto:tls-abuse@example.com"',
      '0 issue "digicert.com; cansignhttpexchanges=yes"',
      '0 issue "letsencrypt.org"',
      '0 issuewild "digicert.com; cansignhttpexchanges=yes"',
      '0 issuewild "letsencrypt.org"',
    ]);
    expect(caa.issue).toEqual(["digicert.com", "letsencrypt.org"]);
    expect(caa.params).toEqual({
      issuers: "digicert.com, letsencrypt.org",
      detail: "issue: digicert.com, letsencrypt.org · issuewild: digicert.com, letsencrypt.org · iodef: mailto:tls-abuse@example.com",
    });
  });

  it("shows a forbidden wildcard and a CAA with no issue", () => {
    expect(summarizeCaa(['0 issue "letsencrypt.org"', '0 issuewild ";"']).params.detail).toBe("issue: letsencrypt.org · issuewild: —");
    expect(summarizeCaa(['0 iodef "mailto:a@example.com"']).issue).toEqual([]);
  });
});

describe("mail context", () => {
  it("treats DKIM as not applicable and suggests DMARC reject when the domain declares no mail", async () => {
    const report = await audit(
      { kind: "domain", name: "example.com" },
      { resolver: fakeResolver({ "example.com MX": ["0 ."], "example.com TXT": ["v=spf1 -all"], "example.com A": ["192.0.2.1"] }), fetch: noFetch },
    );
    const mail = report.sections.find((s) => s.id === "mail")!.findings;
    expect(report.identity?.mailUsage).toBe("disabled");
    expect(mail.map((f) => f.id)).toContain("dkim.not-applicable");
    expect(mail.find((f) => f.id === "dmarc.missing-nomail")?.suggest?.[0]?.value).toBe("v=DMARC1; p=reject;");
  });

  it("starts DMARC at none when it is unknown whether the domain uses mail", async () => {
    const report = await audit({ kind: "domain", name: "example.com" }, { resolver: fakeResolver({ "example.com A": ["192.0.2.1"] }), fetch: noFetch });
    const mail = report.sections.find((s) => s.id === "mail")!.findings;
    expect(report.identity?.mailUsage).toBe("unknown");
    expect(mail.find((f) => f.id === "dmarc.missing")?.suggest?.[0]?.value).toMatch(/p=none/);
  });

  it("keeps the monitoring-first DMARC advice when the domain uses mail", async () => {
    const report = await audit(
      { kind: "domain", name: "example.com" },
      { resolver: fakeResolver({ "example.com MX": ["10 mx.example.net"], "example.com TXT": ["v=spf1 mx -all"] }), fetch: noFetch },
    );
    const mail = report.sections.find((s) => s.id === "mail")!.findings;
    expect(report.identity?.mailUsage).toBe("active");
    expect(mail.find((f) => f.id === "dmarc.missing")?.suggest?.[0]?.value).toMatch(/p=none/);
  });
});

describe("lookups that fail are never read as missing records", () => {
  const zone = {
    "example.com SOA": ["ns1.example.net. hostmaster.example.com. 1 7200 3600 1209600 300"],
    "example.com NS": ["ns1.example.net", "ns2.example.net"],
  };
  const all = (r: Awaited<ReturnType<typeof audit>>) => r.sections.flatMap((s) => s.findings);

  it("does not propose a null MX when the MX lookup failed", async () => {
    const report = await audit({ kind: "domain", name: "example.com" }, { resolver: fakeResolver(zone, { servfail: [] }), fetch: noFetch });
    // Control: with a real "no MX" the no-mail records are proposed…
    expect(all(report).find((f) => f.id === "mx.none")?.suggest?.some((s) => s.type === "MX")).toBe(true);
    // …but not when the answer was SERVFAIL.
    const failing = fakeResolver(zone);
    const resolver: typeof failing = async (n, t) => (t === "MX" ? { status: 2, ad: false, answers: [], provider: "fake" } : failing(n, t));
    const broken = await audit({ kind: "domain", name: "example.com" }, { resolver, fetch: noFetch });
    const findings = all(broken);
    expect(findings.find((f) => f.id === "mx.lookup-error")).toMatchObject({ status: "info" });
    expect(findings.some((f) => f.id === "mx.none")).toBe(false);
    expect(findings.flatMap((f) => f.suggest ?? []).some((s) => s.value === "0 ." || s.value === "v=spf1 -all")).toBe(false);
    expect(broken.identity?.mailUsage).toBe("unknown");
    // Nor DMARC straight at reject: the domain may well send mail.
    expect(findings.find((f) => f.id.startsWith("dmarc.missing"))?.suggest?.[0]?.value).toMatch(/p=none/);
  });

  it("does not propose an SPF when the TXT lookup failed", async () => {
    const base = fakeResolver(zone);
    const resolver: typeof base = async (n, t) => (n === "example.com" && t === "TXT" ? { status: 2, ad: false, answers: [], provider: "fake" } : base(n, t));
    const findings = all(await audit({ kind: "domain", name: "example.com" }, { resolver, fetch: noFetch }));
    expect(findings.find((f) => f.id === "spf.lookup-error")).toMatchObject({ status: "info", params: { name: "example.com" } });
    expect(findings.some((f) => f.id.startsWith("spf.missing"))).toBe(false);
  });

  it("warns that CAs may refuse to issue when the CAA lookup fails, instead of proposing a CAA", async () => {
    const base = fakeResolver(zone);
    const resolver: typeof base = async (n, t) => (t === "CAA" ? { status: 2, ad: false, answers: [], provider: "fake" } : base(n, t));
    const findings = all(await audit({ kind: "domain", name: "example.com" }, { resolver, fetch: noFetch }));
    expect(findings.find((f) => f.id === "dns.caa-lookup-error")).toMatchObject({ status: "warn", params: { name: "example.com" } });
    expect(findings.some((f) => f.id.startsWith("dns.caa-missing"))).toBe(false);
  });
});

describe("CAA that restricts nothing (microsoft.com)", () => {
  it("is a warning, not a passed control", async () => {
    const zone = {
      "example.com SOA": ["ns1.example.net. hostmaster.example.com. 1 7200 3600 1209600 300"],
      "example.com NS": ["ns1.example.net", "ns2.example.net"],
      "example.com CAA": ['0 contactemail "caa@example.com"', '0 issuewild "digicert.com"'],
    };
    const report = await audit({ kind: "domain", name: "example.com" }, { resolver: fakeResolver(zone), fetch: noFetch });
    const caa = buildControls(report).flatMap((g) => g.controls).find((c) => c.id === "caa");
    expect(caa?.state).toBe("warn");
    expect(caa?.findings.map(({ f }) => f.id)).toEqual(["dns.caa-no-issue"]);
  });
});

describe("registry statuses (RFC 5731, section 2.3; RFC 9083, section 10.2.2)", () => {
  const ids = (status: string[], name = "example.com") => lockFindings(status, name).map((f) => `${f.id}:${f.status}`);

  it("reads the generic RDAP `locked` as a registry lock (sidn.nl)", () => {
    expect(ids(["locked"], "sidn.nl")).toEqual(["reg.transfer-lock:ok", "reg.registry-lock:ok"]);
  });

  it("does not call a single server transfer prohibition a registry lock (nic.cz)", () => {
    expect(ids(["server transfer prohibited"], "nic.cz")).toEqual(["reg.transfer-lock:ok"]);
  });

  it("calls the three server prohibitions a registry lock, in RDAP or EPP spelling", () => {
    expect(ids(["server update prohibited", "server delete prohibited", "server transfer prohibited"])).toContain("reg.registry-lock:ok");
    expect(ids(["serverUpdateProhibited", "serverDeleteProhibited", "serverTransferProhibited", "clientTransferProhibited"])).toContain("reg.registry-lock:ok");
    expect(ids(["transfer prohibited"])).toEqual(["reg.transfer-lock:ok"]);
  });

  it("fails a domain on hold, in redemption or pending deletion", () => {
    expect(ids(["client hold", "client transfer prohibited"])).toContain("reg.hold:fail");
    expect(ids(["redemption period", "pending delete"])).toEqual(["reg.redemption:fail", "reg.no-transfer-lock:warn"]);
    expect(ids(["pending delete"])).toContain("reg.pending-delete:fail");
  });

  it("keeps the lock unknown on a country registry without EPP statuses (internet.nl)", () => {
    expect(ids(["active"], "internet.nl")).toEqual(["reg.lock-unknown:info"]);
    expect(ids(["active"], "example.com")).toEqual(["reg.no-transfer-lock:warn"]);
  });

  it("puts a redemption period under the expiry control, where it counts", async () => {
    const zone = { "example.com SOA": ["ns1.example.net. h.example.com. 1 7200 3600 1209600 300"], "example.com NS": ["ns1.example.net", "ns2.example.net"] };
    const report = await audit({ kind: "domain", name: "example.com" }, { resolver: fakeResolver(zone), fetch: rdapFetch(["redemption period"]) });
    expect(buildControls(report).flatMap((g) => g.controls).find((c) => c.id === "expiry")?.state).toBe("fail");
  });
});
