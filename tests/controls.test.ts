import { describe, expect, it } from "vitest";
import type { Report } from "../src/core/types";
import { buildControls, controlIdOf, hasGap, scoreOf, severityOf, stateOf, type Control } from "../src/ui/controls";

describe("controlIdOf", () => {
  it("puts every finding about a topic in the same control", () => {
    expect(["spf.found", "spf.softfail", "spf.lookups"].map(controlIdOf)).toEqual(["spf", "spf", "spf"]);
    expect(controlIdOf("dns.caa-missing-cloudflare")).toBe("caa");
    expect(controlIdOf("dns.dnssec-both")).toBe("dnssec");
    expect(controlIdOf("dns.no-ipv6")).toBe("address");
    expect(controlIdOf("reg.no-transfer-lock")).toBe("lock");
    expect(controlIdOf("ip.fcrdns")).toBe("ptr");
    expect(controlIdOf("something.new")).toBe("other");
  });
});

describe("stateOf", () => {
  it("separates not applicable and not verified from plain information", () => {
    expect(stateOf([{ id: "dkim.not-applicable", status: "info" }])).toBe("na");
    expect(stateOf([{ id: "dkim.not-found", status: "info" }])).toBe("unknown");
  });

  it("takes the most severe state, and optional when only informational", () => {
    expect(stateOf([{ id: "a", status: "ok" }, { id: "b", status: "warn" }])).toBe("warn");
    expect(stateOf([{ id: "a", status: "info" }], true)).toBe("optional");
    expect(stateOf([{ id: "a", status: "info" }])).toBe("info");
  });
});

describe("buildControls", () => {
  const report: Report = {
    query: "example.com",
    kind: "domain",
    generatedAt: "2026-09-27T10:00:00.000Z",
    resolverCheck: [{ name: "example.com", type: "CAA", providers: ["cloudflare", "google"], answers: [[], []], same: true, ad: [true, true] }],
    sections: [
      { id: "mail", findings: [{ id: "mta-sts.missing", status: "info" }, { id: "spf.found", status: "ok" }], records: [] },
      { id: "dns", findings: [{ id: "dns.caa-missing", status: "warn" }, { id: "dns.nuevo", status: "info" }], records: [] },
    ],
  };
  const groups = buildControls(report);

  it("groups controls by area in a fixed order and keeps unmapped findings", () => {
    expect(groups.map((g) => `${g.id}: ${g.controls.map((c) => `${c.id}=${c.state}`).join(",")}`)).toEqual([
      "mail-auth: spf=ok",
      "mail-transport: mta-sts=optional",
      "dns-infra: other=info",
      "dns-integrity: caa=warn",
    ]);
  });

  it("attaches the resolver comparison of the control's query", () => {
    const caa = groups.flatMap((g) => g.controls).find((c) => c.id === "caa")!;
    expect(caa.check?.same).toBe(true);
  });
});

describe("scoreOf", () => {
  const domainReport = (findings: Report["sections"][number]["findings"]): Report => ({
    query: "example.com",
    kind: "domain",
    generatedAt: "2026-09-27T10:00:00.000Z",
    sections: [{ id: "mail", findings, records: [] }],
  });

  it("always counts the same 8 basic controls for a domain", () => {
    const report = domainReport([
      { id: "spf.found", status: "ok" },
      { id: "dkim.not-found", status: "info" },
      { id: "tls-rpt.found", status: "ok" },
    ]);
    expect(scoreOf(report, buildControls(report))).toEqual({ passed: 1, total: 8, notApplicable: 0, unverified: 7, extras: 1, extrasTotal: 4 });
  });

  it("leaves Certificate Transparency out, so a crt.sh outage does not change the score", () => {
    const base = [{ id: "spf.found", status: "ok" as const }];
    const up = domainReport([...base, { id: "ct.issuers-caa-ok", status: "ok" }, { id: "ct.no-takeover", status: "info" }]);
    const down = domainReport([...base, { id: "ct.unavailable", status: "info" }]);
    expect(scoreOf(up, buildControls(up))).toEqual(scoreOf(down, buildControls(down)));
  });

  it("never counts an unverified MTA-STS policy as a passed extra", () => {
    const report = domainReport([{ id: "mta-sts.unverified", status: "info" }]);
    const mtaSts = buildControls(report).flatMap((g) => g.controls).find((c) => c.id === "mta-sts");
    expect(mtaSts?.state).toBe("unknown");
    expect(scoreOf(report, buildControls(report)).extras).toBe(0);
  });
});

describe("stateOf", () => {
  it("does not call a control ok when part of it could not be checked", () => {
    expect(stateOf([{ id: "spf.found", status: "ok" }, { id: "spf.include-error", status: "info" }])).toBe("unknown");
    expect(stateOf([{ id: "spf.found", status: "ok" }, { id: "spf.include-error", status: "info" }, { id: "spf.syntax", status: "fail" }])).toBe("fail");
    expect(stateOf([{ id: "mta-sts.unverified", status: "info" }], true)).toBe("unknown");
    expect(stateOf([{ id: "mta-sts.missing", status: "info" }], true)).toBe("optional");
  });
});

describe("severity and risk", () => {
  const control = (id: string, findings: Array<[string, "ok" | "warn" | "fail" | "info"]>, state: Control["state"]): Control =>
    ({ id, group: "mail-auth", state, findings: findings.map(([fid, status]) => ({ f: { id: fid, status }, section: { id: "mail", findings: [], records: [] } })) }) as Control;

  it("only rates subdomains high for a claimable takeover", () => {
    expect(severityOf(control("subdomains", [["ct.takeover", "fail"]], "fail"))).toBe("high");
    expect(severityOf(control("subdomains", [["ct.dangling", "warn"]], "warn"))).toBe("low");
  });

  it("does not show the missing-DMARC risk for a DMARC at reject without reports", () => {
    expect(hasGap(control("dmarc", [["dmarc.no-rua", "warn"], ["dmarc.p-reject", "ok"]], "warn"))).toBe(false);
    expect(hasGap(control("dmarc", [["dmarc.p-none", "warn"]], "warn"))).toBe(true);
  });
});
