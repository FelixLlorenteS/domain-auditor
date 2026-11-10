import { describe, expect, it } from "vitest";
import { audit } from "../src/core/audit";
import { verdicts } from "../src/core/summary";
import { buildControls, scoreOf, severityOf } from "../src/ui/controls";
import { fakeResolver, rdapFetch } from "./helpers";

/** A website on a subdomain (like audit.felixllorente.com) of a domain that sends no mail from it. */
const zone = {
  "example.com SOA": ["ns1.example.net. hostmaster.example.com. 1 7200 3600 1209600 300"],
  "example.com NS": ["ns1.example.net", "ns2.example.net"],
  "example.com DS": ["2371 13 2 ab"],
  "example.com CAA": ['0 issue "letsencrypt.org"'],
  "_dmarc.example.com TXT": ["v=DMARC1; p=reject; sp=reject; rua=mailto:d@example.com"],
  "web.example.com A": ["192.0.2.10"],
};

describe("a subdomain is judged with what it inherits", () => {
  it("checks the name servers of its zone instead of leaving them unverified (RFC 1034, section 4.2)", async () => {
    const report = await audit({ kind: "domain", name: "web.example.com" }, { resolver: fakeResolver(zone, { ad: true }), fetch: rdapFetch(["client transfer prohibited"]) });
    const controls = buildControls(report).flatMap((g) => g.controls);
    const ns = controls.find((c) => c.id === "ns")!;
    expect(ns.findings.map(({ f }) => f.id)).toEqual(expect.arrayContaining(["dns.ns-parent", "dns.ns"]));
    expect(ns.state).toBe("ok");
    expect(report.sections.flatMap((s) => s.findings).find((f) => f.id === "dns.ns-parent")?.params).toEqual({ name: "web.example.com", zone: "example.com" });
  });

  it("says the inherited DMARC at reject applies, and that the missing SPF is hardening", async () => {
    const report = await audit({ kind: "domain", name: "web.example.com" }, { resolver: fakeResolver(zone, { ad: true }), fetch: rdapFetch(["client transfer prohibited"]) });
    expect(verdicts(report).find((v) => v.area === "spoofing")).toEqual({ area: "spoofing", level: "partial", reason: "no-mail-reject" });
    const spf = buildControls(report).flatMap((g) => g.controls).find((c) => c.id === "spf")!;
    expect(spf.state).toBe("warn");
    expect(severityOf(spf)).toBe("low");
  });

  it("keeps the SPF advice at medium severity without a DMARC at reject", async () => {
    const lax = { ...zone, "_dmarc.example.com TXT": ["v=DMARC1; p=none; rua=mailto:d@example.com"] };
    const report = await audit({ kind: "domain", name: "web.example.com" }, { resolver: fakeResolver(lax, { ad: true }), fetch: rdapFetch(["client transfer prohibited"]) });
    const spf = buildControls(report).flatMap((g) => g.controls).find((c) => c.id === "spf")!;
    expect(severityOf(spf)).toBe("medium");
  });

  it("with `v=spf1 -all` and a null MX it reaches a full score", async () => {
    const done = { ...zone, "web.example.com TXT": ["v=spf1 -all"], "web.example.com MX": ["0 ."] };
    const report = await audit({ kind: "domain", name: "web.example.com" }, { resolver: fakeResolver(done, { ad: true }), fetch: rdapFetch(["client transfer prohibited"]) });
    const score = scoreOf(report, buildControls(report));
    expect(score.passed).toBe(score.total);
  });
});
