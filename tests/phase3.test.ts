import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import { audit } from "../src/core/audit";
import { checkDkim } from "../src/core/dkim";
import { checkDmarc, sameOrganisation } from "../src/core/dmarc";
import { checkDane } from "../src/core/dnsextra";
import type { DnsAnswer } from "../src/core/doh";
import { checkMx, checkMxHosts, parseMx } from "../src/core/mail";
import { fakeResolver, noFetch } from "./helpers";

/** Defects found in the audit of 2026-09-30 and fixed in phase 3. */
const ids = (f: { id: string }[]) => f.map((x) => x.id);
const rsaKey = () => generateKeyPairSync("rsa", { modulusLength: 2048 }).publicKey.export({ type: "spki", format: "der" }).toString("base64");

describe("DMARC report destinations (RFC 9990, section 4)", () => {
  it("flags an external address that has not authorised the reports (a Gmail mailbox)", async () => {
    const r = await checkDmarc("example.com", fakeResolver({ "_dmarc.example.com TXT": ["v=DMARC1; p=reject; rua=mailto:someone@gmail.com"] }));
    expect(r.findings.find((f) => f.id === "dmarc.rua-unauthorized")).toMatchObject({ status: "warn", params: { hosts: "gmail.com", domain: "example.com" } });
    expect(ids(r.findings)).not.toContain("dmarc.rua");
  });

  it("accepts an authorised one, with or without the final semicolon", async () => {
    const zone = {
      "_dmarc.example.com TXT": ["v=DMARC1; p=reject; rua=mailto:a@reports.example.net,mailto:b@example.com"],
      "example.com._report._dmarc.reports.example.net TXT": ["v=DMARC1"],
    };
    const r = await checkDmarc("example.com", fakeResolver(zone));
    expect(ids(r.findings)).toContain("dmarc.rua");
    expect(ids(r.findings)).not.toContain("dmarc.rua-unauthorized");
  });

  it("keeps the report addresses that work when only some are unauthorised", async () => {
    const r = await checkDmarc("example.com", fakeResolver({ "_dmarc.example.com TXT": ["v=DMARC1; p=reject; rua=mailto:d@example.com,mailto:x@other.example"] }));
    expect(ids(r.findings)).toEqual(expect.arrayContaining(["dmarc.rua", "dmarc.rua-unauthorized"]));
  });

  it("does not warn on a guess when the authorisation lookup fails", async () => {
    const r = await checkDmarc("example.com", fakeResolver({ "_dmarc.example.com TXT": ["v=DMARC1; p=reject; rua=mailto:x@other.example"] }, { servfail: ["example.com._report._dmarc.other.example"] }));
    expect(ids(r.findings)).not.toContain("dmarc.rua-unauthorized");
  });

  it("tells same organisation from another one without a suffix list", () => {
    expect(sameOrganisation("example.com", "dmarc.example.com")).toBe(true);
    expect(sameOrganisation("a.example.com", "b.example.com")).toBe(true);
    expect(sameOrganisation("bbva.es", "bbva.com")).toBe(false);
    expect(sameOrganisation("a.co.uk", "b.co.uk")).toBe(false);
  });
});

describe("MX targets", () => {
  it("flags an MX host that does not resolve and one that is an alias", async () => {
    const zone = { "mx2.example.com CNAME": ["mail.provider.example"], "mail.provider.example A": ["192.0.2.25"], "mx3.example.com A": ["192.0.2.26"] };
    const out = await checkMxHosts(["mx1.example.com", "mx2.example.com", "mx3.example.com"], fakeResolver(zone, { nxdomain: ["mx1.example.com"] }));
    expect(out).toEqual([
      { id: "mx.unresolvable", status: "fail", params: { hosts: "mx1.example.com" } },
      { id: "mx.cname", status: "warn", params: { hosts: "mx2.example.com → mail.provider.example" } },
    ]);
  });

  it("says nothing about a host whose lookup failed", async () => {
    expect(await checkMxHosts(["mx.example.com"], fakeResolver({}, { servfail: ["mx.example.com"] }))).toEqual([]);
  });

  it("flags a null MX next to other MX records (RFC 7505, section 3)", () => {
    const mx = parseMx([
      { name: "example.com", type: "MX", ttl: 1, data: "0 " },
      { name: "example.com", type: "MX", ttl: 1, data: "10 mx.example.com" },
    ]);
    expect(ids(checkMx(mx))).toEqual(["mx.null-mixed"]);
  });
});

describe("audited name that is an alias", () => {
  it("does not suggest records at a CNAME and says it is an alias (RFC 1034, section 3.6.2)", async () => {
    const zone = { "www.example.com CNAME": ["example.herokudns.com"], "example.herokudns.com A": ["192.0.2.1"] };
    const report = await audit({ kind: "domain", name: "www.example.com" }, { resolver: fakeResolver(zone), fetch: noFetch });
    const all = report.sections.flatMap((s) => s.findings);
    expect(all.flatMap((f) => f.suggest ?? []).filter((s) => s.name === "www.example.com")).toEqual([]);
    expect(all.find((f) => f.id === "dns.alias")?.params).toEqual({ name: "www.example.com", target: "example.herokudns.com" });
  });
});

describe("DKIM", () => {
  it("does not accept an unknown key type (RFC 6376, section 3.6.1)", async () => {
    const r = await checkDkim("example.com", fakeResolver({ "s1._domainkey.example.com TXT": ["v=DKIM1; k=foo; p=AAAA"] }), ["s1"]);
    expect(r.findings[0]).toMatchObject({ id: "dkim.unknown-type", status: "warn" });
  });

  it("fails a key limited to SHA-1 (RFC 8301, section 3.1)", async () => {
    const r = await checkDkim("example.com", fakeResolver({ "s1._domainkey.example.com TXT": [`v=DKIM1; h=sha1; k=rsa; p=${rsaKey()}`] }), ["s1"]);
    expect(r.findings[0]).toMatchObject({ id: "dkim.sha1", status: "fail" });
    const both = await checkDkim("example.com", fakeResolver({ "s1._domainkey.example.com TXT": [`v=DKIM1; h=sha1:sha256; p=${rsaKey()}`] }), ["s1"]);
    expect(both.findings[0]?.id).toBe("dkim.found");
  });

  /** NXDOMAIN for names that do not exist, as a real zone without wildcard answers. */
  const strict = (zone: Record<string, string[]>, exists: string[]) => {
    const base = fakeResolver(zone);
    return async (n: string, t: "TXT"): Promise<DnsAnswer> => (exists.includes(n) || zone[`${n} ${t}`] ? base(n, t) : { status: 3, ad: false, answers: [], provider: "fake" });
  };

  it("tells no keys at all from keys under an unknown selector (RFC 8020, section 2)", async () => {
    const none = await checkDkim("example.com", strict({}, []) as never, ["s1"]);
    expect(none.findings[0]).toMatchObject({ id: "dkim.no-domainkey", status: "warn" });
    const hidden = await checkDkim("example.com", strict({}, ["_domainkey.example.com"]) as never, ["s1"]);
    expect(hidden.findings[0]).toMatchObject({ id: "dkim.selector-unknown", status: "info" });
  });

  it("concludes nothing in a zone with a wildcard", async () => {
    const r = await checkDkim("example.com", fakeResolver({}), ["s1"]);
    expect(r.findings[0]?.id).toBe("dkim.not-found");
  });
});

describe("DANE (RFC 7672, section 2.2.1)", () => {
  const tlsa = { "_25._tcp.mx1.example.com TLSA": ["3 1 1 ab"] };

  it("checks every MX and flags those without TLSA", async () => {
    const r = await checkDane(["mx1.example.com", "mx2.example.com", "mx3.example.com", "mx4.example.com"], fakeResolver(tlsa, { ad: true }));
    expect(r.findings.find((f) => f.id === "mx.dane-partial")?.params).toEqual({ hosts: "mx2.example.com, mx3.example.com, mx4.example.com" });
  });

  it("notes when the domain's own MX answer is not signed", async () => {
    const r = await checkDane(["mx1.example.com"], fakeResolver(tlsa, { ad: true }), false);
    expect(ids(r.findings)).toEqual(["mx.dane", "mx.dane-insecure-mx"]);
  });
});

describe("DNSSEC failure (RFC 8914)", () => {
  const servfail = (ede?: string) => async (): Promise<DnsAnswer> => ({ status: 2, ad: false, answers: [], provider: "fake", ...(ede ? { ede } : {}) });

  it("tells a broken signature from a dead zone by the Extended DNS Error", async () => {
    const broken = await audit({ kind: "domain", name: "example.com" }, { resolver: servfail("EDE(9): DNSKEY Missing"), fetch: noFetch });
    expect(broken.sections[0]!.findings).toEqual([{ id: "dns.dnssec-broken", status: "fail", params: { name: "example.com", ede: "EDE(9): DNSKEY Missing" } }]);
    const dead = await audit({ kind: "domain", name: "example.com" }, { resolver: servfail("EDE(22): No Reachable Authority"), fetch: noFetch });
    expect(dead.sections[0]!.findings[0]?.id).toBe("dns.servfail");
  });

  it("or by asking again with checking disabled", async () => {
    const ok: DnsAnswer = { status: 0, ad: false, answers: [], provider: "fake" };
    const report = await audit({ kind: "domain", name: "example.com" }, { resolver: servfail(), fetch: noFetch, checkingDisabled: async () => ok });
    expect(report.sections[0]!.findings[0]?.id).toBe("dns.dnssec-broken");
  });
});
