import { describe, expect, it } from "vitest";
import { checkDane, checkDnssecAlgorithms, checkSoa, checkWildcard } from "../src/core/dnsextra";
import { fakeResolver } from "./helpers";

describe("DNSSEC algorithms (RFC 9904)", () => {
  it("accepts ECDSA P-256 with SHA-256", () => {
    expect(checkDnssecAlgorithms(["2371 13 2 ab6b26"]).map((f) => f.id)).toEqual(["dnssec.algorithm"]);
  });
  it("flags RSASHA1 and a DS that only has SHA-1", () => {
    expect(checkDnssecAlgorithms(["123 5 1 abcd"]).map((f) => f.id)).toEqual(["dnssec.weak-algorithm", "dnssec.weak-digest"]);
  });
  it("does not flag SHA-1 when SHA-256 is also published", () => {
    expect(checkDnssecAlgorithms(["123 8 1 abcd", "123 8 2 ef01"]).map((f) => f.id)).toEqual(["dnssec.algorithm"]);
  });
});

describe("SOA timers", () => {
  it("only flags contradictions", () => {
    expect(checkSoa("ns1. hostmaster. 1 10000 2400 604800 1800")[0]?.id).toBe("dns.soa");
    expect(checkSoa("ns1. hostmaster. 1 3600 7200 604800 1800")[0]?.id).toBe("dns.soa-inconsistent");
  });
});

describe("wildcard", () => {
  it("detects a zone where any name resolves", async () => {
    const probe = "da-check-1.example.com";
    const seed = 1 / 1e10;
    const wild = await checkWildcard("example.com", fakeResolver({ [`${probe} A`]: ["192.0.2.1"] }), seed);
    expect(wild.findings[0]?.id).toBe("dns.wildcard");
    const none = await checkWildcard("example.com", fakeResolver({}, { nxdomain: [probe] }), seed);
    expect(none.findings[0]?.id).toBe("dns.no-wildcard");
  });
});

describe("DANE", () => {
  it("needs a DNSSEC-validated TLSA answer", async () => {
    const zone = { "_25._tcp.mx.example.net TLSA": ["3 1 1 abcdef"] };
    expect((await checkDane(["mx.example.net"], fakeResolver(zone, { ad: true }))).findings[0]?.id).toBe("mx.dane");
    expect((await checkDane(["mx.example.net"], fakeResolver(zone))).findings[0]?.id).toBe("mx.dane-unsigned");
    expect((await checkDane(["mx.example.net"], fakeResolver({}))).findings[0]?.id).toBe("mx.no-dane");
  });
});
