import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import { checkDkim, rsaKeyBits } from "../src/core/dkim";
import { fakeResolver } from "./helpers";

function rsaKey(bits: number, format: "spki" | "pkcs1" = "spki"): string {
  const { publicKey } = generateKeyPairSync("rsa", { modulusLength: bits });
  return publicKey.export({ type: format, format: "der" }).toString("base64");
}

describe("rsaKeyBits", () => {
  it.each([1024, 2048, 4096])("measures a %i-bit SPKI key", (bits) => {
    expect(rsaKeyBits(rsaKey(bits))).toBe(bits);
  });

  it("reads a PKCS#1 RSAPublicKey", () => {
    expect(rsaKeyBits(rsaKey(2048, "pkcs1"))).toBe(2048);
  });

  it("returns null for garbage", () => {
    expect(rsaKeyBits("not base64!")).toBeNull();
    expect(rsaKeyBits("AAAA")).toBeNull();
  });
});

describe("checkDkim", () => {
  it("reports found, 1024-bit, revoked and testing selectors", async () => {
    const r = fakeResolver({
      "google._domainkey.example.com TXT": [`v=DKIM1; k=rsa; p=${rsaKey(2048)}`],
      "selector1._domainkey.example.com TXT": [`v=DKIM1; t=y; p=${rsaKey(1024)}`],
      "k1._domainkey.example.com TXT": ["v=DKIM1; p="],
    });
    const out = await checkDkim("example.com", r);
    expect(out.findings.map((f) => f.id)).toEqual(["dkim.found", "dkim.rsa-1024", "dkim.testing", "dkim.revoked"]);
    expect(out.findings[0]?.params).toEqual({ selector: "google", alg: "RSA", bits: 2048 });
    expect(out.records).toHaveLength(3);
  });

  it("is informative when nothing is found", async () => {
    const out = await checkDkim("example.com", fakeResolver({}), ["a", "b"]);
    expect(out.findings).toEqual([{ id: "dkim.not-found", status: "info", params: { count: 2 } }]);
  });
});

describe("delegated DKIM keys", () => {
  it("says who manages a key published through a CNAME", async () => {
    const r = fakeResolver({
      "k1._domainkey.example.com CNAME": ["dkim.mcsv.net"],
      "dkim.mcsv.net TXT": [`k=rsa; p=${rsaKey(1024)}`],
      "s1._domainkey.example.com CNAME": ["s1.domainkey.u1.wl1.sendgrid.net"],
      "s1.domainkey.u1.wl1.sendgrid.net TXT": [`k=rsa; p=${rsaKey(2048)}`],
    });
    const out = await checkDkim("example.com", r, ["k1", "s1"]);
    expect(out.findings).toEqual([
      { id: "dkim.rsa-1024-delegated", status: "warn", params: { selector: "k1", via: "dkim.mcsv.net", bits: 1024 } },
      { id: "dkim.found-delegated", status: "ok", params: { selector: "s1", via: "s1.domainkey.u1.wl1.sendgrid.net", alg: "RSA", bits: 2048 } },
    ]);
    // The records table shows the alias as well as the key.
    expect(out.records.map((x) => x.type)).toEqual(["CNAME", "TXT", "CNAME", "TXT"]);
  });
});

describe("user selectors", () => {
  it("cleans what the user types", async () => {
    const { cleanSelector } = await import("../src/core/dkim");
    expect(cleanSelector(" S1 ")).toBe("s1");
    expect(cleanSelector("selector1._domainkey.example.com")).toBe("selector1");
    expect(cleanSelector("bad selector")).toBeNull();
    expect(cleanSelector("")).toBeNull();
  });

  it("finds a key under a selector that is not in the common list", async () => {
    const { audit } = await import("../src/core/audit");
    const r = fakeResolver({ "example.com MX": ["10 mx.example.com"], "custom2026._domainkey.example.com TXT": [`v=DKIM1; p=${rsaKey(2048)}`] });
    const noFetch = (async () => new Response(null, { status: 404 })) as typeof fetch;
    const report = await audit({ kind: "domain", name: "example.com" }, { resolver: r, fetch: noFetch, dkimSelectors: ["custom2026"] });
    const ids = report.sections.flatMap((s) => s.findings.map((f) => f.id));
    expect(ids).toContain("dkim.found");
    expect(ids).not.toContain("dkim.not-found");
  });
});
