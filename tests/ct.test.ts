import { describe, expect, it } from "vitest";
import { caaAllows, checkSurface, issuerOrg, parseCaa, restrictingIds, subdomainsOf, type CtEntry } from "../src/core/ct";
import { fakeResolver } from "./helpers";

const entry = (names: string, issuer: string, notAfter = "2099-01-01T00:00:00"): CtEntry => ({
  issuer_name: issuer,
  name_value: names,
  not_before: "2026-01-01T00:00:00",
  not_after: notAfter,
});

const LE = "C=US, O=Let's Encrypt, CN=R11";
const DIGICERT = 'C=US, O="DigiCert, Inc.", CN=DigiCert TLS';

describe("certificate transparency", () => {
  it("lists subdomains without wildcards, the apex or other domains", () => {
    const e = [entry("example.com\nwww.example.com\n*.example.com", LE), entry("shop.example.com\nevil-example.com", LE)];
    expect(subdomainsOf(e, "example.com")).toEqual({ names: ["shop.example.com", "www.example.com"], wildcards: 1 });
  });

  it("reads the issuer organisation and matches it to CAA", () => {
    expect(issuerOrg(LE)).toBe("Let's Encrypt");
    expect(issuerOrg(DIGICERT)).toBe("DigiCert, Inc.");
    expect(caaAllows("Let's Encrypt", ["letsencrypt.org"])).toBe(true);
    expect(caaAllows("DigiCert, Inc.", ["letsencrypt.org"])).toBe(false);
    expect(caaAllows("Unknown CA", ["letsencrypt.org"])).toBeNull();
  });

  it("flags a dangling CNAME and certificates the CAA does not allow", async () => {
    const body = JSON.stringify([entry("old.example.com\nwww.example.com", LE), entry("www.example.com", DIGICERT), entry("x.example.com", DIGICERT, "2020-01-01T00:00:00")]);
    const fetchCt: typeof fetch = async () => new Response(body, { status: 200 });
    const resolver = fakeResolver(
      { "old.example.com CNAME": ["old-site.azurewebsites.net"], "www.example.com A": ["192.0.2.1"] },
      { nxdomain: ["old-site.azurewebsites.net"] },
    );
    const r = await checkSurface("example.com", resolver, ['0 issue "letsencrypt.org"'], { fetch: fetchCt, now: new Date("2026-09-27T00:00:00Z") });
    const byId = Object.fromEntries(r.findings.map((f) => [f.id, f]));
    expect(byId["ct.takeover"]?.params).toMatchObject({ host: "old.example.com", target: "old-site.azurewebsites.net", provider: "Microsoft Azure" });
    expect(byId["ct.issuer-not-caa"]?.params).toMatchObject({ issuers: "DigiCert Inc", names: "www.example.com (DigiCert Inc)" });
    expect(byId["ct.subdomains"]?.params).toMatchObject({ count: 3, alive: 1 });
  });

  it("accepts a certificate allowed by the CAA of its own name", async () => {
    const body = JSON.stringify([entry("cdn.example.com", DIGICERT)]);
    const resolver = fakeResolver({ "cdn.example.com CAA": ['0 issue "digicert.com"'], "cdn.example.com A": ["192.0.2.2"] });
    const r = await checkSurface("example.com", resolver, ['0 issue "letsencrypt.org"'], { fetch: async () => new Response(body), now: new Date("2026-09-27T00:00:00Z") });
    expect(r.findings.map((f) => f.id)).toContain("ct.issuers-caa-ok");
  });

  it("calls a dangling CNAME to a provider-assigned name an orphan, not a takeover, and flags private addresses", async () => {
    const body = JSON.stringify([entry("app.example.com\nintranet.example.com", LE)]);
    const resolver = fakeResolver(
      { "app.example.com CNAME": ["internal-k8s-abc-123.eu-west-1.elb.amazonaws.com"], "intranet.example.com A": ["192.168.1.35"] },
      { nxdomain: ["internal-k8s-abc-123.eu-west-1.elb.amazonaws.com"] },
    );
    const r = await checkSurface("example.com", resolver, [], { fetch: async () => new Response(body), now: new Date("2026-09-27T00:00:00Z") });
    const ids = r.findings.map((f) => f.id);
    expect(ids).toContain("ct.dangling");
    expect(ids).not.toContain("ct.takeover");
    expect(r.findings.find((f) => f.id === "ct.private-ips")?.params?.hosts).toBe("intranet.example.com");
  });

  it("knows every CAA identifier an authority accepts (posteo.de: DigiCert through geotrust.com)", () => {
    expect(caaAllows("DigiCert Inc", ["certum.pl", "d-trust.net", "geotrust.com"])).toBe(true);
    expect(caaAllows("DigiCert Inc", ["quovadisglobal.com"])).toBe(true);
    expect(caaAllows("Sectigo Limited", ["usertrust.com"])).toBe(true);
    expect(caaAllows("ZeroSSL", ["sectigo.com"])).toBe(true);
    expect(caaAllows("DigiCert Inc", ["letsencrypt.org"])).toBe(false);
  });

  it("reads issue and issuewild, keeping `;` as a ban on every authority", () => {
    const set = parseCaa(['0 issue "letsencrypt.org; validationmethods=dns-01"', '0 issuewild ";"', '0 iodef "mailto:a@example.com"']);
    expect(set).toEqual({ issue: ["letsencrypt.org"], wild: [""] });
    expect(restrictingIds(set, false)).toEqual(["letsencrypt.org"]);
    expect(restrictingIds(set, true)).toEqual([""]);
    expect(restrictingIds(parseCaa(['0 issuewild "digicert.com"']), false)).toEqual([]);
  });

  it("judges a wildcard certificate by issuewild (RFC 8659, section 4.3)", async () => {
    const body = JSON.stringify([entry("*.example.com\nexample.com", DIGICERT)]);
    const ok = await checkSurface("example.com", fakeResolver({}), ['0 issue "letsencrypt.org"', '0 issuewild "digicert.com"'], {
      fetch: async () => new Response(body),
      now: new Date("2026-09-27T00:00:00Z"),
    });
    // The apex name is issue-only (letsencrypt): that part breaks the CAA, the wildcard does not.
    expect(ok.findings.find((f) => f.id === "ct.issuer-not-caa")?.params?.names).toBe("example.com (DigiCert Inc)");
  });

  it("uses the CAA of the closest parent of a subdomain", async () => {
    const body = JSON.stringify([entry("a.shop.example.com", DIGICERT)]);
    const resolver = fakeResolver({ "shop.example.com CAA": ['0 issue "digicert.com"'] });
    const r = await checkSurface("example.com", resolver, ['0 issue "letsencrypt.org"'], { fetch: async () => new Response(body), now: new Date("2026-09-27T00:00:00Z") });
    expect(r.findings.map((f) => f.id)).toContain("ct.issuers-caa-ok");
  });

  it("reports the subdomains checked as information, with how many there were", async () => {
    const names = Array.from({ length: 45 }, (_, i) => `h${String(i).padStart(2, "0")}.example.com`).join("\n");
    const r = await checkSurface("example.com", fakeResolver({}), [], { fetch: async () => new Response(JSON.stringify([entry(names, LE)])) });
    expect(r.findings.find((f) => f.id === "ct.no-takeover")).toMatchObject({ status: "info", params: { checked: 40, count: 45 } });
  });

  it("says so when crt.sh does not answer", async () => {
    const r = await checkSurface("example.com", fakeResolver({}), [], { fetch: async () => new Response("", { status: 502 }) });
    expect(r.findings.map((f) => f.id)).toEqual(["ct.unavailable"]);
  });
});

describe("Certificate Transparency fallback", () => {
  const spotter = (n: number) =>
    JSON.stringify(
      Array.from({ length: n }, (_, i) => ({
        dns_names: [`h${i}.example.com`],
        issuer: { name: "C=US, O=Let's Encrypt, CN=R11" },
        not_before: "2026-09-01T00:00:00Z",
        not_after: "2026-12-01T00:00:00Z",
      })),
    );
  const fetchWith = (crtsh: number, body: string): typeof fetch => async (url) =>
    String(url).includes("crt.sh") ? new Response("", { status: crtsh }) : new Response(body, { status: 200 });
  const now = new Date("2026-10-01T00:00:00Z");

  it("uses Cert Spotter when crt.sh fails, and says so", async () => {
    const r = await checkSurface("example.com", fakeResolver({}), [], { fetch: fetchWith(502, spotter(3)), now });
    const ids = r.findings.map((f) => f.id);
    expect(ids).toContain("ct.fallback");
    expect(r.findings.find((f) => f.id === "ct.subdomains")?.params).toMatchObject({ count: 3 });
    expect(r.findings.find((f) => f.id === "ct.issuers")?.params).toMatchObject({ total: 3 });
    expect(r.caaIds).toEqual(["letsencrypt.org"]);
  });

  it("marks a full page as partial and proposes no CAA from it", async () => {
    const r = await checkSurface("example.com", fakeResolver({}), [], { fetch: fetchWith(404, spotter(100)), now });
    expect(r.findings.find((f) => f.id === "ct.partial")).toMatchObject({ status: "info", params: { source: "Cert Spotter", max: 100 } });
    expect(r.caaIds).toBeUndefined();
  });

  it("is unavailable only when both fail", async () => {
    const r = await checkSurface("example.com", fakeResolver({}), [], { fetch: async () => new Response("", { status: 503 }) });
    expect(r.findings.map((f) => f.id)).toEqual(["ct.unavailable"]);
  });
});
