import { describe, expect, it } from "vitest";
import { audit } from "../src/core/audit";
import { fetchCertificates } from "../src/core/ct";
import {
  checkHeaders,
  checkMtaStsPolicy,
  checkSecurityTxt,
  checkWeb,
  hstsMaxAge,
  mxMatches,
  parseMtaStsPolicy,
  REFUSED,
  type HttpResult,
  type TlsResult,
  type TlsVersion,
  type WebProbe,
} from "../src/core/web";
import { buildControls } from "../src/ui/controls";
import { fakeResolver, noFetch } from "./helpers";

const NOW = new Date("2026-11-10T00:00:00Z");
const inDays = (d: number) => new Date(NOW.getTime() + d * 86_400_000).toISOString();

type Answer = Partial<HttpResult> | Error;
const err = (code: string) => Object.assign(new Error(code), { code });

/** A website as a table of URL → answer, and TLS answers per offered version. */
function fakeProbe(pages: Record<string, Answer>, tls: Partial<Record<TlsVersion | "default", TlsResult | Error>> = {}): WebProbe {
  return {
    async request(url) {
      // Another path on a server that answers is a 404; a server not in the table refuses.
      const a = pages[url] ?? (pages[`${new URL(url).origin}/`] && !(pages[`${new URL(url).origin}/`] instanceof Error) ? { status: 404 } : undefined);
      if (!a) throw err("ECONNREFUSED");
      if (a instanceof Error) throw a;
      return { url, status: 200, headers: {}, body: "", ...a };
    },
    async tls(_host, version) {
      const a = tls[version ?? "default"] ?? (version ? err("ERR_SSL_TLSV1_ALERT_PROTOCOL_VERSION") : undefined);
      if (!a) throw err("ECONNREFUSED");
      if (a instanceof Error) throw a;
      return a;
    },
  };
}

const GOOD_TLS: TlsResult = { protocol: "TLSv1.3", authorized: true, cert: { subject: "example.com", issuer: "Let's Encrypt", validFrom: inDays(-30), validTo: inDays(60), san: ["example.com"] } };
const SECURE_HEADERS = {
  "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
  "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
  "x-content-type-options": "nosniff",
  "referrer-policy": "strict-origin-when-cross-origin",
};
const ids = (fs: Array<{ id: string }>) => fs.map((f) => f.id);

describe("HSTS", () => {
  it("reads max-age from the first header only (RFC 6797, sections 6.1.1 and 8.1)", () => {
    expect(hstsMaxAge("max-age=31536000; includeSubDomains")).toBe(31536000);
    expect(hstsMaxAge('max-age="600"')).toBe(600);
    expect(hstsMaxAge("includeSubDomains")).toBeNull();
    expect(hstsMaxAge("max-age=0, max-age=31536000")).toBe(0);
  });
});

describe("security headers", () => {
  it("accepts frame-ancestors or X-Frame-Options and judges each header apart", () => {
    expect(ids(checkHeaders(SECURE_HEADERS, "https://example.com/"))).toEqual(["hdr.frame", "hdr.nosniff", "hdr.csp", "hdr.referrer"]);
    const bare = checkHeaders({ server: "nginx/1.18.0" }, "https://example.com/");
    expect(ids(bare)).toEqual(["hdr.no-frame", "hdr.no-nosniff", "hdr.no-csp", "hdr.version-leak"]);
    expect(bare.find((f) => f.id === "hdr.no-csp")?.status).toBe("info");
    expect(ids(checkHeaders({ "x-frame-options": "sameorigin" }, "u"))).toContain("hdr.frame");
    expect(ids(checkHeaders({ "x-frame-options": "ALLOW-FROM https://x" }, "u"))).toContain("hdr.no-frame");
  });

  it("flags 'unsafe-inline' scripts and an unsafe referrer policy", () => {
    expect(ids(checkHeaders({ "content-security-policy": "script-src 'self' 'unsafe-inline'" }, "u"))).toContain("hdr.csp-unsafe");
    expect(ids(checkHeaders({ "content-security-policy": "default-src 'unsafe-inline'" }, "u"))).toContain("hdr.csp-unsafe");
    expect(ids(checkHeaders({ "content-security-policy": "default-src 'unsafe-inline'; script-src 'self'" }, "u"))).toContain("hdr.csp");
    expect(ids(checkHeaders({ "referrer-policy": "unsafe-url" }, "u"))).toContain("hdr.referrer-unsafe");
  });

  it("does not call a product name without a version a leak", () => {
    expect(ids(checkHeaders({ server: "cloudflare" }, "u"))).not.toContain("hdr.version-leak");
  });
});

describe("security.txt (RFC 9116)", () => {
  const url = "https://example.com/.well-known/security.txt";
  const txt = (body: string, type = "text/plain; charset=utf-8") => fakeProbe({ [url]: { body, headers: { "content-type": type } } });

  it("needs Contact and exactly one Expires in the future", async () => {
    expect((await checkSecurityTxt("example.com", txt(`Contact: mailto:s@example.com\nExpires: ${inDays(200)}`), NOW)).id).toBe("sectxt.found");
    expect((await checkSecurityTxt("example.com", txt(`Contact: mailto:s@example.com\nExpires: ${inDays(-1)}`), NOW)).id).toBe("sectxt.expired");
    expect((await checkSecurityTxt("example.com", txt("Contact: mailto:s@example.com"), NOW)).params?.missing).toBe("Expires");
    expect((await checkSecurityTxt("example.com", txt(`Expires: ${inDays(9)}\nExpires: ${inDays(10)}\nContact: x`), NOW)).id).toBe("sectxt.invalid");
  });

  it("does not take an HTML page answering every path for a security.txt", async () => {
    expect((await checkSecurityTxt("example.com", txt("<html>Contact: x</html>", "text/html"), NOW)).id).toBe("sectxt.missing");
    expect((await checkSecurityTxt("example.com", fakeProbe({ [url]: { status: 404 } }), NOW)).id).toBe("sectxt.missing");
  });

  it("says when it could not be checked", async () => {
    expect((await checkSecurityTxt("example.com", fakeProbe({ [url]: err("TIMEOUT") }), NOW)).id).toBe("sectxt.unavailable");
  });
});

describe("MTA-STS policy (RFC 8461)", () => {
  const url = "https://mta-sts.example.com/.well-known/mta-sts.txt";
  const policy = (body: string) => fakeProbe({ [url]: { body, headers: { "content-type": "text/plain" } } });
  const enforce = "version: STSv1\r\nmode: enforce\r\nmx: *.mail.example.net\r\nmx: mx.example.com\r\nmax_age: 604800\r\n";

  it("parses the policy and rejects malformed ones", () => {
    expect(parseMtaStsPolicy(enforce)).toEqual({ mode: "enforce", mx: ["*.mail.example.net", "mx.example.com"], maxAge: 604800 });
    expect(parseMtaStsPolicy("version: STSv2\nmode: enforce\nmx: a\nmax_age: 1")).toEqual({ error: "version" });
    expect(parseMtaStsPolicy("version: STSv1\nmode: strict\nmx: a\nmax_age: 1")).toEqual({ error: "mode" });
    expect(parseMtaStsPolicy("version: STSv1\nmode: enforce\nmx: a\nmax_age: 99999999")).toEqual({ error: "max_age" });
    expect(parseMtaStsPolicy("version: STSv1\nmode: enforce\nmax_age: 60")).toEqual({ error: "mx" });
  });

  it("matches a wildcard against exactly one label (section 4.1)", () => {
    expect(mxMatches("a.mail.example.net", "*.mail.example.net")).toBe(true);
    expect(mxMatches("a.b.mail.example.net", "*.mail.example.net")).toBe(false);
    expect(mxMatches("mail.example.net", "*.mail.example.net")).toBe(false);
    expect(mxMatches("MX.example.com.", "mx.example.com")).toBe(true);
  });

  it("is only ok in enforce mode covering every MX", async () => {
    expect((await checkMtaStsPolicy("example.com", ["a.mail.example.net", "mx.example.com"], policy(enforce))).id).toBe("mta-sts.enforce");
    const missing = await checkMtaStsPolicy("example.com", ["mx2.example.com"], policy(enforce));
    expect([missing.id, missing.params?.missing]).toEqual(["mta-sts.policy-mx", "mx2.example.com"]);
    expect((await checkMtaStsPolicy("example.com", ["mx.example.com"], policy(enforce.replace("enforce", "testing")))).id).toBe("mta-sts.policy-testing");
  });

  it("does not follow redirects and reports certificate errors (section 3.3)", async () => {
    expect((await checkMtaStsPolicy("example.com", [], fakeProbe({ [url]: { status: 301, headers: { location: "https://x/" } } }))).id).toBe("mta-sts.policy-redirect");
    expect((await checkMtaStsPolicy("example.com", [], fakeProbe({ [url]: err("CERT_HAS_EXPIRED") }))).id).toBe("mta-sts.policy-cert");
    expect((await checkMtaStsPolicy("example.com", [], fakeProbe({ [url]: { status: 404 } }))).id).toBe("mta-sts.policy-error");
  });
});

describe("checkWeb", () => {
  const site = (extra: Record<string, Answer> = {}) => ({
    "http://example.com/": { status: 301, headers: { location: "https://example.com/" } },
    "https://example.com/": { headers: SECURE_HEADERS },
    ...extra,
  });

  it("passes a well configured site", async () => {
    const out = await checkWeb("example.com", fakeProbe(site(), { default: GOOD_TLS }), NOW);
    expect(out.filter((f) => f.status === "warn" || f.status === "fail")).toEqual([]);
    expect(ids(out)).toEqual(expect.arrayContaining(["https.redirect", "https.hsts", "tls.cert", "tls.no-legacy", "sectxt.missing"]));
  });

  it("warns about plain HTTP, missing HSTS and old TLS versions", async () => {
    const probe = fakeProbe(site({ "http://example.com/": { status: 200 }, "https://example.com/": { headers: {} } }), {
      default: GOOD_TLS,
      TLSv1: { ...GOOD_TLS, protocol: "TLSv1" },
    });
    const out = await checkWeb("example.com", probe, NOW);
    expect(ids(out)).toEqual(expect.arrayContaining(["https.no-redirect", "https.no-hsts", "tls.legacy"]));
    expect(out.find((f) => f.id === "tls.legacy")?.params?.versions).toBe("TLS 1.0");
  });

  it("never reads an inconclusive old-version attempt as refused", async () => {
    const out = await checkWeb("example.com", fakeProbe(site(), { default: GOOD_TLS, TLSv1: err("CLIENT_UNSUPPORTED"), "TLSv1.1": err("TIMEOUT") }), NOW);
    expect(ids(out)).toContain("tls.legacy-unknown");
    expect(ids(out)).not.toContain("tls.no-legacy");
    expect(REFUSED.test("ERR_SSL_TLSV1_ALERT_PROTOCOL_VERSION")).toBe(true);
    expect(REFUSED.test("ECONNRESET")).toBe(true);
    expect(REFUSED.test("ERR_SSL_INVALID_DIGEST")).toBe(false);
  });

  it("fails an invalid or expiring certificate", async () => {
    const expired = await checkWeb("example.com", fakeProbe(site(), { default: { ...GOOD_TLS, authorized: false, authError: "CERT_HAS_EXPIRED" } }), NOW);
    expect(expired.find((f) => f.id === "tls.expired")?.status).toBe("fail");
    const wrong = await checkWeb("example.com", fakeProbe(site(), { default: { ...GOOD_TLS, authorized: false, authError: "ERR_TLS_CERT_ALTNAME_INVALID" } }), NOW);
    expect(ids(wrong)).toContain("tls.wrong-name");
    const soon = await checkWeb("example.com", fakeProbe(site(), { default: { ...GOOD_TLS, cert: { ...GOOD_TLS.cert!, validTo: inDays(5) } } }), NOW);
    expect(soon.find((f) => f.id === "tls.expires-soon")?.params?.days).toBe(5);
    const https = await checkWeb("example.com", fakeProbe(site({ "https://example.com/": err("CERT_HAS_EXPIRED") }), { default: GOOD_TLS }), NOW);
    expect(https.find((f) => f.id === "https.cert-error")?.status).toBe("fail");
  });

  it("does not judge the headers of a bot challenge page", async () => {
    const challenged = site({ "https://example.com/": { status: 403, headers: { "cf-mitigated": "challenge", "x-frame-options": "SAMEORIGIN" } } });
    const out = await checkWeb("example.com", fakeProbe(challenged, { default: GOOD_TLS }), NOW);
    expect(ids(out)).toContain("hdr.blocked");
    expect(ids(out).filter((i) => i.startsWith("hdr."))).toEqual(["hdr.blocked"]);
    expect(buildControls({ query: "example.com", kind: "domain", generatedAt: "", sections: [{ id: "web", findings: out, records: [] }] }).flatMap((g) => g.controls).find((c) => c.id === "headers")?.state).toBe("unknown");
  });

  it("notices HSTS sent only by www, not by the bare domain people type", async () => {
    const probe = fakeProbe(
      {
        "http://example.com/": { status: 301, headers: { location: "https://example.com/" } },
        "https://example.com/": { status: 301, headers: { location: "https://www.example.com/" } },
        "https://www.example.com/": { headers: SECURE_HEADERS },
      },
      { default: GOOD_TLS },
    );
    const f = (await checkWeb("example.com", probe, NOW)).find((x) => x.id.startsWith("https.hsts") || x.id === "https.no-hsts");
    expect([f?.id, f?.params?.final]).toEqual(["https.hsts-final-only", "www.example.com"]);
  });

  it("does not call a site offline when only our own lookup failed", async () => {
    const probe = fakeProbe({ "http://example.com/": err("ENOTFOUND"), "https://example.com/": err("ENOTFOUND") });
    expect(ids(await checkWeb("example.com", probe, NOW))).toEqual(["https.unresolved"]);
  });

  it("says the domain has no website when neither port answers", async () => {
    expect(ids(await checkWeb("example.com", fakeProbe({}), NOW))).toEqual(["https.no-web"]);
  });

  it("logs every connection for the raw data view", async () => {
    const log: Parameters<typeof checkWeb>[3] = [];
    await checkWeb("example.com", fakeProbe(site(), { default: GOOD_TLS }), NOW, log);
    expect(log!.every((e) => e.source === "web")).toBe(true);
    expect(log!.map((e) => e.label)).toEqual(expect.arrayContaining(["web GET http://example.com/", "web TLS example.com:443"]));
  });
});

describe("audit with a web probe (desktop app)", () => {
  const zone = {
    "example.com SOA": ["ns1.example.net. hostmaster.example.com. 1 7200 3600 1209600 300"],
    "example.com NS": ["ns1.example.net", "ns2.example.net"],
    "example.com A": ["192.0.2.10"],
    "example.com MX": ["10 mx.example.com"],
    "mx.example.com A": ["192.0.2.25"],
    "mta-sts.example.com A": ["192.0.2.30"],
    "_mta-sts.example.com TXT": ["v=STSv1; id=20261110"],
  };
  const probe = fakeProbe(
    {
      "http://example.com/": { status: 301, headers: { location: "https://example.com/" } },
      "https://example.com/": { headers: SECURE_HEADERS },
      "https://mta-sts.example.com/.well-known/mta-sts.txt": { body: "version: STSv1\nmode: enforce\nmx: mx.example.com\nmax_age: 604800\n" },
    },
    { default: GOOD_TLS },
  );

  it("adds the web section and reads the MTA-STS policy", async () => {
    const report = await audit({ kind: "domain", name: "example.com" }, { resolver: fakeResolver(zone), fetch: noFetch, web: probe, now: NOW });
    expect(report.sections.map((s) => s.id)).toEqual(["mail", "dns", "web", "registration"]);
    const all = report.sections.flatMap((s) => s.findings.map((f) => f.id));
    expect(all).toContain("mta-sts.enforce");
    expect(all).not.toContain("mta-sts.unverified");
    const controls = buildControls(report).find((g) => g.id === "web")!.controls;
    expect(controls.map((c) => [c.id, c.state])).toEqual([
      ["https", "ok"],
      ["tls", "ok"],
      ["headers", "ok"],
      ["security-txt", "optional"],
    ]);
  });

  it("leaves the website report unchanged without a probe", async () => {
    const report = await audit({ kind: "domain", name: "example.com" }, { resolver: fakeResolver(zone), fetch: noFetch, now: NOW });
    expect(report.sections.map((s) => s.id)).not.toContain("web");
    expect(report.sections.flatMap((s) => s.findings.map((f) => f.id))).toContain("mta-sts.unverified");
  });
});

describe("first report while Certificate Transparency is slow", () => {
  const zone = {
    "example.com SOA": ["ns1.example.net. hostmaster.example.com. 1 7200 3600 1209600 300"],
    "example.com NS": ["ns1.example.net", "ns2.example.net"],
    "example.com A": ["192.0.2.10"],
  };
  const slowCt: typeof fetch = async (input) => {
    if (/crt\.sh|certspotter/.test(String(input))) await new Promise((r) => setTimeout(r, 300));
    return new Response(String(input).includes("crt.sh") ? "[]" : null, { status: String(input).includes("crt.sh") ? 200 : 404 });
  };

  it("delivers everything else first, then the full report", async () => {
    const partials: string[][] = [];
    const report = await audit(
      { kind: "domain", name: "example.com" },
      { resolver: fakeResolver(zone), fetch: slowCt, now: NOW, partialAfterMs: 20, onPartial: (r) => partials.push(r.sections.flatMap((s) => s.findings.map((f) => f.id))) },
    );
    await new Promise((r) => setTimeout(r, 10));
    expect(partials).toHaveLength(1);
    expect(partials[0]).toContain("ct.pending");
    expect(partials[0]).toContain("dns.ns");
    const final = report.sections.flatMap((s) => s.findings.map((f) => f.id));
    expect(final).not.toContain("ct.pending");
  });

  it("does not send a first report when everything arrives in time", async () => {
    let calls = 0;
    await audit({ kind: "domain", name: "example.com" }, { resolver: fakeResolver(zone), fetch: noFetch, now: NOW, partialAfterMs: 2_000, onPartial: () => calls++ });
    expect(calls).toBe(0);
  });
});

describe("Certificate Transparency sources", () => {
  const crt = JSON.stringify([{ issuer_name: "O=Let's Encrypt", name_value: "www.example.com", not_before: "2026-01-01T00:00:00", not_after: "2027-01-01T00:00:00" }]);
  const spotter = JSON.stringify([{ dns_names: ["api.example.com"], issuer: { name: "O=Let's Encrypt" }, not_before: "2026-01-01T00:00:00Z", not_after: "2027-01-01T00:00:00Z" }]);
  const delayed = (crtMs: number): typeof fetch => async (input) => {
    if (String(input).includes("crt.sh")) {
      await new Promise((r) => setTimeout(r, crtMs));
      return new Response(crt, { status: 200 });
    }
    return new Response(spotter, { status: 200 });
  };

  it("keeps crt.sh when it answers in time", async () => {
    expect((await fetchCertificates("example.com", { fetch: delayed(5), hedgeMs: 200 }))?.source).toBe("crt.sh");
  });

  it("asks Cert Spotter in parallel when crt.sh is slow, and takes the first answer", async () => {
    const started = Date.now();
    const r = await fetchCertificates("example.com", { fetch: delayed(2_000), hedgeMs: 50 });
    expect(r?.source).toBe("Cert Spotter");
    expect(Date.now() - started).toBeLessThan(1_000);
  });
});

describe("the site's own headers (Cloudflare Pages _headers)", () => {
  it("pass the auditor's own web checks", async () => {
    const { HEADERS } = await import("../vite.config");
    const block = HEADERS.split(/\n\n/)[0]!;
    const headers = Object.fromEntries(
      block
        .split("\n")
        .slice(1)
        .map((l) => /^\s+([^:]+):\s*(.+)$/.exec(l))
        .filter((m): m is RegExpExecArray => m !== null)
        .map((m) => [m[1]!.toLowerCase(), m[2]!]),
    );
    const out = checkHeaders(headers, "https://audit.felixllorente.com/");
    expect(out.filter((f) => f.status !== "ok")).toEqual([]);
    expect(hstsMaxAge(headers["strict-transport-security"]!)).toBeGreaterThanOrEqual(31_536_000);
    expect(headers["content-security-policy"]).toContain("frame-ancestors 'none'");
  });
});
