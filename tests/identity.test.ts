import { describe, expect, it } from "vitest";
import { audit } from "../src/core/audit";
import { lookupDomain, lookupIp, rdapBaseForDomain, rdapBaseForIp } from "../src/core/rdap";
import { fakeResolver } from "./helpers";

const json = (body: unknown) => new Response(JSON.stringify(body), { status: 200 });
const registrant = (fn: string, org?: string) => ({
  roles: ["registrant"],
  vcardArray: ["vcard", [["fn", {}, "text", fn], ...(org ? [["org", {}, "text", org]] : []), ["adr", {}, "text", ["", "", "Calle 1", "Madrid", "", "", "ES"]]]],
});

/** Registry answer (thin, no registrant) linking to the registrar's RDAP. */
function fetchFor(registrarEntity: unknown): typeof fetch {
  return (async (url: string | URL | Request) => {
    const u = String(url);
    if (u.startsWith("https://rdap.org/domain/example.com"))
      return json({
        status: ["client transfer prohibited"],
        events: [{ eventAction: "registration", eventDate: "2009-02-17T00:00:00Z" }],
        entities: [{ roles: ["registrar"], vcardArray: ["vcard", [["fn", {}, "text", "Example Registrar"]]] }],
        links: [{ rel: "related", type: "application/rdap+json", href: "https://rdap.registrar.example/domain/EXAMPLE.COM" }],
      });
    if (u.startsWith("https://rdap.registrar.example/")) return json({ entities: [registrarEntity] });
    return new Response(null, { status: 404 });
  }) as typeof fetch;
}

describe("domain holder", () => {
  it("takes the organisation from the registrar's RDAP, never the address", async () => {
    const reg = await lookupDomain("example.com", fetchFor(registrant("REDACTED REGISTRANT", "Example Corp")));
    expect(reg).toMatchObject({ registrant: "Example Corp", registrar: "Example Registrar" });
    expect(JSON.stringify(reg)).not.toContain("Madrid");
  });

  it("marks a redacted holder as hidden", async () => {
    const reg = await lookupDomain("example.com", fetchFor(registrant("DATA REDACTED", "DATA REDACTED")));
    expect(reg?.registrant).toBeUndefined();
    expect(reg?.registrantRedacted).toBe(true);
  });

  it("fills the report identity", async () => {
    const report = await audit(
      { kind: "domain", name: "example.com" },
      { resolver: fakeResolver({ "example.com NS": ["kim.ns.cloudflare.com"], "example.com MX": ["1 aspmx.l.google.com"] }), fetch: fetchFor(registrant("x", "Example Corp")) },
    );
    expect(report.identity).toMatchObject({
      holder: "Example Corp",
      registrar: "Example Registrar",
      created: "2009-02-17",
      dnsProvider: "Cloudflare",
      mailProvider: "Google (Gmail / Workspace)",
    });
  });

  it("flags a domain registered less than 30 days ago", async () => {
    const opts = { resolver: fakeResolver({}), fetch: fetchFor(registrant("x", "Example Corp")) };
    const ids = async (now: string) =>
      (await audit({ kind: "domain", name: "example.com" }, { ...opts, now: new Date(now) })).sections.flatMap((s) => s.findings.map((f) => f.id));
    expect(await ids("2009-03-01T00:00:00Z")).toContain("reg.recent");
    expect(await ids("2009-04-01T00:00:00Z")).toContain("reg.created");
  });
});

describe("IP identity", () => {
  it("starts with the reverse name, holder and announcing network", async () => {
    const fakeFetch = (async (url: string | URL | Request) => {
      const u = String(url);
      if (u.includes("maxmind-geo-lite")) return json({ data: { located_resources: [{ locations: [{ country: "US" }] }] } });
      if (u.includes("stat.ripe.net"))
        return json({ data: { announced: true, resource: "8.8.8.0/24", asns: [{ asn: 15169, holder: "GOOGLE - Google LLC" }] } });
      if (u.includes("rdap.org/ip/"))
        return json({ name: "GOGL", cidr0_cidrs: [{ v4prefix: "8.8.8.0", length: 24 }], entities: [registrant("Google LLC")] });
      return new Response(null, { status: 404 });
    }) as typeof fetch;
    const report = await audit({ kind: "ip", ip: "8.8.8.8", version: 4 }, { resolver: fakeResolver({ "8.8.8.8.in-addr.arpa PTR": ["dns.google"] }), fetch: fakeFetch });
    expect(report.identity).toEqual({
      ptr: "dns.google",
      holder: "Google LLC",
      network: "GOGL",
      range: "8.8.8.0/24",
      asn: 15169,
      asHolder: "GOOGLE - Google LLC",
      prefix: "8.8.8.0/24",
      location: "US",
    });
  });
});

describe("RDAP through IANA's bootstrap registries (RFC 9224)", () => {
  const dnsJson = { services: [[["com", "net"], ["http://rdap.verisign.example/com/v1/", "https://rdap.verisign.example/com/v1/"]], [["nl"], ["https://rdap.sidn.example"]]] };
  const ipv4Json = { services: [[["8.0.0.0/8"], ["https://rdap.arin.example/registry/"]], [["8.8.8.0/24"], ["https://rdap.more-specific.example/"]], [["193.0.0.0/8"], ["https://rdap.ripe.example/"]]] };
  const ipv6Json = { services: [[["2001:4800::/23"], ["https://rdap.arin.example/registry/"]], [["2001:4000::/23"], ["https://rdap.ripe.example/"]]] };

  /** IANA files plus a registry that answers; records every URL asked. */
  function registry(asked: string[], iana = true): typeof fetch {
    return (async (url: string | URL | Request) => {
      const u = String(url);
      asked.push(u);
      if (u.startsWith("https://data.iana.org/")) {
        if (!iana) return new Response(null, { status: 503 });
        return json(u.endsWith("dns.json") ? dnsJson : u.endsWith("ipv4.json") ? ipv4Json : ipv6Json);
      }
      if (u.includes("/domain/example.com") || u.includes("/ip/")) return json({ status: ["client transfer prohibited"], name: "NET" });
      return new Response(null, { status: 404 });
    }) as typeof fetch;
  }

  it("asks the TLD's own registry over HTTPS, not rdap.org", async () => {
    const asked: string[] = [];
    const reg = await lookupDomain("www.example.com", registry(asked));
    expect(reg?.status).toEqual(["client transfer prohibited"]);
    expect(asked).toContain("https://rdap.verisign.example/com/v1/domain/example.com");
    expect(asked.some((u) => u.includes("rdap.org"))).toBe(false);
  });

  it("does not ask anyone when the TLD has no RDAP service", async () => {
    const asked: string[] = [];
    expect(await lookupDomain("example.es", registry(asked))).toBeNull();
    expect(asked.filter((u) => !u.startsWith("https://data.iana.org/"))).toEqual([]);
  });

  it("falls back to rdap.org when IANA's files cannot be read", async () => {
    const asked: string[] = [];
    await lookupDomain("example.com", registry(asked, false));
    expect(asked).toContain("https://rdap.org/domain/example.com");
  });

  it("picks the longest prefix for an address", async () => {
    const asked: string[] = [];
    await lookupIp("8.8.8.8", registry(asked));
    await lookupIp("8.8.4.4", registry(asked));
    await lookupIp("2001:4860:4860::8888", registry(asked));
    expect(asked).toEqual(
      expect.arrayContaining(["https://rdap.more-specific.example/ip/8.8.8.8", "https://rdap.arin.example/registry/ip/8.8.4.4", "https://rdap.arin.example/registry/ip/2001:4860:4860::8888"]),
    );
  });

  it("matches labels and prefixes as RFC 9224 describes", () => {
    const map = new Map([["uk", "https://a/"], ["co.uk", "https://b/"]]);
    expect(rdapBaseForDomain(map, "shop.example.co.uk")).toBe("https://b/");
    expect(rdapBaseForDomain(map, "example.uk")).toBe("https://a/");
    expect(rdapBaseForDomain(map, "example.es")).toBeUndefined();
    expect(rdapBaseForIp(new Map([["192.0.2.0/24", "https://x/"]]), "192.0.3.1", 4)).toBeUndefined();
  });
});

describe("IP location (RIPEstat geolocation)", () => {
  it("gives no single country for anycast or CDN addresses", async () => {
    const { lookupGeo } = await import("../src/core/rdap");
    const geo = (locations: Array<{ country: string }>) => (async () => json({ data: { located_resources: [{ locations }] } })) as unknown as typeof fetch;
    expect(await lookupGeo("188.114.96.5", geo([{ country: "?" }]))).toEqual({});
    expect(await lookupGeo("192.0.2.1", geo([{ country: "ES" }, { country: "FR" }]))).toEqual({});
    expect(await lookupGeo("192.0.2.1", geo([{ country: "ES" }]))).toEqual({ country: "ES" });
  });
});
