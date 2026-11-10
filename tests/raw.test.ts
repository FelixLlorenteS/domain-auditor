import { describe, expect, it, vi } from "vitest";
import { audit } from "../src/core/audit";
import { createResolver, queryProvider, type DnsAnswer } from "../src/core/doh";
import { curlCommand, loggedFetch, type RawLog } from "../src/core/raw";
import { fakeResolver, noFetch } from "./helpers";

describe("raw log", () => {
  it("keeps the body exactly as received and the final URL", async () => {
    const body = '{"Status":0,  "Answer":[]}';
    const fetch = vi.fn(async () => {
      const res = new Response(body, { status: 200 });
      Object.defineProperty(res, "url", { value: "https://registry.example/x" });
      return res;
    });
    const log: RawLog = [];
    await loggedFetch(fetch, "https://rdap.org/x", { source: "rdap", label: "x", timeoutMs: 1000, log });
    expect(log).toHaveLength(1);
    expect(log[0]).toMatchObject({ source: "rdap", status: 200, body, finalUrl: "https://registry.example/x" });
  });

  it("logs failed requests too", async () => {
    const log: RawLog = [];
    const fetch = vi.fn(async () => {
      throw new TypeError("offline");
    });
    await expect(loggedFetch(fetch, "https://x.example/", { source: "google", label: "x", timeoutMs: 1000, log })).rejects.toThrow();
    expect(log[0]).toMatchObject({ status: null, error: "TypeError: offline" });
  });

  it("builds a curl command that repeats the query", () => {
    expect(
      curlCommand({ source: "cloudflare", label: "", url: "https://cloudflare-dns.com/dns-query?name=a.example&type=TXT", accept: "application/dns-json", status: 200, ms: 1, at: "" }),
    ).toBe("curl -sL -H 'accept: application/dns-json' 'https://cloudflare-dns.com/dns-query?name=a.example&type=TXT'");
  });

  it("records both providers when the first one fails", async () => {
    const log: RawLog = [];
    const fetch = vi.fn(async (url: string | URL | Request) =>
      String(url).includes("cloudflare") ? new Response("busy", { status: 503 }) : new Response('{"Status":0}', { status: 200 }),
    );
    const answer = await createResolver({ fetch, log })("a.example", "A");
    expect(answer.provider).toBe("google");
    expect(log.map((e) => [e.source, e.status])).toEqual([
      ["cloudflare", 503],
      ["google", 200],
    ]);
  });

  it("asks one specific provider", async () => {
    const urls: string[] = [];
    const fetch = vi.fn(async (url: string | URL | Request) => {
      urls.push(String(url));
      return new Response(`{"Status":0,"AD":true}`, { status: 200 });
    });
    const answer = await queryProvider("google", "a.example", "NS", { fetch });
    expect(urls[0]).toContain("dns.google");
    expect(answer).toMatchObject({ provider: "google", ad: true });
  });
});

describe("resolver cross-check", () => {
  const zone = { "example.com SOA": ["ns1.example.net. h.example.com. 1 2 3 4 5"], "example.com MX": ["10 mx.example.com"] };
  const resolver = fakeResolver(zone);
  const other = (changed: boolean) => async (provider: "cloudflare" | "google", name: string, type: Parameters<typeof resolver>[1]) => {
    const answer: DnsAnswer = await resolver(name, type);
    const answers = changed && type === "MX" ? [{ name, type, ttl: 1, data: "10 new-mx.example.com" }] : answer.answers;
    return { ...answer, answers, provider };
  };

  it("reports agreement", async () => {
    const report = await audit({ kind: "domain", name: "example.com" }, { resolver, fetch: noFetch, secondOpinion: other(false) });
    expect(report.resolverCheck?.every((c) => c.same)).toBe(true);
    expect(report.sections.find((s) => s.id === "dns")?.findings.at(-1)?.id).toBe("dns.resolvers-agree");
  });

  it("warns when the resolvers disagree and says where", async () => {
    const report = await audit({ kind: "domain", name: "example.com" }, { resolver, fetch: noFetch, secondOpinion: other(true) });
    const f = report.sections.find((s) => s.id === "dns")?.findings.at(-1);
    expect(f).toMatchObject({ id: "dns.resolvers-differ", status: "warn", params: { items: "example.com MX" } });
    expect(report.resolverCheck?.find((c) => c.type === "MX")?.answers).toEqual([["10 mx.example.com"], ["10 new-mx.example.com"]]);
  });

  it("confirms DNSSEC with both resolvers, or warns when they disagree", async () => {
    const signed = fakeResolver(zone, { ad: true });
    const agree = async (provider: "cloudflare" | "google", name: string, type: Parameters<typeof signed>[1]) => ({ ...(await signed(name, type)), provider });
    const disagree = async (provider: "cloudflare" | "google", name: string, type: Parameters<typeof signed>[1]) => ({ ...(await signed(name, type)), provider, ad: false });
    const dnsIds = async (second: typeof agree) =>
      (await audit({ kind: "domain", name: "example.com" }, { resolver: signed, fetch: noFetch, secondOpinion: second })).sections
        .find((s) => s.id === "dns")
        ?.findings.map((f) => f.id);
    expect(await dnsIds(agree)).toContain("dns.dnssec-both");
    expect(await dnsIds(disagree)).toContain("dns.dnssec-disagree");
  });
});
