import { describe, expect, it } from "vitest";
import { checkIntel } from "../src/core/intel";
import type { RawLog } from "../src/core/raw";

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });

/** Shodan and OTX answers by URL; anything else is 404. */
function services(map: Record<string, Response | (() => Response)>): typeof fetch {
  return (async (url: string | URL | Request) => {
    const u = String(url);
    const hit = Object.entries(map).find(([k]) => u.includes(k));
    if (!hit) return new Response(null, { status: 404 });
    return typeof hit[1] === "function" ? hit[1]() : hit[1].clone();
  }) as typeof fetch;
}

describe("Shodan InternetDB and AlienVault OTX", () => {
  it("reports ports and CVEs as information, attributed to Shodan", async () => {
    const f = await checkIntel(
      { domain: "example.com", ips: ["192.0.2.1"] },
      services({
        "internetdb.shodan.io/192.0.2.1": json({ ip: "192.0.2.1", ports: [22, 443], vulns: ["CVE-2023-1", "CVE-2023-2"], tags: ["cloud"], hostnames: [] }),
        "otx.alienvault.com/api/v1/indicators/domain/example.com": json({ pulse_info: { count: 0, pulses: [] }, validation: [{ name: "Whitelisted domain" }] }),
      }),
    );
    expect(f).toEqual([
      { id: "intel.shodan", status: "info", params: { ip: "192.0.2.1", ports: "22, 443", vulns: 2, cves: "CVE-2023-1, CVE-2023-2", tags: "cloud" } },
      { id: "intel.otx-none", status: "info", params: { indicator: "example.com", validation: "Whitelisted domain" } },
    ]);
  });

  it("never turns OTX pulses into a warning, and lists the most recent ones", async () => {
    const pulses = [
      { name: "Old", created: "2023-01-25T00:00:00" },
      { name: "Newest", created: "2026-11-03T00:00:00" },
      { name: "Middle", created: "2026-10-03T00:00:00" },
      { name: "Oldest", created: "2020-01-01T00:00:00" },
    ];
    const f = await checkIntel({ domain: "example.com", ips: [] }, services({ "indicators/domain/example.com": json({ pulse_info: { count: 50, pulses } }) }));
    expect(f).toEqual([
      { id: "intel.otx", status: "info", params: { indicator: "example.com", count: 50, recent: "Newest (2026-11-03); Middle (2026-10-03); Old (2023-01-25)", validation: "—" } },
    ]);
  });

  it("asks OTX about the IP itself when auditing an IP, and says when Shodan has nothing", async () => {
    const log: RawLog = [];
    const f = await checkIntel({ ips: ["2001:db8::1"] }, services({ "indicators/IPv6/2001%3Adb8%3A%3A1": json({ pulse_info: { count: 0 } }) }), log);
    expect(f.map((x) => x.id)).toEqual(["intel.shodan-none", "intel.otx-none"]);
    expect(log.map((e) => e.source)).toEqual(expect.arrayContaining(["shodan", "otx"]));
  });

  it("says a source failed instead of reading it as nothing found", async () => {
    const f = await checkIntel({ domain: "example.com", ips: ["192.0.2.1"] }, services({ "internetdb.shodan.io": json({}, 503), "otx.alienvault.com": json({}, 429) }));
    expect(f).toEqual([
      { id: "intel.unavailable", status: "info", params: { source: "Shodan InternetDB" } },
      { id: "intel.unavailable", status: "info", params: { source: "AlienVault OTX" } },
    ]);
  });

  it("looks up at most two addresses per domain", async () => {
    const asked: string[] = [];
    const counting = (async (url: string | URL | Request) => (asked.push(String(url)), new Response(null, { status: 404 }))) as typeof fetch;
    await checkIntel({ domain: "example.com", ips: ["192.0.2.1", "192.0.2.2", "192.0.2.3"] }, counting);
    expect(asked.filter((u) => u.includes("internetdb"))).toHaveLength(2);
  });
});

describe("Shodan data of a CDN address", () => {
  it("says the ports belong to the CDN's shared infrastructure (rtve.es on Fastly)", async () => {
    const { audit } = await import("../src/core/audit");
    const { fakeResolver } = await import("./helpers");
    const fetchAll = services({
      "internetdb.shodan.io/151.101.1.1": json({ ip: "151.101.1.1", ports: [80, 443], vulns: ["CVE-1"], tags: ["cdn"], hostnames: [] }),
      "stat.ripe.net": json({ data: { announced: true, resource: "151.101.0.0/16", asns: [{ asn: 54113, holder: "FASTLY" }] } }),
    });
    const report = await audit({ kind: "domain", name: "example.com" }, { resolver: fakeResolver({ "example.com A": ["151.101.1.1"] }), fetch: fetchAll });
    const f = report.sections.flatMap((s) => s.findings).find((x) => x.id.startsWith("intel.shodan"));
    expect(f).toMatchObject({ id: "intel.shodan-cdn", params: { cdn: "Fastly", vulns: 1 } });
  });
});
