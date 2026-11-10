/**
 * Context from third-party intelligence services, read from the browser (both
 * send CORS and need no key):
 * - Shodan InternetDB: open ports, known vulnerabilities (CVE) and tags that
 *   Shodan's own scans saw on an IP;
 * - AlienVault OTX: community "pulses" that mention a domain or an IP, and the
 *   allow-lists OTX itself keeps.
 * Neither is verifiable against a standard and both have false positives (OTX
 * pulses mention example.com fifty times), so every result is information
 * attributed to its source, never a warning or a failure of the domain.
 */
import { loggedFetch, type RawLog } from "./raw";
import { finding, type Finding } from "./types";

type Fetch = typeof fetch;

export const INTERNETDB = "https://internetdb.shodan.io";
export const OTX = "https://otx.alienvault.com/api/v1/indicators";

export interface InternetDbHost {
  ip: string;
  ports: number[];
  vulns: string[];
  tags: string[];
  hostnames: string[];
}

/** Shodan InternetDB for one IP. Null when Shodan has nothing on it (404); throws on other errors. */
export async function internetDb(ip: string, doFetch: Fetch = fetch, log?: RawLog): Promise<InternetDbHost | null> {
  const res = await loggedFetch(doFetch, `${INTERNETDB}/${encodeURIComponent(ip)}`, { source: "shodan", label: `intel Shodan InternetDB ${ip}`, timeoutMs: 10_000, log });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`InternetDB HTTP ${res.status}`);
  const j = JSON.parse(res.text) as Partial<InternetDbHost>;
  return { ip, ports: j.ports ?? [], vulns: j.vulns ?? [], tags: j.tags ?? [], hostnames: j.hostnames ?? [] };
}

export interface OtxIndicator {
  indicator: string;
  pulses: number;
  /** Names and dates of the most recent pulses, as published by their authors. */
  recent: Array<{ name: string; created: string }>;
  /** OTX's own allow-lists for the indicator ("Whitelisted domain", "Akamai Popular Domain"…). */
  validation: string[];
}

interface OtxJson {
  pulse_info?: { count?: number; pulses?: Array<{ name?: string; created?: string }> };
  validation?: Array<{ name?: string }>;
}

/** AlienVault OTX general data for a domain or an IP. */
export async function otx(kind: "domain" | "IPv4" | "IPv6", indicator: string, doFetch: Fetch = fetch, log?: RawLog): Promise<OtxIndicator> {
  const res = await loggedFetch(doFetch, `${OTX}/${kind}/${encodeURIComponent(indicator)}/general`, {
    source: "otx",
    label: `intel AlienVault OTX ${indicator}`,
    timeoutMs: 15_000,
    log,
  });
  if (!res.ok) throw new Error(`OTX HTTP ${res.status}`);
  const j = JSON.parse(res.text) as OtxJson;
  const recent = (j.pulse_info?.pulses ?? [])
    .map((p) => ({ name: (p.name ?? "").trim(), created: (p.created ?? "").slice(0, 10) }))
    .filter((p) => p.name)
    .sort((a, b) => b.created.localeCompare(a.created))
    .slice(0, 3);
  return { indicator, pulses: j.pulse_info?.count ?? 0, recent, validation: [...new Set((j.validation ?? []).map((v) => v.name ?? "").filter(Boolean))] };
}

/** At most this many IPs are looked up per domain: the first addresses of the domain itself. */
export const MAX_INTEL_IPS = 2;

/**
 * Findings for the "exposure and reputation" control. Every failure of a source
 * is said (`intel.unavailable`), so a missing answer never reads as "nothing found".
 */
export async function checkIntel(target: { domain?: string; ips: string[] }, doFetch: Fetch = fetch, log?: RawLog): Promise<Finding[]> {
  const ips = [...new Set(target.ips)].slice(0, MAX_INTEL_IPS);
  const failed = new Set<string>();
  const [hosts, rep] = await Promise.all([
    Promise.all(
      ips.map((ip) =>
        internetDb(ip, doFetch, log).then(
          (h) => ({ ip, h }),
          () => (failed.add("Shodan InternetDB"), null),
        ),
      ),
    ),
    Promise.all(
      [
        ...(target.domain ? [["domain", target.domain] as const] : []),
        ...(target.domain ? [] : ips.map((ip) => [ip.includes(":") ? "IPv6" : "IPv4", ip] as const)),
      ].map(([kind, indicator]) => otx(kind, indicator, doFetch, log).catch(() => (failed.add("AlienVault OTX"), null))),
    ),
  ]);
  const out: Finding[] = [];
  for (const entry of hosts) {
    if (!entry) continue;
    const { ip, h } = entry;
    if (!h) {
      out.push(finding("intel.shodan-none", "info", { ip }));
      continue;
    }
    out.push(
      finding("intel.shodan", "info", {
        ip,
        ports: h.ports.join(", ") || "—",
        vulns: h.vulns.length,
        cves: h.vulns.slice(0, 5).join(", ") + (h.vulns.length > 5 ? "…" : "") || "—",
        tags: h.tags.join(", ") || "—",
      }),
    );
  }
  for (const r of rep) {
    if (!r) continue;
    const listed = r.validation.join(", ") || "—";
    out.push(
      r.pulses
        ? finding("intel.otx", "info", { indicator: r.indicator, count: r.pulses, recent: r.recent.map((p) => `${p.name} (${p.created})`).join("; ") || "—", validation: listed })
        : finding("intel.otx-none", "info", { indicator: r.indicator, validation: listed }),
    );
  }
  for (const source of failed) out.push(finding("intel.unavailable", "info", { source }));
  return out;
}
