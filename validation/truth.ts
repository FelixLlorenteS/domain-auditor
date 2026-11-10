/**
 * Independent ground truth, outside the auditor's resolver, cache and parsing.
 * Two resolvers are asked: dns.google (DNS over HTTPS JSON) and NextDNS, which is
 * not one of the auditor's sources. Only raw answers are used, and a value is
 * only taken as truth when both agree.
 */
export interface Truth {
  status: number;
  ad: boolean;
  data: string[];
}

const TYPES: Record<string, number> = { A: 1, NS: 2, CNAME: 5, SOA: 6, MX: 15, TXT: 16, AAAA: 28, DS: 43, TLSA: 52, CAA: 257 };
type RRType = keyof typeof TYPES;

const RESOLVERS = {
  google: "https://dns.google/resolve",
  nextdns: "https://dns.nextdns.io/dns-query",
} as const;

/** TXT as one string (quoted parts joined), names without the final dot. */
function clean(type: RRType, data: string): string {
  if (type === "TXT") {
    const parts = [...data.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((m) => m[1] ?? "");
    const joined = parts.length ? parts.join("") : data;
    return joined.replace(/\\(\d{3})/g, (_, d: string) => String.fromCharCode(Number(d))).replace(/\\"/g, '"');
  }
  if (type === "TLSA") return data.replace(/[()\s]+/g, " ").trim().toLowerCase();
  return data.replace(/\.$/, "");
}

export async function truth(name: string, type: RRType, resolver: keyof typeof RESOLVERS = "google"): Promise<Truth> {
  const url = `${RESOLVERS[resolver]}?name=${encodeURIComponent(name)}&type=${type}`;
  const res = await fetch(url, { headers: { accept: "application/dns-json" }, signal: AbortSignal.timeout(20_000) });
  const j = (await res.json()) as { Status: number; AD?: boolean; Answer?: Array<{ type: number; data: string }> };
  const data = (j.Answer ?? []).filter((a) => a.type === TYPES[type]).map((a) => clean(type, a.data));
  return { status: j.Status, ad: Boolean(j.AD), data };
}

/**
 * The same question to both resolvers. `agree` is false when they differ (a
 * record just changed, a rotating value…): then the value is not used as truth.
 */
export async function consensus(name: string, type: RRType): Promise<Truth & { agree: boolean }> {
  const [g, n] = await Promise.all([truth(name, type, "google"), truth(name, type, "nextdns")]);
  const key = (t: Truth) => JSON.stringify([t.status, [...t.data].map(norm).sort()]);
  return { ...g, ad: g.ad && n.ad, agree: key(g) === key(n) };
}

export const norm = (s: string) => s.replace(/\s+/g, " ").trim().toLowerCase();

/** A fetch that sends a User-Agent like a browser (rdap.org and others reject Node without one). */
export const browserFetch: typeof fetch = (input, init) =>
  fetch(input, { ...init, headers: { ...(init?.headers as Record<string, string>), "user-agent": "Mozilla/5.0 (DomainAuditor validation)" } });
