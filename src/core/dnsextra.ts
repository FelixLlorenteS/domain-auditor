import { recordsOf, type Resolver } from "./doh";
import { finding, type Finding, type RecordRow } from "./types";

/**
 * DNS hardening checks beyond presence: DNSSEC algorithms, wildcard records,
 * SOA timers, name server diversity and DANE for the mail servers.
 */

/** DNSSEC algorithm numbers and their "use for signing" status in RFC 9904, Table 2. */
const ALGORITHMS: Record<number, { name: string; use: "recommended" | "may" | "not-recommended" | "must-not" }> = {
  1: { name: "RSAMD5", use: "must-not" },
  3: { name: "DSA", use: "must-not" },
  5: { name: "RSASHA1", use: "not-recommended" },
  6: { name: "DSA-NSEC3-SHA1", use: "must-not" },
  7: { name: "RSASHA1-NSEC3-SHA1", use: "not-recommended" },
  8: { name: "RSASHA256", use: "recommended" },
  10: { name: "RSASHA512", use: "not-recommended" },
  12: { name: "ECC-GOST", use: "must-not" },
  13: { name: "ECDSAP256SHA256", use: "recommended" },
  14: { name: "ECDSAP384SHA384", use: "may" },
  15: { name: "ED25519", use: "recommended" },
  16: { name: "ED448", use: "may" },
};

/** DS digest types and their "use for delegation" status in RFC 9904, Table 3. */
const DIGESTS: Record<number, { name: string; use: "recommended" | "may" | "must-not" }> = {
  1: { name: "SHA-1", use: "must-not" },
  2: { name: "SHA-256", use: "recommended" },
  3: { name: "GOST R 34.11-94", use: "must-not" },
  4: { name: "SHA-384", use: "may" },
};

/** DS records (`keytag algorithm digesttype digest`) judged against RFC 9904. */
export function checkDnssecAlgorithms(ds: string[]): Finding[] {
  const parsed = ds.map((d) => d.trim().split(/\s+/).map(Number)).filter((p) => p.length >= 3 && p.every((n, i) => i > 2 || Number.isFinite(n)));
  if (!parsed.length) return [];
  const algs = [...new Set(parsed.map((p) => p[1]!))];
  const digests = [...new Set(parsed.map((p) => p[2]!))];
  const algName = (n: number) => ALGORITHMS[n]?.name ?? String(n);
  const digestName = (n: number) => DIGESTS[n]?.name ?? String(n);
  const out: Finding[] = [];
  const weakAlg = algs.filter((a) => ["not-recommended", "must-not"].includes(ALGORITHMS[a]?.use ?? ""));
  // Some registries publish a SHA-1 DS next to the SHA-256 one: only flag it if it is the only digest.
  const onlyWeakDigest = digests.every((d) => DIGESTS[d]?.use === "must-not");
  if (weakAlg.length) out.push(finding("dnssec.weak-algorithm", "warn", { alg: weakAlg.map(algName).join(", ") }));
  if (onlyWeakDigest) out.push(finding("dnssec.weak-digest", "warn", { digest: digests.map(digestName).join(", ") }));
  if (!weakAlg.length && !onlyWeakDigest) {
    out.push(finding("dnssec.algorithm", "ok", { alg: algs.map(algName).join(", "), digest: digests.map(digestName).join(", ") }));
  }
  return out;
}

/** A name that should not exist: if it resolves, the zone has a wildcard. */
export function wildcardProbe(domain: string, seed = Math.random()): string {
  return `da-check-${Math.floor(seed * 1e10).toString(36)}.${domain}`;
}

export async function checkWildcard(domain: string, resolver: Resolver, seed?: number): Promise<{ findings: Finding[]; records: RecordRow[] }> {
  const probe = wildcardProbe(domain, seed);
  try {
    const ans = await resolver(probe, "A");
    if (ans.status === 0 && ans.answers.length) {
      const target = ans.answers.at(-1)!.data;
      return { findings: [finding("dns.wildcard", "info", { probe, target })], records: ans.answers.map(({ name, type, ttl, data }) => ({ name, type, ttl, data })) };
    }
    return { findings: [finding("dns.no-wildcard", "ok", { probe })], records: [] };
  } catch {
    return { findings: [], records: [] };
  }
}

/**
 * SOA timers (RFC 1035, section 3.3.13), shown as information only: they matter
 * for classic secondaries fed by zone transfer, which most anycast providers do
 * not use (Google, for instance, publishes 900/900/1800 on purpose).
 */
export function checkSoa(soa: string | undefined): Finding[] {
  if (!soa) return [];
  const parts = soa.trim().split(/\s+/);
  const [refresh, retry, expire, minimum] = parts.slice(3, 7).map(Number);
  if (![refresh, retry, expire, minimum].every((n) => Number.isFinite(n))) return [];
  const params = { serial: parts[2] ?? "?", refresh: refresh!, retry: retry!, expire: expire!, minimum: minimum! };
  if (retry! >= refresh! || expire! <= refresh! + retry!) return [finding("dns.soa-inconsistent", "info", params)];
  return [finding("dns.soa", "info", params)];
}

/**
 * DANE for SMTP (RFC 7672): a TLSA record at `_25._tcp.<mx>`, only meaningful with
 * DNSSEC. Every MX is checked: a domain that wants secure inbound mail needs all its
 * servers configured (section 2.2.1). `mxSigned` is whether the domain's own MX
 * answer was validated: without it an attacker can still swap the MX themselves.
 */
export async function checkDane(mxHosts: string[], resolver: Resolver, mxSigned = true): Promise<{ findings: Finding[]; records: RecordRow[] }> {
  const hosts = [...new Set(mxHosts.filter(Boolean))].slice(0, 10);
  if (!hosts.length) return { findings: [], records: [] };
  const records: RecordRow[] = [];
  const withTlsa: string[] = [];
  // What counts is the DNSSEC of the MX host's own zone: the resolver's AD bit on the TLSA answer.
  const unsigned: string[] = [];
  await Promise.all(
    hosts.map(async (host) => {
      try {
        const ans = await resolver(`_25._tcp.${host}`, "TLSA");
        const tlsa = recordsOf(ans, "TLSA");
        records.push(...tlsa.map(({ name, type, ttl, data }) => ({ name, type, ttl, data })));
        if (tlsa.length) (ans.ad ? withTlsa : unsigned).push(host);
      } catch {
        /* skip */
      }
    }),
  );
  const findings: Finding[] = [];
  const without = hosts.filter((h) => !withTlsa.includes(h) && !unsigned.includes(h));
  if (withTlsa.length) findings.push(finding("mx.dane", "ok", { hosts: withTlsa.sort().join(", ") }));
  if (unsigned.length) findings.push(finding("mx.dane-unsigned", "warn", { hosts: unsigned.sort().join(", ") }));
  if (withTlsa.length && without.length) findings.push(finding("mx.dane-partial", "warn", { hosts: without.sort().join(", ") }));
  if (withTlsa.length && !mxSigned) findings.push(finding("mx.dane-insecure-mx", "info"));
  if (!findings.length) findings.push(finding("mx.no-dane", "info"));
  return { findings, records };
}
