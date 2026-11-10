import { DnsError, type DnsAnswer, type Resolver, type RRType } from "../src/core/doh";

/** Zone as `"name TYPE" -> data[]`. Names missing from the zone are NOERROR/NODATA. */
export type Zone = Record<string, string[]>;

export interface FakeOptions {
  ad?: boolean;
  /** Names that answer NXDOMAIN (RCODE 3). */
  nxdomain?: string[];
  /** Names that answer SERVFAIL (RCODE 2), as a broken or unreachable zone does. */
  servfail?: string[];
  /** Names whose query never gets an answer (both resolvers down, timeout). */
  unreachable?: string[];
}

/**
 * A DNS that answers from a table like a real resolver: it follows CNAMEs,
 * applies wildcards (`*.example.com A`) to names that do not exist, and can
 * simulate NXDOMAIN, SERVFAIL and queries that never get an answer.
 */
export function fakeResolver(zone: Zone, opts: FakeOptions = {}): Resolver {
  const names = new Set(Object.keys(zone).map((k) => k.split(" ")[0]));
  const resolve = async (name: string, type: RRType): Promise<DnsAnswer> => {
    const n = name.toLowerCase();
    if (opts.unreachable?.includes(n)) throw new DnsError(`DNS query failed for ${n} ${type}`);
    if (opts.servfail?.includes(n)) return { status: 2, ad: false, answers: [], provider: "fake" };
    if (opts.nxdomain?.includes(n)) return { status: 3, ad: false, answers: [], provider: "fake" };
    // Follow a CNAME like a real resolver: the answer holds the alias and the target's records.
    const alias = type !== "CNAME" ? zone[`${n} CNAME`]?.[0] : undefined;
    if (alias) {
      const target = await resolve(alias, type);
      return { ...target, answers: [{ name: n, type: "CNAME", ttl: 300, data: alias }, ...target.answers] };
    }
    // A wildcard answers for names that do not exist (RFC 4592, section 2.2).
    const wildcard = names.has(n) ? undefined : zone[`*.${n.split(".").slice(1).join(".")} ${type}`];
    const data = zone[`${n} ${type}`] ?? wildcard ?? [];
    return { status: 0, ad: opts.ad ?? false, answers: data.map((d) => ({ name: n, type, ttl: 300, data: d })), provider: "fake" };
  };
  return resolve;
}

export const noFetch: typeof fetch = async () => new Response(null, { status: 404 });

/** RDAP answer for a domain with these EPP/RDAP statuses; everything else is 404. */
export function rdapFetch(status: string[], expires = "2030-01-01T00:00:00Z"): typeof fetch {
  return async (input) => {
    if (!String(input).includes("/domain/")) return new Response(null, { status: 404 });
    const events = [
      { eventAction: "registration", eventDate: "2010-01-01T00:00:00Z" },
      { eventAction: "expiration", eventDate: expires },
    ];
    return new Response(JSON.stringify({ status, events }), { status: 200 });
  };
}
