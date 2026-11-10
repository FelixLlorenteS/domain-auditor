/**
 * DNS over HTTPS client using the JSON APIs of Cloudflare and Google.
 * Both send CORS headers, so queries run straight from the browser.
 */

export const RR_TYPES = {
  A: 1,
  NS: 2,
  CNAME: 5,
  SOA: 6,
  PTR: 12,
  MX: 15,
  TXT: 16,
  AAAA: 28,
  DS: 43,
  TLSA: 52,
  CAA: 257,
} as const;

export type RRType = keyof typeof RR_TYPES;

import { loggedFetch, type RawLog } from "./raw";

const TYPE_NAMES = new Map<number, string>(Object.entries(RR_TYPES).map(([k, v]) => [v, k]));

export interface DnsRecord {
  name: string;
  type: string;
  ttl: number;
  data: string;
}

export interface DnsAnswer {
  /** DNS RCODE: 0 NOERROR, 2 SERVFAIL, 3 NXDOMAIN. */
  status: number;
  /** Authenticated Data: the resolver validated the answer with DNSSEC. */
  ad: boolean;
  answers: DnsRecord[];
  provider: string;
  /** Extended DNS Error the resolver attached (RFC 8914), e.g. `EDE(9): DNSKEY Missing…`. */
  ede?: string;
}

export type Resolver = (name: string, type: RRType) => Promise<DnsAnswer>;

export class DnsError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DnsError";
  }
}

export const PROVIDERS = [
  { id: "cloudflare", url: "https://cloudflare-dns.com/dns-query" },
  { id: "google", url: "https://dns.google/resolve" },
] as const;

interface DohJson {
  Status: number;
  AD?: boolean;
  Answer?: Array<{ name: string; type: number; TTL: number; data: string }>;
  /** Cloudflare: `["EDE(9): …"]`; Google: a free-text string. */
  Comment?: string | string[];
  /** Google: Extended DNS Errors (RFC 8914) as objects. */
  extended_dns_errors?: Array<{ info_code: number; extra_text?: string }>;
}

/** The Extended DNS Error of an answer, as `EDE(code): text`, from either provider's format. */
function edeOf(json: DohJson): string | undefined {
  const google = json.extended_dns_errors?.[0];
  if (google) return `EDE(${google.info_code}): ${google.extra_text ?? ""}`.trim();
  const comments = Array.isArray(json.Comment) ? json.Comment : [];
  return comments.find((c) => /^EDE\(\d+\)/.test(c));
}

/**
 * Joins the character-strings of a TXT record. Cloudflare returns them quoted
 * (`"part one" "part two"`), Google returns them already joined.
 */
export function decodeTxt(data: string): string {
  const s = data.trim();
  if (!s.startsWith('"')) return s;
  let out = "";
  let i = 0;
  while (i < s.length) {
    if (s[i] !== '"') {
      i++;
      continue;
    }
    i++;
    while (i < s.length && s[i] !== '"') {
      if (s[i] === "\\" && i + 1 < s.length) {
        const code = /^\d{3}/.exec(s.slice(i + 1));
        if (code) {
          out += String.fromCharCode(Number(code[0]));
          i += 4;
        } else {
          out += s[i + 1];
          i += 2;
        }
        continue;
      }
      out += s[i];
      i++;
    }
    i++;
  }
  return out;
}

const NAME_TYPES = new Set(["NS", "CNAME", "PTR"]);

function normalizeRecord(r: { name: string; type: number; TTL: number; data: string }): DnsRecord {
  const type = TYPE_NAMES.get(r.type) ?? `TYPE${r.type}`;
  let data = r.data;
  if (type === "TXT") data = decodeTxt(data);
  else if (NAME_TYPES.has(type)) data = data.replace(/\.$/, "").toLowerCase();
  else if (type === "MX") data = data.replace(/\.$/, "").toLowerCase();
  else if (type === "DS") data = data.toLowerCase();
  return { name: r.name.replace(/\.$/, "").toLowerCase(), type, ttl: r.TTL, data };
}

export type ProviderId = (typeof PROVIDERS)[number]["id"];

export interface ResolverOptions {
  fetch?: typeof fetch;
  timeoutMs?: number;
  /** Every request and its raw response are appended here. */
  log?: RawLog;
  /** Checking Disabled: the resolver returns the data without validating DNSSEC. */
  cd?: boolean;
}

/** One query to one provider, without cache or fallback. */
export async function queryProvider(provider: ProviderId, name: string, type: RRType, options: ResolverOptions = {}): Promise<DnsAnswer> {
  const doFetch = options.fetch ?? globalThis.fetch.bind(globalThis);
  const base = PROVIDERS.find((p) => p.id === provider)!;
  const url = `${base.url}?name=${encodeURIComponent(name)}&type=${type}${options.cd ? "&cd=1" : ""}`;
  const res = await loggedFetch(doFetch, url, {
    source: provider,
    label: `${name} ${type}${options.cd ? " cd" : ""}`,
    accept: "application/dns-json",
    timeoutMs: options.timeoutMs ?? 8000,
    log: options.log,
  });
  if (!res.ok) throw new DnsError(`${provider}: HTTP ${res.status}`);
  const json = JSON.parse(res.text) as DohJson;
  const ede = edeOf(json);
  return {
    status: json.Status,
    ad: json.AD === true,
    answers: (json.Answer ?? []).map(normalizeRecord),
    provider,
    ...(ede ? { ede } : {}),
  };
}

/**
 * True when the resolver could not get an answer (SERVFAIL, REFUSED…), as
 * opposed to a real one: NOERROR, with or without records, or NXDOMAIN. A
 * failed lookup says nothing about what the zone publishes.
 */
export function lookupFailed(answer: DnsAnswer): boolean {
  return answer.status !== 0 && answer.status !== 3;
}

/**
 * Creates a caching resolver that falls back to the second provider if the
 * first one fails or cannot get an answer (SERVFAIL): one resolver's upstream
 * trouble must not read as "the record does not exist".
 */
export function createResolver(options: ResolverOptions = {}): Resolver {
  const cache = new Map<string, Promise<DnsAnswer>>();

  async function query(name: string, type: RRType): Promise<DnsAnswer> {
    let lastError: unknown;
    let failed: DnsAnswer | undefined;
    for (const provider of PROVIDERS) {
      try {
        const answer = await queryProvider(provider.id, name, type, options);
        if (!lookupFailed(answer)) return answer;
        failed = answer;
      } catch (err) {
        lastError = err;
      }
    }
    if (failed) return failed;
    throw new DnsError(`DNS query failed for ${name} ${type}: ${String(lastError)}`);
  }

  return (name, type) => {
    const key = `${name.toLowerCase()}|${type}`;
    let pending = cache.get(key);
    if (!pending) {
      pending = query(name, type);
      pending.catch(() => cache.delete(key));
      cache.set(key, pending);
    }
    return pending;
  };
}

/** Records of the requested type only (drops the CNAME chain). */
export function recordsOf(answer: DnsAnswer, type: RRType): DnsRecord[] {
  return answer.answers.filter((r) => r.type === type);
}
