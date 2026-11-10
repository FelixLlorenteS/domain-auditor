/**
 * RDAP (RFC 9083), asked straight to the registry that runs the TLD or the
 * address block, found through IANA's bootstrap registries (RFC 9224). rdap.org,
 * a volunteer redirector with a tight rate limit, is only a fallback for when the
 * IANA files cannot be read.
 */

import { expandIPv6 } from "./ip";
import { loggedFetch, type RawLog } from "./raw";

export const RDAP_BASE = "https://rdap.org";
export const IANA_BOOTSTRAP = "https://data.iana.org/rdap";

type BootstrapKind = "dns" | "ipv4" | "ipv6";
/** Entry (TLD or CIDR) → base URL of its RDAP service. */
type Bootstrap = Map<string, string>;

/** One download per bootstrap file and fetch function (the page reuses it across audits). */
const bootstraps = new WeakMap<typeof fetch, Map<BootstrapKind, Promise<Bootstrap | null>>>();

function bootstrap(kind: BootstrapKind, doFetch: typeof fetch, timeoutMs: number, log?: RawLog): Promise<Bootstrap | null> {
  let byKind = bootstraps.get(doFetch);
  if (!byKind) bootstraps.set(doFetch, (byKind = new Map()));
  let pending = byKind.get(kind);
  if (!pending) {
    pending = loggedFetch(doFetch, `${IANA_BOOTSTRAP}/${kind}.json`, { source: "rdap", label: `IANA bootstrap ${kind}`, timeoutMs, log })
      .then((res) => {
        if (!res.ok) return null;
        const json = JSON.parse(res.text) as { services?: Array<[string[], string[]]> };
        const map: Bootstrap = new Map();
        for (const [entries, urls] of json.services ?? []) {
          // Several URLs are equivalent; HTTPS is preferred (RFC 9224, section 3).
          const url = urls.find((u) => u.startsWith("https://"));
          if (url) for (const e of entries) map.set(e.toLowerCase(), url.endsWith("/") ? url : `${url}/`);
        }
        return map;
      })
      .catch(() => null);
    byKind.set(kind, pending);
    // A failed download is not kept: the next audit tries again.
    void pending.then((b) => b ?? byKind!.delete(kind));
  }
  return pending;
}

/** Label-wise longest match of a domain name (RFC 9224, section 4). */
export function rdapBaseForDomain(map: Bootstrap, domain: string): string | undefined {
  const labels = domain.toLowerCase().split(".");
  for (let i = 0; i < labels.length; i++) {
    const url = map.get(labels.slice(i).join("."));
    if (url) return url;
  }
  return undefined;
}

const toBits = (ip: string, version: 4 | 6): bigint =>
  version === 4
    ? ip.split(".").reduce((acc, o) => (acc << 8n) + BigInt(Number(o)), 0n)
    : expandIPv6(ip).reduce((acc, g) => (acc << 16n) + BigInt(parseInt(g, 16)), 0n);

/** Longest prefix match of an address (RFC 9224, section 5). */
export function rdapBaseForIp(map: Bootstrap, ip: string, version: 4 | 6): string | undefined {
  const width = version === 4 ? 32 : 128;
  const addr = toBits(ip, version);
  let best: { len: number; url: string } | undefined;
  for (const [cidr, url] of map) {
    const [net = "", lenText = ""] = cidr.split("/");
    const len = Number(lenText);
    if (!Number.isInteger(len) || len > width || (best && len <= best.len)) continue;
    let base: bigint;
    try {
      base = toBits(net, version);
    } catch {
      continue;
    }
    const shift = BigInt(width - len);
    if (addr >> shift === base >> shift) best = { len, url };
  }
  return best?.url;
}

interface RdapEntity {
  roles?: string[];
  vcardArray?: [string, Array<[string, unknown, string, unknown]>];
  entities?: RdapEntity[];
}

interface RdapObject {
  name?: string;
  handle?: string;
  status?: string[];
  country?: string;
  startAddress?: string;
  endAddress?: string;
  cidr0_cidrs?: Array<{ v4prefix?: string; v6prefix?: string; length: number }>;
  events?: Array<{ eventAction: string; eventDate: string }>;
  entities?: RdapEntity[];
  links?: Array<{ rel?: string; href?: string; type?: string }>;
}

export interface DomainRegistration {
  domain: string;
  registrar?: string;
  created?: string;
  expires?: string;
  status: string[];
  /** Registrant organisation, only when the registrar publishes it. */
  registrant?: string;
  /** The registrar answered but hides the registrant (GDPR / privacy). */
  registrantRedacted?: boolean;
}

/** Placeholders registrars use instead of personal data. */
const REDACTED = /redact|privacy|withheld|not disclosed|data protected|gdpr|statutory masking/i;

/**
 * Registrant organisation from the registrar's RDAP. Only the organisation (or the
 * name, if no organisation) is used; addresses and contacts are never read out.
 */
function registrantOf(obj: RdapObject): { registrant?: string; redacted: boolean } {
  const entity = findEntity(obj.entities, "registrant");
  if (!entity) return { redacted: false };
  const props = entity.vcardArray?.[1] ?? [];
  const pick = (key: string) => {
    const value = props.find((p) => p[0] === key)?.[3];
    return typeof value === "string" && value.trim() ? value.trim() : undefined;
  };
  const org = pick("org");
  const fn = pick("fn");
  const candidate = [org, fn].find((v) => v && !REDACTED.test(v));
  return candidate ? { registrant: candidate, redacted: false } : { redacted: Boolean(org || fn) };
}

export interface IpRegistration {
  name?: string;
  handle?: string;
  range?: string;
  country?: string;
  organization?: string;
}

type Fetch = typeof fetch;

async function getRdap(url: string, doFetch: Fetch, timeoutMs: number, log?: RawLog): Promise<RdapObject | null> {
  const label = url.replace(/^https:\/\//, "");
  const res = await loggedFetch(doFetch, url, { source: "rdap", label, accept: "application/rdap+json", timeoutMs, log });
  if (!res.ok) return null;
  return JSON.parse(res.text) as RdapObject;
}

async function getJson(url: string, doFetch: Fetch, timeoutMs: number, log?: RawLog): Promise<RdapObject | null> {
  const label = url.replace(/^https:\/\//, "");
  const res = await loggedFetch(doFetch, url, { source: "rdap", label, accept: "application/rdap+json", timeoutMs, log });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`RDAP HTTP ${res.status}`);
  return JSON.parse(res.text) as RdapObject;
}

function vcardName(entity: RdapEntity): string | undefined {
  const fn = entity.vcardArray?.[1]?.find((p) => p[0] === "fn");
  const value = fn?.[3];
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function findEntity(entities: RdapEntity[] | undefined, role: string): RdapEntity | undefined {
  for (const e of entities ?? []) {
    if (e.roles?.includes(role)) return e;
    const nested = findEntity(e.entities, role);
    if (nested) return nested;
  }
  return undefined;
}

function event(obj: RdapObject, action: string): string | undefined {
  return obj.events?.find((e) => e.eventAction === action)?.eventDate;
}

/**
 * Registration data of a domain. Subdomains have no RDAP entry, so it walks up
 * the labels until one answers. Returns null if the TLD has no RDAP service.
 */
export async function lookupDomain(name: string, doFetch: Fetch = fetch, timeoutMs = 8000, log?: RawLog): Promise<DomainRegistration | null> {
  const map = await bootstrap("dns", doFetch, timeoutMs, log);
  // A TLD missing from IANA's registry has no RDAP service (.es, .de…): nothing to ask.
  const base = map ? rdapBaseForDomain(map, name) : `${RDAP_BASE}/`;
  if (!base) return null;
  const labels = name.split(".");
  for (let i = 0; i <= labels.length - 2; i++) {
    const domain = labels.slice(i).join(".");
    const obj = await getJson(`${base}domain/${domain}`, doFetch, timeoutMs, log);
    if (!obj) continue;
    const registrar = findEntity(obj.entities, "registrar");
    const result: DomainRegistration = {
      domain,
      registrar: registrar ? vcardName(registrar) : undefined,
      created: event(obj, "registration"),
      expires: event(obj, "expiration"),
      status: obj.status ?? [],
    };
    // Thin registries (.com, .net) leave the registrant to the registrar's RDAP,
    // linked as "related"; it is optional and a failure there changes nothing else.
    const related = obj.links?.find((l) => l.rel === "related" && l.href?.startsWith("https://") && /rdap/i.test(`${l.type ?? ""} ${l.href}`));
    const own = registrantOf(obj);
    let holder = own;
    if (!own.registrant && related?.href) {
      try {
        const regObj = await getRdap(related.href, doFetch, timeoutMs, log);
        if (regObj) holder = registrantOf(regObj);
      } catch {
        /* the registrar's RDAP is optional */
      }
    }
    if (holder.registrant) result.registrant = holder.registrant;
    if (holder.redacted) result.registrantRedacted = true;
    return result;
  }
  return null;
}

export async function lookupIp(ip: string, doFetch: Fetch = fetch, timeoutMs = 8000, log?: RawLog): Promise<IpRegistration | null> {
  const version = ip.includes(":") ? 6 : 4;
  const map = await bootstrap(version === 4 ? "ipv4" : "ipv6", doFetch, timeoutMs, log);
  const base = map ? rdapBaseForIp(map, ip, version) : `${RDAP_BASE}/`;
  if (!base) return null;
  const obj = await getJson(`${base}ip/${ip}`, doFetch, timeoutMs, log);
  if (!obj) return null;
  const cidr = obj.cidr0_cidrs?.[0];
  const range = cidr
    ? `${cidr.v4prefix ?? cidr.v6prefix}/${cidr.length}`
    : obj.startAddress && obj.endAddress
      ? `${obj.startAddress} – ${obj.endAddress}`
      : undefined;
  const owner = findEntity(obj.entities, "registrant") ?? findEntity(obj.entities, "administrative");
  return {
    name: obj.name,
    handle: obj.handle,
    range,
    country: obj.country,
    organization: owner ? vcardName(owner) : undefined,
  };
}

export interface AsnInfo {
  prefix?: string;
  asn?: number;
  holder?: string;
}

/** Origin AS of the prefix that covers an IP, from RIPEstat (works for every region). */
export async function lookupAsn(ip: string, doFetch: Fetch = fetch, timeoutMs = 8000, log?: RawLog): Promise<AsnInfo | null> {
  const url = `https://stat.ripe.net/data/prefix-overview/data.json?resource=${encodeURIComponent(ip)}&sourceapp=domain-auditor`;
  const res = await loggedFetch(doFetch, url, { source: "ripestat", label: `prefix-overview ${ip}`, timeoutMs, log });
  if (!res.ok) return null;
  const json = JSON.parse(res.text) as { data?: { resource?: string; announced?: boolean; asns?: Array<{ asn: number; holder: string }> } };
  const data = json.data;
  if (!data?.announced) return null;
  const first = data.asns?.[0];
  return { prefix: data.resource, asn: first?.asn, holder: first?.holder };
}

/**
 * Country where an IP is located, from RIPEstat's MaxMind GeoLite data. Anycast
 * and CDN addresses serve from many countries at once and come back as "?":
 * then `country` is undefined rather than a misleading single country.
 */
export async function lookupGeo(ip: string, doFetch: Fetch = fetch, timeoutMs = 8000, log?: RawLog): Promise<{ country?: string } | null> {
  const url = `https://stat.ripe.net/data/maxmind-geo-lite/data.json?resource=${encodeURIComponent(ip)}&sourceapp=domain-auditor`;
  const res = await loggedFetch(doFetch, url, { source: "ripestat", label: `maxmind-geo-lite ${ip}`, timeoutMs, log });
  if (!res.ok) return null;
  const json = JSON.parse(res.text) as { data?: { located_resources?: Array<{ locations?: Array<{ country?: string }> }> } };
  const countries = [...new Set((json.data?.located_resources ?? []).flatMap((r) => r.locations ?? []).map((l) => l.country ?? "?"))];
  const only = countries.length === 1 ? countries[0] : undefined;
  return only && /^[A-Z]{2}$/.test(only) ? { country: only } : {};
}
