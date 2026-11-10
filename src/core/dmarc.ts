/** DMARC (RFC 9989, which obsoletes RFC 7489): parsing, policy discovery and findings. */
import { lookupFailed, recordsOf, type Resolver } from "./doh";
import { finding, withSuggest, type Finding, type RecordRow } from "./types";

/**
 * A DMARC Policy Record starts with the `v` tag, whose value is exactly
 * `DMARC1`: case-sensitive (RFC 9989, sections 4.7 and 4.8). The tag name and
 * the spaces around `=` and `;` follow the ABNF (`*WSP`).
 */
export function isDmarc(txt: string): boolean {
  return /^[vV][ \t]*=[ \t]*DMARC1[ \t]*(;|$)/.test(txt);
}

/** Looks like DMARC (`v=dmarc1`, leading spaces…) but receivers MUST ignore it. */
export function isBrokenDmarc(txt: string): boolean {
  return !isDmarc(txt) && /^\s*v\s*=\s*dmarc1\s*(;|$)/i.test(txt);
}

export function parseTags(record: string): Map<string, string> {
  const tags = new Map<string, string>();
  for (const part of record.split(";")) {
    const i = part.indexOf("=");
    if (i < 0) continue;
    const key = part.slice(0, i).trim().toLowerCase();
    if (key && !tags.has(key)) tags.set(key, part.slice(i + 1).trim());
  }
  return tags;
}

/**
 * Rebuilds a DMARC record changing some tags. `v` stays first and `p` second, as
 * RFC 9989 recommends; a `null` value removes the tag.
 */
export function editDmarc(record: string, changes: Record<string, string | null>): string {
  const tags = parseTags(record);
  for (const [k, v] of Object.entries(changes)) {
    if (v === null) tags.delete(k);
    else tags.set(k, v);
  }
  tags.delete("v");
  const p = tags.get("p");
  tags.delete("p");
  const parts = ["v=DMARC1", ...(p ? [`p=${p}`] : []), ...[...tags].map(([k, v]) => `${k}=${v}`)];
  return `${parts.join("; ")};`;
}

const POLICIES = new Set(["none", "quarantine", "reject"]);
/** Tags removed by RFC 9989 (Appendix C.5.2). */
const REMOVED_TAGS = ["pct", "rf", "ri"];

export interface DmarcResult {
  findings: Finding[];
  records: RecordRow[];
}

interface Lookup {
  domain: string;
  records: string[];
  rows: RecordRow[];
  /** Records that look like DMARC but are ignored by receivers (`v=dmarc1`…). */
  broken: RecordRow[];
  /** The query got no answer (SERVFAIL, timeout): nothing is known about this name. */
  failed: boolean;
}

const toRow = ({ name, type, ttl, data }: RecordRow & { ttl?: number }): RecordRow => ({ name, type, ttl, data });

async function lookup(domain: string, resolver: Resolver): Promise<Lookup> {
  const empty = { domain, records: [], rows: [], broken: [] };
  let answer;
  try {
    answer = await resolver(`_dmarc.${domain}`, "TXT");
  } catch {
    return { ...empty, failed: true };
  }
  if (lookupFailed(answer)) return { ...empty, failed: true };
  const txt = recordsOf(answer, "TXT");
  const dmarc = txt.filter((r) => isDmarc(r.data));
  return { domain, records: dmarc.map((r) => r.data), rows: dmarc.map(toRow), broken: txt.filter((r) => isBrokenDmarc(r.data)).map(toRow), failed: false };
}

/** Parent domains queried by the DNS Tree Walk of RFC 9989, section 4.10, in order. */
export function treeWalkTargets(domain: string): string[] {
  const all = domain.split(".");
  const labels = all.length > 8 ? all.slice(-7) : all.slice(1);
  return labels.map((_, i) => labels.slice(i).join("."));
}

export interface Discovery extends Lookup {
  multiple: boolean;
  /** Records at the Author Domain that receivers ignore, when it has no valid one. */
  ownBroken: RecordRow[];
}

/**
 * Policy discovery (RFC 9989, section 4.10.1): the Author Domain first and, if it has no
 * valid record, a DNS Tree Walk up to its Organizational Domain or PSD. A lookup that
 * fails stops the walk: a transient error is not "no record" (same section).
 */
export async function discoverDmarc(domain: string, resolver: Resolver): Promise<Discovery> {
  const own = await lookup(domain, resolver);
  // Next to a valid record, a broken one is simply discarded (section 4.10, step 2).
  const ownBroken = own.records.length ? [] : own.broken;
  if (own.failed || own.records.length) return { ...own, multiple: own.records.length > 1, ownBroken };
  for (const target of treeWalkTargets(domain)) {
    const found = await lookup(target, resolver);
    if (found.failed) return { ...found, records: [], rows: [], multiple: false, ownBroken };
    // Several records at one name are all discarded and the walk goes on.
    if (found.records.length === 1) return { ...found, multiple: false, ownBroken };
  }
  return { ...own, multiple: false, ownBroken };
}

/** The same record with a conforming version tag. */
const fixVersion = (record: string) => record.replace(/^\s*v\s*=\s*dmarc1\s*/i, "v=DMARC1");

export async function checkDmarc(domain: string, resolver: Resolver): Promise<DmarcResult> {
  const found = await discoverDmarc(domain, resolver);
  const records = [...found.ownBroken, ...found.rows];
  if (found.failed) return { findings: [finding("dmarc.lookup-error", "info", { name: `_dmarc.${found.domain}` })], records };
  if (found.multiple) return { findings: [finding("dmarc.multiple", "fail")], records };
  // A record receivers ignore: say so and propose it written correctly.
  const broken = found.ownBroken.map((r) =>
    withSuggest(finding("dmarc.bad-version", "fail", { record: r.data }), [
      { type: "TXT", name: `_dmarc.${domain}`, value: fixVersion(r.data), action: "replace" },
    ]),
  );
  if (found.records.length === 0) {
    if (broken.length) return { findings: broken, records };
    // The report mailbox is typed by the user: never invent an address.
    const value = "v=DMARC1; p=none; rua=mailto:{mailbox};";
    const suggest = [{ type: "TXT", name: `_dmarc.${domain}`, value, input: "mailbox" as const }];
    return { findings: [withSuggest(finding("dmarc.missing", "fail", { domain }), suggest)], records };
  }

  const record = found.records[0] ?? "";
  const tags = parseTags(record);
  const inherited = found.domain !== domain;
  // Fixes go to the record that applies, which may be the parent's.
  const fix = (changes: Record<string, string | null>) => {
    const value = editDmarc(record, changes);
    return [{ type: "TXT", name: `_dmarc.${found.domain}`, value, action: "replace" as const, ...(value.includes("{mailbox}") ? { input: "mailbox" as const } : {}) }];
  };
  const out: Finding[] = [...broken, finding("dmarc.found", "ok", { record })];
  if (inherited) out.push(finding("dmarc.inherited", "info", { domain: found.domain }));

  // An invalid p, sp or np makes receivers act as if the record said p=none (with a
  // valid rua) or skip DMARC altogether (RFC 9989, section 4.10.1), whatever p says.
  const invalid = ["p", "sp", "np"].filter((t) => tags.has(t) && !POLICIES.has((tags.get(t) ?? "").toLowerCase()));
  if (invalid.length) {
    const params = { tag: invalid.join(", "), value: invalid.map((t) => `${t}=${tags.get(t) ?? ""}`).join("; ") };
    // Without the broken sp/np, p applies again; a broken p cannot be guessed.
    const suggest = invalid.includes("p") ? [] : fix(Object.fromEntries(invalid.map((t) => [t, null])));
    out.push(withSuggest(finding("dmarc.invalid-policy", "fail", params), suggest));
    return { findings: out, records };
  }

  // A subdomain that inherits the record is governed by `sp` (or `p` if absent).
  const policyTag = inherited && tags.has("sp") ? "sp" : "p";
  const raw = tags.get(policyTag)?.toLowerCase();
  if (raw === undefined) {
    out.push(withSuggest(finding("dmarc.p-missing", "warn"), fix({ p: "quarantine" })));
  } else {
    // Next step up the ladder: none → quarantine → reject.
    const next = raw === "none" ? fix({ [policyTag]: "quarantine" }) : raw === "quarantine" ? fix({ [policyTag]: "reject" }) : [];
    out.push(withSuggest(finding(`dmarc.p-${raw}`, raw === "none" ? "warn" : "ok"), next));
  }

  const p = raw ?? "none";
  if (!inherited && tags.get("sp")?.toLowerCase() === "none" && p !== "none") out.push(withSuggest(finding("dmarc.sp-none", "warn"), fix({ sp: null })));
  if (tags.get("t")?.toLowerCase() === "y" && p !== "none") out.push(withSuggest(finding("dmarc.testing", "warn"), fix({ t: null })));

  const removed = REMOVED_TAGS.filter((t) => tags.has(t));
  if (removed.length) {
    const drop = Object.fromEntries(removed.map((t) => [t, null]));
    out.push(withSuggest(finding("dmarc.removed-tags", "info", { tags: removed.join(", ") }), fix(drop)));
  }

  const rua = tags.get("rua");
  if (!rua) {
    // Reports are how the owner sees who uses the domain, but they do not change how
    // receivers treat its mail (RFC 9989, section 4.7): a recommendation, not a fault.
    out.push(withSuggest(finding("dmarc.no-rua", "info", { domain: found.domain }), fix({ rua: "mailto:{mailbox}" })));
    return { findings: out, records };
  }
  // Reports to another organisation are only sent if it agrees (RFC 9990, section 4).
  const hosts = ruaHosts(rua);
  const unauthorised = (await Promise.all(hosts.map(async (h) => ((await reportsAuthorised(found.domain, h, resolver)) ? null : h)))).filter((h): h is string => h !== null);
  if (unauthorised.length) out.push(finding("dmarc.rua-unauthorized", "warn", { hosts: unauthorised.join(", "), domain: found.domain }));
  if (unauthorised.length < hosts.length || !hosts.length) out.push(finding("dmarc.rua", "ok", { rua }));
  return { findings: out, records };
}

/** Domains of the `mailto:` report addresses (a `!10m` size suffix is dropped). */
export function ruaHosts(rua: string): string[] {
  const hosts = [...rua.matchAll(/mailto:[^@,\s]+@([^!,\s;]+)/gi)].map((m) => m[1]!.toLowerCase().replace(/\.$/, ""));
  return [...new Set(hosts)];
}

/** Second-level labels that usually sit under a country code as public suffixes (co.uk, com.es…). */
const SUFFIX_SLD = new Set(["co", "com", "org", "net", "gov", "gob", "edu", "ac", "nom", "ltd", "plc", "or", "ne", "go"]);

/**
 * Whether two names belong to the same organisation, as far as can be told
 * without a list of public suffixes: one inside the other, or a shared parent
 * that is not a public suffix. When in doubt they are treated as different,
 * and then the external authorisation is checked in DNS.
 */
export function sameOrganisation(a: string, b: string): boolean {
  if (a === b || a.endsWith(`.${b}`) || b.endsWith(`.${a}`)) return true;
  const la = a.split(".").reverse();
  const lb = b.split(".").reverse();
  let shared = 0;
  while (shared < la.length && shared < lb.length && la[shared] === lb[shared]) shared++;
  if (shared >= 3) return true;
  return shared === 2 && !SUFFIX_SLD.has(la[1] ?? "") && (la[1] ?? "").length > 3;
}

/**
 * External destination verification (RFC 9990, section 4): a host of another
 * organisation must publish a record starting with `v=DMARC1` at
 * `<policy domain>._report._dmarc.<host>`. A lookup that fails proves nothing,
 * so it counts as authorised (no warning on a guess).
 */
export async function reportsAuthorised(policyDomain: string, host: string, resolver: Resolver): Promise<boolean> {
  if (sameOrganisation(policyDomain, host)) return true;
  try {
    const answer = await resolver(`${policyDomain}._report._dmarc.${host}`, "TXT");
    if (lookupFailed(answer)) return true;
    return recordsOf(answer, "TXT").some((r) => isDmarc(r.data));
  } catch {
    return true;
  }
}
