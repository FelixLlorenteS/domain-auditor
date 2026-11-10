/** SPF (RFC 7208): parsing, DNS lookup counting and findings. */
import { lookupFailed, recordsOf, type Resolver, type RRType } from "./doh";
import { isIPv4, normalizeIPv6 } from "./ip";
import type { MailProvider } from "./mail";
import { finding, withSuggest, type Finding, type Suggestion } from "./types";

export type Qualifier = "+" | "-" | "~" | "?";

export interface SpfTerm {
  qualifier: Qualifier;
  mechanism: string;
  value?: string;
}

export interface ParsedSpf {
  terms: SpfTerm[];
  redirect?: string;
  all?: Qualifier;
  errors: string[];
}

const MECHANISMS = new Set(["all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists"]);
/** Mechanisms and modifiers that cost a DNS lookup (RFC 7208, section 4.6.4). */
const LOOKUP_TERMS = new Set(["include", "a", "mx", "ptr", "exists"]);
export const MAX_LOOKUPS = 10;

export function isSpf(txt: string): boolean {
  return /^v=spf1(\s|$)/i.test(txt);
}

/** macro-expand (RFC 7208, section 7.1): `%{letter digits r delimiters}`, `%%`, `%_` or `%-`. */
const MACRO_EXPAND = /%\{[slodiphcrtv]\d*r?[.\-+,/_=]*\}|%%|%_|%-/gi;
/** toplabel (RFC 7208, section 7.1): not all digits, no hyphen at either end. */
const TOPLABEL = /^(?:[a-z0-9]*[a-z][a-z0-9]*|[a-z0-9]+-[a-z0-9-]*[a-z0-9])$/i;

/**
 * domain-spec (RFC 7208, section 7.1): any text with valid macros, ending in a
 * macro or in "." plus a top label. `example`, `1.2.3.4` or `a.b%x` are not valid.
 */
export function isDomainSpec(spec: string): boolean {
  if (!spec || /\s/.test(spec)) return false;
  if (spec.replace(MACRO_EXPAND, "").includes("%")) return false;
  if (/(?:%\{[^}]*\}|%%|%_|%-)$/i.test(spec)) return true;
  const labels = spec.replace(/\.$/, "").split(".");
  return labels.length >= 2 && TOPLABEL.test(labels.at(-1) ?? "");
}

/** `/n` with 0 <= n <= max. */
const cidrOk = (cidr: string | undefined, max: number) => cidr === undefined || (/^(0|[1-9]\d{0,2})$/.test(cidr) && Number(cidr) <= max);

/**
 * Checks the value of a mechanism against its grammar (RFC 7208, sections 5.1
 * to 5.7): a syntax error anywhere makes the whole record a permerror (section 4.6).
 */
function validTerm(mechanism: string, raw: string): boolean {
  const rest = raw.slice(mechanism.length);
  switch (mechanism) {
    case "all":
      return rest === "";
    case "ip4": {
      const m = /^:([^/]+)(?:\/(.*))?$/.exec(rest);
      return Boolean(m && isIPv4(m[1] ?? "") && cidrOk(m[2], 32));
    }
    case "ip6": {
      const m = /^:([^/]+)(?:\/(.*))?$/.exec(rest);
      return Boolean(m && normalizeIPv6(m[1] ?? "") && cidrOk(m[2], 128));
    }
    case "include":
    case "exists":
      return rest.startsWith(":") && isDomainSpec(rest.slice(1));
    case "ptr":
      return rest === "" || (rest.startsWith(":") && isDomainSpec(rest.slice(1)));
    case "a":
    case "mx": {
      // [ ":" domain-spec ] [ "/" ip4-cidr ] [ "//" ip6-cidr ]
      const m = /^(?::([^/]*))?(?:\/(\d+))?(?:\/\/(\d+))?$/.exec(rest);
      return Boolean(m && (m[1] === undefined || isDomainSpec(m[1])) && cidrOk(m[2], 32) && cidrOk(m[3], 128));
    }
    default:
      return false;
  }
}

export function parseSpf(record: string): ParsedSpf {
  const parts = record.trim().split(/\s+/).slice(1);
  const result: ParsedSpf = { terms: [], errors: [] };
  const modifiers = new Set<string>();

  for (const part of parts) {
    const modifier = /^([a-z][a-z0-9_.-]*)=(.*)$/i.exec(part);
    if (modifier) {
      const key = (modifier[1] ?? "").toLowerCase();
      // redirect and exp: at most once each, with a valid domain-spec (RFC 7208, section 6).
      // Other modifiers are ignored wherever they appear.
      if (key === "redirect" || key === "exp") {
        if (modifiers.has(key) || !isDomainSpec(modifier[2] ?? "")) result.errors.push(part);
        modifiers.add(key);
        if (key === "redirect" && result.redirect === undefined) result.redirect = modifier[2];
      }
      continue;
    }
    const m = /^([+\-~?]?)([a-z0-9]+)(?=$|[:/])(.*)$/i.exec(part);
    const mechanism = (m?.[2] ?? "").toLowerCase();
    if (!m || !MECHANISMS.has(mechanism) || !validTerm(mechanism, `${mechanism}${m[3] ?? ""}`)) {
      result.errors.push(part);
      continue;
    }
    const qualifier = (m[1] || "+") as Qualifier;
    const value = part.includes(":") ? part.slice(part.indexOf(":") + 1) : undefined;
    result.terms.push(value === undefined ? { qualifier, mechanism } : { qualifier, mechanism, value });
    if (mechanism === "all") result.all = qualifier;
  }
  return result;
}

export interface SpfTree {
  lookups: number;
  /** Domains referenced by include/redirect that have no SPF record. */
  missing: string[];
  /**
   * Domains referenced by include/redirect whose lookup failed (SERVFAIL,
   * timeout): nothing is known about them, so they are neither "missing" nor
   * counted further. Receivers get a temperror there (RFC 7208, section 2.6.6).
   */
  errors: string[];
  loops: string[];
  /** Terms whose DNS query returned nothing (NXDOMAIN or no records). */
  voids: string[];
  /** `mx` mechanisms whose domain has more than 10 MX records. */
  mxTooMany: string[];
  /**
   * Terms with macros (`%{i}`, `%{d}`…): they expand with each message's data
   * (RFC 7208, section 7), so they are counted but never resolved as written.
   */
  macros: string[];
  /** The walk stopped following includes well past the limit: `lookups` is a minimum. */
  truncated: boolean;
}

/** RFC 7208, section 4.6.4: implementations SHOULD limit void lookups to two. */
export const MAX_VOID_LOOKUPS = 2;
/** RFC 7208, section 4.6.4: each `mx` mechanism may not use more than 10 MX records. */
export const MAX_MX_PER_MECHANISM = 10;
/**
 * Past this many lookups the result is a permerror anyway, so includes are no
 * longer followed: a hostile record cannot make the browser run hundreds of queries.
 */
const FOLLOW_LIMIT = MAX_LOOKUPS * 2;

/** Target of `a`, `mx` or `exists`: its own domain-spec, or the domain being evaluated. */
function targetOf(term: SpfTerm, domain: string): string | null {
  const raw = (term.value ?? domain).split("/")[0] ?? "";
  // Macros (%{i}…) depend on the sender and cannot be resolved ahead of time.
  return raw.includes("%") || !raw ? null : raw.toLowerCase();
}

/**
 * A void lookup is a NOERROR answer with no records, or NXDOMAIN (RFC 7208,
 * section 4.6.4). A lookup that failed (network error, SERVFAIL) is not one.
 */
async function isVoid(name: string, types: RRType[], resolver: Resolver): Promise<{ empty: boolean; count: number }> {
  let count = 0;
  for (const type of types) {
    try {
      const answer = await resolver(name, type);
      if (lookupFailed(answer)) return { empty: false, count: 0 };
      count += recordsOf(answer, type).length;
    } catch {
      return { empty: false, count: 0 };
    }
  }
  return { empty: count === 0, count };
}

const emptyTree = (): SpfTree => ({ lookups: 0, missing: [], errors: [], loops: [], voids: [], mxTooMany: [], macros: [], truncated: false });

/**
 * Follows include and redirect recursively and counts the DNS lookups the record
 * costs (limit 10), the void lookups (limit 2) and `mx` mechanisms with more than
 * 10 MX records, all from RFC 7208, section 4.6.4.
 */
export async function countLookups(
  spf: ParsedSpf,
  resolver: Resolver,
  seen = new Set<string>(),
  domain = [...seen].at(-1) ?? "",
  budget = { used: 0 },
): Promise<SpfTree> {
  const tree = emptyTree();
  const targets: string[] = [];
  const checks: Array<Promise<void>> = [];

  for (const term of spf.terms) {
    if (!LOOKUP_TERMS.has(term.mechanism)) continue;
    tree.lookups++;
    budget.used++;
    if (term.value?.includes("%")) {
      tree.macros.push(`${term.mechanism}:${term.value}`);
      continue;
    }
    if (term.mechanism === "include" && term.value) targets.push(term.value.toLowerCase());
    const target = term.mechanism === "include" || term.mechanism === "ptr" ? null : targetOf(term, domain);
    if (!target) continue;
    const label = `${term.mechanism}:${target}`;
    if (term.mechanism === "mx") {
      checks.push(
        isVoid(target, ["MX"], resolver).then(({ empty, count }) => {
          if (empty) tree.voids.push(label);
          if (count > MAX_MX_PER_MECHANISM) tree.mxTooMany.push(`${label} (${count})`);
        }),
      );
    } else {
      checks.push(
        isVoid(target, ["A", "AAAA"], resolver).then(({ empty }) => {
          if (empty) tree.voids.push(label);
        }),
      );
    }
  }
  if (spf.redirect && spf.all === undefined) {
    tree.lookups++;
    budget.used++;
    if (spf.redirect.includes("%")) tree.macros.push(`redirect=${spf.redirect}`);
    else targets.push(spf.redirect.toLowerCase());
  }

  const children = await Promise.all(
    targets.map(async (target): Promise<SpfTree> => {
      if (seen.has(target)) return { ...emptyTree(), loops: [target] };
      if (budget.used > FOLLOW_LIMIT) return { ...emptyTree(), truncated: true };
      const found = await lookupSpf(target, resolver);
      if (found.failed) return { ...emptyTree(), errors: [target] };
      if (found.records.length !== 1) return { ...emptyTree(), missing: [target] };
      return countLookups(parseSpf(found.records[0] ?? ""), resolver, new Set(seen).add(target), target, budget);
    }),
  );
  await Promise.all(checks);
  for (const child of children) {
    tree.lookups += child.lookups;
    tree.missing.push(...child.missing);
    tree.errors.push(...child.errors);
    tree.loops.push(...child.loops);
    tree.voids.push(...child.voids);
    tree.mxTooMany.push(...child.mxTooMany);
    tree.macros.push(...child.macros);
    tree.truncated ||= child.truncated;
  }
  return tree;
}

/** SPF records at a name, or `failed` when the TXT lookup got no answer (SERVFAIL, timeout). */
export async function lookupSpf(domain: string, resolver: Resolver): Promise<{ failed: boolean; records: string[] }> {
  try {
    const answer = await resolver(domain, "TXT");
    if (lookupFailed(answer)) return { failed: true, records: [] };
    return { failed: false, records: recordsOf(answer, "TXT").map((r) => r.data).filter(isSpf) };
  } catch {
    return { failed: true, records: [] };
  }
}

const ALL_RE = /^[+\-~?]?all$/i;

function terms(record: string): string[] {
  return record.trim().split(/\s+/).slice(1);
}

/** Rebuilds an SPF record with `~all` as its only, final `all`. */
export function withSoftfail(record: string): string {
  return ["v=spf1", ...terms(record).filter((t) => !ALL_RE.test(t)), "~all"].join(" ");
}

/** Merges several SPF records into one, keeping every sender once and a single `all`. */
export function mergeSpf(records: string[]): string {
  const seen = new Set<string>();
  const out: string[] = [];
  let all = "";
  for (const r of records) {
    for (let t of terms(r)) {
      if (ALL_RE.test(t)) {
        all ||= t;
        continue;
      }
      // With an `all` in the merged record a redirect would be ignored (RFC 7208,
      // section 6.1): its senders are kept as an include, which costs the same lookup.
      if (/^redirect=/i.test(t)) t = `include:${t.slice(t.indexOf("=") + 1)}`;
      const key = t.toLowerCase();
      if (!seen.has(key)) {
        seen.add(key);
        out.push(t);
      }
    }
  }
  return ["v=spf1", ...out, all && !/^\+?all$/i.test(all) ? all : "~all"].join(" ");
}

function spfFix(domain: string, value: string, action: Suggestion["action"] = "replace"): Suggestion[] {
  return [{ type: "TXT", name: domain, value, action }];
}

export async function checkSpf(
  domain: string,
  txt: string[],
  hasMx: boolean,
  resolver: Resolver,
  provider?: MailProvider | null,
): Promise<Finding[]> {
  const records = txt.filter(isSpf);
  if (records.length === 0) {
    const value = !hasMx ? "v=spf1 -all" : provider?.spf ? `v=spf1 include:${provider.spf} ~all` : "v=spf1 mx ~all";
    const params = provider ? { provider: provider.name } : undefined;
    const id = !hasMx ? "spf.missing-nomail" : provider?.spf ? "spf.missing-provider" : "spf.missing";
    return [withSuggest(finding(id, hasMx ? "fail" : "warn", params), spfFix(domain, value, "add"))];
  }
  if (records.length > 1) {
    return [withSuggest(finding("spf.multiple", "fail", { count: records.length }), spfFix(domain, mergeSpf(records)))];
  }

  const record = records[0] ?? "";
  const spf = parseSpf(record);
  const out: Finding[] = [finding("spf.found", "ok", { record })];

  if (spf.errors.length) out.push(finding("spf.syntax", "fail", { terms: spf.errors.join(" ") }));

  // An SPF that authorises nobody while the domain has mail servers: its own mail fails SPF.
  const noSenders = hasMx && !spf.redirect && !spf.terms.some((t) => t.mechanism !== "all");
  if (noSenders) {
    const all = spf.all === "-" ? "-all" : "~all";
    const value = provider?.spf ? `v=spf1 include:${provider.spf} ${all}` : `v=spf1 mx ${all}`;
    out.push(withSuggest(finding("spf.no-senders", "warn", provider ? { provider: provider.name } : { provider: "" }), spfFix(domain, value)));
  }

  switch (spf.all) {
    case "+":
      out.push(withSuggest(finding("spf.all-pass", "fail"), spfFix(domain, withSoftfail(record))));
      break;
    case "?":
      out.push(withSuggest(finding("spf.all-neutral", "warn"), spfFix(domain, withSoftfail(record))));
      break;
    // With no sender listed, "all" catches everything, the domain's own mail included: not praised.
    case "~":
      if (!noSenders) out.push(finding("spf.all-softfail", "ok"));
      break;
    case "-":
      if (!noSenders) out.push(finding("spf.all-fail", "ok"));
      break;
    default:
      if (!spf.redirect) out.push(withSuggest(finding("spf.no-all", "warn"), spfFix(domain, withSoftfail(record))));
  }

  if (spf.terms.some((t) => t.mechanism === "ptr")) out.push(finding("spf.ptr", "warn"));

  const tree = await countLookups(spf, resolver, new Set([domain]), domain);
  // Only what does not exist is removed; a lookup that failed may work in a minute.
  if (tree.errors.length) out.push(finding("spf.include-error", "info", { domains: tree.errors.join(", ") }));
  if (tree.missing.length) {
    const missing = new Set(tree.missing);
    const fixed = ["v=spf1", ...terms(record).filter((t) => !missing.has(t.replace(/^[+\-~?]?(include:|redirect=)/i, "").toLowerCase()))].join(" ");
    out.push(withSuggest(finding("spf.include-missing", "fail", { domains: tree.missing.join(", ") }), spfFix(domain, fixed)));
  }
  if (tree.loops.length) out.push(finding("spf.loop", "fail", { domains: tree.loops.join(", ") }));
  if (tree.voids.length > MAX_VOID_LOOKUPS)
    out.push(finding("spf.void-lookups", "warn", { count: tree.voids.length, max: MAX_VOID_LOOKUPS, terms: tree.voids.join(", ") }));
  if (tree.mxTooMany.length) out.push(finding("spf.mx-too-many", "fail", { terms: tree.mxTooMany.join(", "), max: MAX_MX_PER_MECHANISM }));
  if (tree.macros.length) out.push(finding("spf.macros", "info", { terms: tree.macros.join(", ") }));
  if (tree.lookups > MAX_LOOKUPS) {
    out.push(finding("spf.too-many-lookups", "fail", { count: tree.truncated ? `${tree.lookups}+` : tree.lookups, max: MAX_LOOKUPS }));
  } else if (!tree.errors.length) {
    // With an include that could not be read, the count is only a minimum: no verdict.
    out.push(finding("spf.lookups", "ok", { count: tree.lookups, max: MAX_LOOKUPS }));
  }
  return out;
}
