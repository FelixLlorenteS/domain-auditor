/**
 * Independent re-implementations of what the auditor claims, written apart from
 * src/core on purpose (no shared parsing): if both agree, the claim is backed by
 * two different readings of the RFC and two different resolvers.
 */
import { browserFetch, consensus } from "./truth";

// ---------------------------------------------------------------- DMARC (RFC 9989)

export type DmarcPolicy = "none" | "quarantine" | "reject" | "invalid" | "absent" | "unknown";

const tagsOf = (record: string) =>
  new Map(
    record
      .split(";")
      .map((p) => p.split("="))
      .filter((kv) => kv.length >= 2)
      .map(([k, ...v]) => [k!.trim().toLowerCase(), v.join("=").trim()] as const)
      .reverse(), // the first occurrence wins
  );

async function dmarcAt(name: string): Promise<{ failed: boolean; records: string[] } | null> {
  const t = await consensus(`_dmarc.${name}`, "TXT");
  if (!t.agree) return null;
  if (t.status !== 0 && t.status !== 3) return { failed: true, records: [] };
  return { failed: false, records: t.data.filter((d) => /^[vV][ \t]*=[ \t]*DMARC1[ \t]*(;|$)/.test(d)) };
}

/** Policy a receiver applies to mail from `domain` (sections 4.7, 4.10 and 4.10.1). */
export async function dmarcPolicy(domain: string): Promise<{ policy: DmarcPolicy; at?: string; record?: string }> {
  const labels = domain.split(".");
  const walk = labels.length > 8 ? labels.slice(-7) : labels.slice(1);
  const names = [domain, ...walk.map((_, i) => walk.slice(i).join("."))];
  for (const name of names) {
    const found = await dmarcAt(name);
    if (!found || found.failed) return { policy: "unknown" };
    if (found.records.length !== 1) continue;
    const record = found.records[0]!;
    const tags = tagsOf(record);
    const valid = (v?: string) => v !== undefined && ["none", "quarantine", "reject"].includes(v.toLowerCase());
    if (["p", "sp", "np"].some((t) => tags.has(t) && !valid(tags.get(t)))) return { policy: "invalid", at: name, record };
    const tag = name !== domain && tags.has("sp") ? "sp" : "p";
    return { policy: (tags.get(tag)?.toLowerCase() as DmarcPolicy | undefined) ?? "none", at: name, record };
  }
  return { policy: "absent" };
}

/**
 * External report destinations that have not authorised the reports (RFC 9990,
 * section 4): `<policy domain>._report._dmarc.<host>` must hold a record starting
 * with v=DMARC1. Same organisation is approximated as one name inside the other.
 */
export async function unauthorisedRua(policyDomain: string, record: string): Promise<string[]> {
  const rua = tagsOf(record).get("rua") ?? "";
  const hosts = [...rua.matchAll(/mailto:[^@,\s]+@([^!,\s;]+)/gi)].map((m) => m[1]!.toLowerCase().replace(/\.$/, ""));
  const out: string[] = [];
  for (const host of new Set(hosts)) {
    if (host === policyDomain || host.endsWith(`.${policyDomain}`) || policyDomain.endsWith(`.${host}`)) continue;
    const t = await consensus(`${policyDomain}._report._dmarc.${host}`, "TXT");
    if (t.agree && t.status !== 2 && !t.data.some((d) => /^v\s*=\s*DMARC1/.test(d))) out.push(host);
  }
  return out;
}

// ---------------------------------------------------------------- CAA (RFC 8659)

/** Relevant RRset (section 3): the name's own CAA or the closest ancestor's. Null if the resolvers disagree. */
export async function relevantCaa(domain: string): Promise<{ owner?: string; records: string[] } | null> {
  const labels = domain.split(".");
  for (let i = 0; i < labels.length - 1; i++) {
    const name = labels.slice(i).join(".");
    const t = await consensus(name, "CAA");
    if (!t.agree || (t.status !== 0 && t.status !== 3)) return null;
    if (t.data.length) return { owner: name, records: t.data };
  }
  return { records: [] };
}

export const restrictsIssue = (records: string[]) => records.some((r) => /^\d+\s+issue\s+"/i.test(r));

// ---------------------------------------------------------------- RDAP through the IANA bootstrap

let bootstrap: Promise<Map<string, string>> | undefined;

/** Statuses published by the TLD's own registry (not through rdap.org). Null if unavailable. */
export async function registryStatus(domain: string): Promise<string[] | null> {
  bootstrap ??= browserFetch("https://data.iana.org/rdap/dns.json", { signal: AbortSignal.timeout(20_000) })
    .then((r) => r.json() as Promise<{ services: Array<[string[], string[]]> }>)
    .then((j) => new Map(j.services.flatMap(([tlds, urls]) => tlds.map((t) => [t, urls[0]!] as const))));
  const base = (await bootstrap).get(domain.split(".").pop() ?? "");
  if (!base) return null;
  const labels = domain.split(".");
  for (let i = 0; i < labels.length - 1; i++) {
    const res = await browserFetch(`${base.replace(/\/$/, "")}/domain/${labels.slice(i).join(".")}`, {
      headers: { accept: "application/rdap+json" },
      signal: AbortSignal.timeout(20_000),
    }).catch(() => null);
    if (!res) return null;
    if (res.status === 404) continue;
    if (!res.ok) return null;
    return ((await res.json()) as { status?: string[] }).status ?? [];
  }
  return null;
}

const statusKey = (s: string) => s.toLowerCase().replace(/[\s_-]/g, "");

export function lockOf(status: string[]): { transfer: boolean; registry: boolean } {
  const s = new Set(status.map(statusKey));
  const registry = s.has("locked") || ["serverupdateprohibited", "serverdeleteprohibited", "servertransferprohibited"].every((k) => s.has(k));
  const transfer = registry || ["clienttransferprohibited", "servertransferprohibited", "transferprohibited"].some((k) => s.has(k));
  return { transfer, registry };
}

// ---------------------------------------------------------------- MTA-STS policy (RFC 8461, section 3.2)

/** Mode of the published policy, read over HTTPS as a sending MTA would (the browser cannot). */
export async function mtaStsMode(domain: string): Promise<string> {
  try {
    const res = await browserFetch(`https://mta-sts.${domain}/.well-known/mta-sts.txt`, { signal: AbortSignal.timeout(15_000), redirect: "error" });
    if (!res.ok) return `HTTP ${res.status}`;
    return /^mode:\s*(\S+)/m.exec(await res.text())?.[1] ?? "sin modo";
  } catch {
    return "inaccesible";
  }
}
