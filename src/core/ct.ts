import { recordsOf, type Resolver } from "./doh";
import { loggedFetch, type RawLog } from "./raw";
import { finding, type Finding, type RecordRow } from "./types";

/**
 * Attack surface from Certificate Transparency: every public certificate is
 * logged, so crt.sh lists the names the domain has used (subdomains) and which
 * authorities issued them. From there:
 * - subdomains whose CNAME points to a name that no longer exists (dangling
 *   CNAME), which whoever registers that name at the provider can take over;
 * - certificates in force from authorities the current CAA does not allow.
 */

type Fetch = typeof fetch;

export interface CtEntry {
  issuer_name: string;
  name_value: string;
  not_before: string;
  not_after: string;
}

/** Checked per audit, to keep the number of DNS queries reasonable. */
export const MAX_SUBDOMAINS = 40;

/** Names under `domain` found in certificates, without wildcards or duplicates. */
export function subdomainsOf(entries: CtEntry[], domain: string): { names: string[]; wildcards: number } {
  const names = new Set<string>();
  let wildcards = 0;
  for (const e of entries) {
    for (const raw of e.name_value.toLowerCase().split(/\s+/)) {
      if (!raw) continue;
      if (raw.startsWith("*.")) {
        wildcards++;
        continue;
      }
      if (raw !== domain && raw.endsWith(`.${domain}`) && /^[a-z0-9._-]+$/.test(raw)) names.add(raw);
    }
  }
  return { names: [...names].sort(), wildcards };
}

/** Organisation (O=) of a certificate issuer, e.g. "Let's Encrypt". */
export function issuerOrg(issuerName: string): string {
  const m = /(?:^|,\s*)O=(?:"([^"]+)"|([^,]+))/.exec(issuerName);
  return (m?.[1] ?? m?.[2])?.trim() ?? issuerName;
}

/**
 * CAA identifiers each authority accepts, all of them equivalent, from its own
 * documentation (checked 2026-09-30). An issuer missing here is listed but never
 * judged, and a list must be complete: a missing identifier is a false alarm.
 */
const CAA_OF: Array<[RegExp, string[]]> = [
  // letsencrypt.org/docs/caa
  [/let'?s encrypt/i, ["letsencrypt.org"]],
  // Google Trust Services CPS, section 4.2.4
  [/google trust services/i, ["pki.goog"]],
  // DigiCert, "DNS CAA resource record check": one list for all its brands
  [
    /digicert|geotrust|thawte|rapidssl|symantec|quovadis/i,
    [
      "digicert.com",
      "www.digicert.com",
      "digicert.ne.jp",
      "cybertrust.ne.jp",
      "thawte.com",
      "geotrust.com",
      "rapidssl.com",
      "symantec.com",
      "digitalcertvalidation.com",
      "volusion.digitalcertvalidation.com",
      "stratossl.digitalcertvalidation.com",
      "intermediatecertificate.digitalcertvalidation.com",
      "1and1.digitalcertvalidation.com",
      "amazon.com",
      "amazontrust.com",
      "awstrust.com",
      "amazonaws.com",
      "quovadisglobal.com",
      "pkioverheid.nl",
    ],
  ],
  // Sectigo TLS CPS v6.1.5, section 4.2.4 (ZeroSSL certificates are issued by Sectigo)
  [/sectigo|comodo|usertrust|zerossl/i, ["sectigo.com", "usertrust.com", "trust-provider.com", "comodo.com", "comodoca.com", "entrust.net", "affirmtrust.com"]],
  // GlobalSign, "CAA Checking for SSL Certificates"
  [/globalsign/i, ["globalsign.com"]],
  // AWS Certificate Manager, "CAA records"
  [/amazon/i, ["amazon.com", "amazontrust.com", "awstrust.com", "amazonaws.com"]],
  [/ssl\.com/i, ["ssl.com"]],
];

/**
 * Whether one of the authority's identifiers is in `ids`. Null when the authority
 * is not known here: then nothing is said about it.
 */
export function caaAllows(org: string, ids: string[]): boolean | null {
  const own = CAA_OF.find(([re]) => re.test(org))?.[1];
  if (!own) return null;
  return ids.some((id) => own.includes(id.toLowerCase()));
}

/** The `issue` and `issuewild` values of a CAA RRset; `""` stands for `";"`, which forbids every authority. */
export interface CaaSet {
  issue: string[];
  wild: string[];
}

export function parseCaa(records: string[]): CaaSet {
  const values = (tag: string) =>
    records
      .map((r) => new RegExp(`^\\d+\\s+${tag}\\s+"([^"]*)"`, "i").exec(r)?.[1])
      .filter((v): v is string => v !== undefined)
      .map((v) => (v.split(";")[0] ?? "").trim().toLowerCase());
  return { issue: values("issue"), wild: values("issuewild") };
}

/**
 * The identifiers that restrict issuance for one name (RFC 8659, sections 4.2 and
 * 4.3): issuewild for a wildcard name if there is any, issue otherwise. Empty
 * means the RRset does not restrict issuance for that name (section 3).
 */
export function restrictingIds(set: CaaSet, wildcard: boolean): string[] {
  return wildcard && set.wild.length ? set.wild : set.issue;
}

/**
 * Namespaces where a deleted resource's name can be created again by anyone, and
 * a missing target shows as NXDOMAIN (can-i-take-over-xyz, "Vulnerable" with the
 * NXDOMAIN fingerprint; AWS, "Threat tactic spotlight: subdomain takeover").
 * Names with an ID assigned by the provider (ELB, CloudFront…) are not claimable
 * this way, so a dangling CNAME to them is an orphan record, not a takeover.
 */
const CLAIMABLE: Array<[RegExp, string]> = [
  [/\.elasticbeanstalk\.com$/, "AWS Elastic Beanstalk"],
  [
    /\.(cloudapp\.net|cloudapp\.azure\.com|azurewebsites\.net|blob\.core\.windows\.net|azure-api\.net|azurehdinsight\.net|azureedge\.net|azurecontainer\.io|database\.windows\.net|azuredatalakestore\.net|search\.windows\.net|azurecr\.io|redis\.cache\.windows\.net|servicebus\.windows\.net|trafficmanager\.net|visualstudio\.com)$/,
    "Microsoft Azure",
  ],
];
export const claimableProvider = (target: string) => CLAIMABLE.find(([re]) => re.test(target.replace(/\.$/, "")))?.[1];

/** RFC 1918, carrier-grade NAT, loopback, link-local and "this network": addresses that should not be in public DNS. */
export function isPrivateIPv4(ip: string): boolean {
  const [a, b] = ip.split(".").map(Number) as [number, number];
  return a === 0 || a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254);
}

/** Provider name from a CNAME target, only to make the finding readable. */
function providerOf(target: string): string | undefined {
  const known: Array<[RegExp, string]> = [
    [/\.azurewebsites\.net$|\.cloudapp\.(net|azure\.com)$|\.trafficmanager\.net$|\.azureedge\.net$|\.blob\.core\.windows\.net$/, "Microsoft Azure"],
    [/\.elb\.amazonaws\.com$/, "AWS Elastic Load Balancing"],
    [/\.elasticbeanstalk\.com$|\.s3[.-][a-z0-9.-]*amazonaws\.com$|\.cloudfront\.net$|\.amazonaws\.com$/, "Amazon Web Services"],
    [/\.herokuapp\.com$|\.herokudns\.com$/, "Heroku"],
    [/\.github\.io$/, "GitHub Pages"],
    [/\.netlify\.app$/, "Netlify"],
    [/\.vercel-dns\.com$|\.vercel\.app$/, "Vercel"],
    [/\.pages\.dev$/, "Cloudflare Pages"],
  ];
  return known.find(([re]) => re.test(target))?.[1];
}

export interface SurfaceResult {
  findings: Finding[];
  records: RecordRow[];
  /**
   * CAA identifiers covering every certificate in force, to build a CAA that
   * will not block renewals. Undefined if an issuer has no known identifier.
   */
  caaIds?: string[];
}

/** Certificates from a Certificate Transparency search service. */
export interface CtSource {
  entries: CtEntry[];
  source: "crt.sh" | "Cert Spotter";
  /** Only part of the certificates came back (Cert Spotter's first page). */
  partial: boolean;
}

interface CertSpotterIssuance {
  dns_names?: string[];
  issuer?: { name?: string };
  not_before?: string;
  not_after?: string;
}

/** Cert Spotter returns at most this many issuances per page; a full page means there are more. */
export const CERTSPOTTER_PAGE = 100;

/**
 * crt.sh first; when it fails (it often does: 404, 502, 429 or a timeout),
 * Cert Spotter (SSLMate), which also aggregates the CT logs and sends CORS.
 * Without an API key Cert Spotter allows few queries an hour and returns one
 * page of unexpired certificates, so it is a fallback, not the main source.
 *
 * crt.sh can also be slow (20 s answers are common). When it has not answered
 * after HEDGE_MS, Cert Spotter is asked in parallel and the first usable answer
 * wins; the report says which source it came from and whether it is partial.
 */
export const HEDGE_MS = 6_000;

export async function fetchCertificates(domain: string, opts: { fetch?: Fetch; log?: RawLog; timeoutMs?: number; hedgeMs?: number }): Promise<CtSource | null> {
  const doFetch = opts.fetch ?? fetch;
  const crtsh = (async (): Promise<CtSource | null> => {
    try {
      const url = `https://crt.sh/?q=${encodeURIComponent(`%.${domain}`)}&output=json`;
      const res = await loggedFetch(doFetch, url, { source: "crtsh", label: `Certificate Transparency crt.sh %.${domain}`, timeoutMs: opts.timeoutMs ?? 20_000, log: opts.log });
      return res.ok ? { entries: JSON.parse(res.text) as CtEntry[], source: "crt.sh", partial: false } : null;
    } catch {
      return null;
    }
  })();
  const certSpotter = async (): Promise<CtSource | null> => {
    try {
      const url = `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(domain)}&include_subdomains=true&expand=dns_names&expand=issuer`;
      const res = await loggedFetch(doFetch, url, { source: "certspotter", label: `Certificate Transparency Cert Spotter ${domain}`, timeoutMs: 15_000, log: opts.log });
      if (!res.ok) return null;
      const list = JSON.parse(res.text) as CertSpotterIssuance[];
      const entries = list.map((i) => ({
        issuer_name: i.issuer?.name ?? "",
        name_value: (i.dns_names ?? []).join("\n"),
        not_before: (i.not_before ?? "").replace(/Z$/, ""),
        not_after: (i.not_after ?? "").replace(/Z$/, ""),
      }));
      return { entries, source: "Cert Spotter", partial: list.length >= CERTSPOTTER_PAGE };
    } catch {
      return null;
    }
  };

  let timer: ReturnType<typeof setTimeout> | undefined;
  const slow = new Promise<"slow">((resolve) => (timer = setTimeout(() => resolve("slow"), opts.hedgeMs ?? HEDGE_MS)));
  const first = await Promise.race([crtsh, slow]);
  clearTimeout(timer);
  if (first && first !== "slow") return first;
  const spotter = certSpotter();
  if (first === null) return spotter;
  // Both in flight: the first usable answer, or null when both fail.
  return new Promise((resolve) => {
    let pending = 2;
    for (const p of [crtsh, spotter])
      void p.then((r) => {
        pending--;
        if (r) resolve(r);
        else if (!pending) resolve(null);
      });
  });
}

export async function checkSurface(
  domain: string,
  resolver: Resolver,
  /** CAA records that apply to the domain (its own or inherited from a parent). */
  caaRecords: string[],
  opts: { fetch?: Fetch; log?: RawLog; now?: Date; timeoutMs?: number },
): Promise<SurfaceResult> {
  const ct = await fetchCertificates(domain, opts);
  if (!ct) return { findings: [finding("ct.unavailable", "info")], records: [] };
  const { entries, source, partial } = ct;

  const findings: Finding[] = [];
  // Where the list came from, and whether it is complete, is part of the evidence.
  if (source !== "crt.sh" || partial) findings.push(finding(partial ? "ct.partial" : "ct.fallback", "info", { source, max: CERTSPOTTER_PAGE }));
  const records: RecordRow[] = [];
  const { names, wildcards } = subdomainsOf(entries, domain);
  const checked = names.slice(0, MAX_SUBDOMAINS);

  // Subdomains: resolve each one; a CNAME whose chain ends in NXDOMAIN is dangling.
  const dangling: Array<{ host: string; target: string }> = [];
  const privateHosts = new Set<string>();
  const alive: string[] = [];
  await Promise.all(
    checked.map(async (host) => {
      try {
        const ans = await resolver(host, "A");
        const cnames = recordsOf(ans, "CNAME");
        records.push(...ans.answers.map(({ name, type, ttl, data }) => ({ name, type, ttl, data, source: "ct" as const })));
        if (ans.status === 3 && cnames.length) dangling.push({ host, target: cnames[cnames.length - 1]!.data });
        if (recordsOf(ans, "A").some((r) => isPrivateIPv4(r.data))) privateHosts.add(host);
        else if (ans.status === 0 && ans.answers.length) alive.push(host);
      } catch {
        /* one failed lookup does not stop the rest */
      }
    }),
  );
  findings.push(
    names.length === 0 && wildcards
      ? finding("ct.wildcard-only", "info", { wildcards })
      : finding("ct.subdomains", "info", {
      count: names.length,
      checked: checked.length,
      alive: alive.length,
      wildcards,
          list: checked.slice(0, 12).join(", ") + (checked.length > 12 ? "…" : ""),
        }),
  );
  // Takeover only where the provider lets anyone recreate the name; otherwise it is an orphan record.
  for (const d of dangling.sort((a, b) => a.host.localeCompare(b.host))) {
    const claimable = claimableProvider(d.target);
    findings.push(
      claimable
        ? finding("ct.takeover", "fail", { host: d.host, target: d.target, provider: claimable })
        : finding("ct.dangling", "warn", { host: d.host, target: d.target, provider: providerOf(d.target) ?? "?" }),
    );
  }
  if (privateHosts.size) {
    const list = [...privateHosts].sort();
    findings.push(finding("ct.private-ips", "warn", { count: list.length, hosts: list.slice(0, 8).join(", ") + (list.length > 8 ? "…" : "") }));
  }
  // Only a CNAME chain ending in NXDOMAIN is visible from DNS, and only for the names
  // checked: this is a partial inventory, never a clean bill of health.
  if (!dangling.length && checked.length) findings.push(finding("ct.no-takeover", "info", { checked: checked.length, count: names.length }));

  // Certificates in force, by issuer, against the current CAA.
  const now = (opts.now ?? new Date()).getTime();
  const inForce = entries.filter((e) => Date.parse(`${e.not_after}Z`) > now);
  const byOrg = new Map<string, number>();
  // "DigiCert, Inc." and "DigiCert Inc" are the same issuer.
  const orgKey = (o: string) => o.replace(/[.,]/g, "").replace(/\s+/g, " ").trim();
  for (const e of inForce) byOrg.set(orgKey(issuerOrg(e.issuer_name)), (byOrg.get(orgKey(issuerOrg(e.issuer_name))) ?? 0) + 1);
  const orgs = [...byOrg.entries()].sort((a, b) => b[1] - a[1]);
  if (orgs.length) findings.push(finding("ct.issuers", "info", { issuers: orgs.map(([o, n]) => `${o} (${n})`).join(", "), total: inForce.length }));
  const ids = orgs.map(([o]) => CAA_OF.find(([re]) => re.test(o))?.[1][0]);
  // With a partial list an issuer may be missing: a CAA built from it could block its renewals.
  const caaIds = !partial && orgs.length && ids.every(Boolean) ? [...new Set(ids as string[])] : undefined;
  const apex = parseCaa(caaRecords);
  if (apex.issue.length || apex.wild.length) {
    // CAA applies per name (RFC 8659, section 3): the Relevant RRset is the first one
    // found climbing from the name (following its CNAME) up to the domain, or the domain's.
    const caaCache = new Map<string, Promise<string[]>>();
    const caaAt = (name: string) => {
      if (!caaCache.has(name)) {
        caaCache.set(
          name,
          resolver(name, "CAA")
            .then((ans) => recordsOf(ans, "CAA").map((r) => r.data))
            .catch(() => []),
        );
      }
      return caaCache.get(name)!;
    };
    const relevant = async (host: string): Promise<CaaSet> => {
      const labels = host.split(".");
      const depth = labels.length - domain.split(".").length;
      for (let i = 0; i < depth; i++) {
        const own = await caaAt(labels.slice(i).join("."));
        if (own.length) return parseCaa(own);
      }
      return apex;
    };
    const breaches = new Map<string, Set<string>>();
    for (const e of inForce) {
      const org = orgKey(issuerOrg(e.issuer_name));
      if (caaAllows(org, [...apex.issue, ...apex.wild]) === null) continue;
      const names = [...new Set(e.name_value.toLowerCase().split(/\s+/).filter((n) => n.replace(/^\*\./, "") === domain || n.endsWith(`.${domain}`)))].slice(0, 5);
      for (const name of names) {
        const wildcard = name.startsWith("*.");
        const host = name.replace(/^\*\./, "");
        const ids = restrictingIds(await relevant(host), wildcard);
        if (ids.length && caaAllows(org, ids) === false) breaches.set(org, (breaches.get(org) ?? new Set()).add(name));
      }
    }
    const caa = [...new Set([...apex.issue, ...apex.wild].map((v) => v || "—"))].join(", ");
    findings.push(
      breaches.size
        ? finding("ct.issuer-not-caa", "warn", {
            issuers: [...breaches.keys()].join(", "),
            names: [...breaches.entries()].map(([o, h]) => `${[...h].slice(0, 5).join(", ")} (${o})`).join("; "),
            caa,
          })
        : finding("ct.issuers-caa-ok", "ok", { caa }),
    );
  }
  return { findings, records, caaIds };
}
