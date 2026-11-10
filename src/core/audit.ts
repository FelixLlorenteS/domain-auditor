/** Runs every check for a target and builds the report. */
import { checkSurface, type SurfaceResult } from "./ct";
import { checkIntel } from "./intel";
import { sendersOf, verificationsOf } from "./integrations";
import { checkDane, checkDnssecAlgorithms, checkSoa, checkWildcard } from "./dnsextra";
import { lookupFailed, recordsOf, type DnsAnswer, type DnsRecord, type ProviderId, type Resolver, type RRType } from "./doh";
import type { RawLog } from "./raw";
import { checkDkim, COMMON_SELECTORS } from "./dkim";
import { checkDmarc } from "./dmarc";
import { normalizeIPv6, reverseName, specialRange } from "./ip";
import { checkMailExtras, checkMx, checkMxHosts, mtaStsPolicy, mxProvider, parseMx, spfAuthorisesSenders } from "./mail";
import { dnsProvider } from "./providers";
import { lookupAsn, lookupDomain, lookupGeo, lookupIp } from "./rdap";
import { checkSpf, isSpf } from "./spf";
import { checkMtaStsPolicy, checkWeb, type WebProbe } from "./web";
import { finding, withSuggest, type Finding, type Identity, type RecordRow, type Report, type ResolverCheck, type Section, type Target } from "./types";

export interface AuditOptions {
  resolver: Resolver;
  fetch?: typeof fetch;
  now?: Date;
  /** Every HTTP request and its raw response. */
  log?: RawLog;
  /** Asks one specific resolver, to cross-check the main answers. */
  secondOpinion?: (provider: ProviderId, name: string, type: RRType) => Promise<DnsAnswer>;
  /** DKIM selectors given by the user (e.g. the `s=` of a DKIM-Signature header). */
  dkimSelectors?: string[];
  /** Asks again with Checking Disabled (`cd=1`): the data without DNSSEC validation. */
  checkingDisabled?: (name: string, type: RRType) => Promise<DnsAnswer>;
  /**
   * Connections to the website itself (HTTP, TLS, files without CORS). Only the
   * desktop app has one; without it the web checks are not run.
   */
  web?: WebProbe;
  /**
   * Called with a first report when Certificate Transparency is slow: everything
   * else is in it, and the surface is marked as still being checked.
   */
  onPartial?: (report: Report) => void;
  /** How long Certificate Transparency may delay the first report (PARTIAL_AFTER_MS). */
  partialAfterMs?: number;
}

/** How long Certificate Transparency may delay the first report. */
export const PARTIAL_AFTER_MS = 2_500;

/** Extended DNS Error codes that mean a DNSSEC validation failure (RFC 8914, sections 4.2 to 4.13). */
const DNSSEC_EDE = new Set([1, 2, 5, 6, 7, 8, 9, 10, 11, 12]);

/**
 * A SERVFAIL caused by DNSSEC, not by dead servers: the resolver says so with an
 * Extended DNS Error, or the same query answers once validation is switched off.
 */
async function dnssecBroken(name: string, soa: DnsAnswer, opts: AuditOptions): Promise<boolean> {
  const code = Number(/^EDE\((\d+)\)/.exec(soa.ede ?? "")?.[1] ?? -1);
  if (DNSSEC_EDE.has(code)) return true;
  if (!opts.checkingDisabled) return false;
  const plain = await safe(() => opts.checkingDisabled!(name, "SOA"), null);
  return plain?.status === 0;
}

/**
 * Records that must be identical from any resolver. A/AAAA are left out on
 * purpose (CDNs answer by location) and so is SOA (its serial depends on cache age).
 */
function crossCheckTargets(name: string): Array<[string, RRType]> {
  return [
    [name, "NS"],
    [name, "MX"],
    [name, "TXT"],
    [name, "CAA"],
    [name, "DS"],
    [`_dmarc.${name}`, "TXT"],
  ];
}

const RESOLVER_NAMES: Record<string, string> = { cloudflare: "Cloudflare (1.1.1.1)", google: "Google (8.8.8.8)" };

export async function crossCheck(name: string, opts: AuditOptions): Promise<ResolverCheck[]> {
  const ask = opts.secondOpinion;
  if (!ask) return [];
  const checks = await Promise.all(
    crossCheckTargets(name).map(async ([n, type]): Promise<ResolverCheck | null> => {
      try {
        const first = await opts.resolver(n, type);
        const other: ProviderId = first.provider === "cloudflare" ? "google" : "cloudflare";
        const second = await ask(other, n, type);
        // At the domain's own name only the SPF matters among the TXT: verification
        // tokens and rotating values (gov.uk publishes a "#Timestamp") differ between
        // caches without consequence, and used to raise false warnings.
        const relevant = (ans: DnsAnswer) => recordsOf(ans, type).filter((r) => type !== "TXT" || n !== name || isSpf(r.data));
        const a = relevant(first).map((r) => r.data).sort();
        const b = relevant(second).map((r) => r.data).sort();
        return {
          name: n,
          type,
          providers: [first.provider, other],
          answers: [a, b],
          same: JSON.stringify(a) === JSON.stringify(b),
          ad: [first.ad, second.ad],
        };
      } catch {
        return null;
      }
    }),
  );
  return checks.filter((c): c is ResolverCheck => c !== null);
}

const toRow = ({ name, type, ttl, data }: DnsRecord): RecordRow => ({ name, type, ttl, data });


/**
 * Groups CAA records by tag (RFC 8659 section 4): who may issue regular and
 * wildcard certificates, and where violations are reported. Values are deduplicated.
 */
export function summarizeCaa(values: string[]) {
  const by = (tagName: string) => [
    ...new Set(
      values
        .map((v) => new RegExp(`^\\d+\\s+${tagName}\\s+"([^"]*)"`, "i").exec(v)?.[1])
        .filter((v): v is string => v !== undefined)
        .map((v) => v.split(";")[0]!.trim() || "—"),
    ),
  ];
  const issue = by("issue");
  const wild = by("issuewild");
  const iodef = by("iodef");
  const parts = [`issue: ${issue.join(", ") || "—"}`];
  if (wild.length) parts.push(`issuewild: ${wild.join(", ")}`);
  if (iodef.length) parts.push(`iodef: ${iodef.join(", ")}`);
  return { issue, wild, iodef, params: { issuers: issue.join(", ") || "—", detail: parts.join(" · ") } };
}

async function safe<T>(fn: () => Promise<T>, fallback: T): Promise<T> {
  try {
    return await fn();
  } catch {
    return fallback;
  }
}

function section(id: Section["id"], findings: Finding[], records: RecordRow[] = []): Section {
  return { id, findings, records };
}

async function auditDomain(name: string, opts: AuditOptions, id: Identity, onSections?: (sections: Section[]) => void): Promise<Section[]> {
  const { resolver } = opts;
  const q = (type: RRType) => resolver(name, type);
  const [soa, ns, a, aaaa, mxAns, txt, caa, ds] = await Promise.all([
    q("SOA"),
    q("NS"),
    q("A"),
    q("AAAA"),
    q("MX"),
    q("TXT"),
    q("CAA"),
    q("DS"),
  ]);

  if (soa.status === 3) {
    return [section("dns", [finding("dns.nxdomain", "fail", { name })])];
  }
  if (soa.status === 2) {
    const ede = soa.ede ?? "—";
    return [section("dns", [finding((await dnssecBroken(name, soa, opts)) ? "dns.dnssec-broken" : "dns.servfail", "fail", { name, ede })])];
  }

  const sections: Section[] = [];
  // Registration (RDAP) does not depend on anything else: start it now.
  const regP = registrationFindings(name, opts, id);

  // The website, checked in parallel with everything else: the domain itself when
  // it has addresses, otherwise www. when that one does.
  const webP: Promise<Finding[] | null> = opts.web
    ? (async () => {
        const hasAddress = recordsOf(a, "A").length > 0 || recordsOf(aaaa, "AAAA").length > 0;
        const www = hasAddress || name.startsWith("www.") ? null : await safe(() => resolver(`www.${name}`, "A"), null);
        const host = hasAddress ? name : www && recordsOf(www, "A").length ? `www.${name}` : null;
        return host ? safe(() => checkWeb(host, opts.web!, opts.now ?? new Date(), opts.log), null) : null;
      })()
    : Promise.resolve(null);

  // Mail. A lookup that failed (SERVFAIL) says nothing about the zone: it is never
  // read as "no records", which would lead to advice such as publishing a null MX.
  const mxFailed = lookupFailed(mxAns);
  const txtFailed = lookupFailed(txt);
  const mx = parseMx(recordsOf(mxAns, "MX"));
  const mailProvider = mxProvider(mx.map((m) => m.host));
  if (mailProvider) id.mailProvider = mailProvider.name;
  else if (mx.length && mx[0]?.host) id.mxHosts = mx.map((m) => m.host);
  if (mx.length === 1 && mx[0]?.host === "") id.noMail = true;
  const txtValues = recordsOf(txt, "TXT").map((r) => r.data);
  const receivesMail = mx.length > 0 && !(mx.length === 1 && mx[0]?.host === "");
  const [spf, dmarc, dkim, extras, mxHosts] = await Promise.all([
    txtFailed
      ? Promise.resolve([finding("spf.lookup-error", "info", { name })])
      : // Unknown MX counts as "may receive mail": no advice that assumes a domain without mail.
        checkSpf(name, txtValues, receivesMail || mxFailed, resolver, mxProvider(mx.map((m) => m.host))),
    checkDmarc(name, resolver),
    checkDkim(name, resolver, [...new Set([...(opts.dkimSelectors ?? []), ...COMMON_SELECTORS])]),
    receivesMail
      ? checkMailExtras(name, resolver, mx.map((m) => m.host)).then(async (x) => {
          // With a web probe, the MTA-STS policy the browser cannot read is read and judged.
          if (!opts.web) return x;
          const hosts = mx.map((m) => m.host);
          const policyFile = { url: `https://mta-sts.${name}/.well-known/mta-sts.txt`, content: mtaStsPolicy(hosts) };
          const findings = await Promise.all(
            x.findings.map(async (f) => {
              if (f.id !== "mta-sts.unverified") return f;
              const r = await safe(() => checkMtaStsPolicy(name, hosts, opts.web!, opts.log), f);
              return /^mta-sts\.policy-(mx|invalid|error|redirect)$/.test(r.id) ? { ...r, files: [policyFile] } : r;
            }),
          );
          return { ...x, findings };
        })
      : Promise.resolve({ findings: [], records: [] }),
    receivesMail ? checkMxHosts(mx.map((m) => m.host), resolver) : Promise.resolve([]),
  ]);
  // Mail context: what the domain declares decides which advice is safe.
  const spfRecords = txtValues.filter(isSpf);
  const nullMx = mx.length === 1 && mx[0]?.host === "";
  const spfNoSenders = spfRecords.length === 1 && !spfAuthorisesSenders(spfRecords) && /\s-all\s*$/i.test(spfRecords[0]!);
  const dkimFound = dkim.findings.some((f) => f.id.startsWith("dkim.found"));
  // A failed MX or TXT lookup leaves no records, so it can only end in "unknown".
  const mailUsage: Identity["mailUsage"] =
    nullMx || (spfNoSenders && !receivesMail && !dkimFound) ? "disabled" : receivesMail || spfAuthorisesSenders(spfRecords) || dkimFound ? "active" : "unknown";
  id.mailUsage = mailUsage;
  const dkimFindings =
    mailUsage === "disabled" && !dkimFound ? [finding("dkim.not-applicable", "info")] : dkim.findings;
  // Only a domain that declares it uses no mail (null MX, `v=spf1 -all`) can go
  // straight to reject: with "unknown" usage it may still send, so monitoring comes first.
  const dmarcFindings = dmarc.findings.map((f) =>
    f.id === "dmarc.missing" && mailUsage === "disabled"
      ? withSuggest(finding("dmarc.missing-nomail", "warn", { domain: name }), [{ type: "TXT", name: `_dmarc.${name}`, value: "v=DMARC1; p=reject;" }])
      : f,
  );
  sections.push(
    section(
      "mail",
      [
        ...(mxFailed ? [finding("mx.lookup-error", "info", { name })] : checkMx(mx, { domain: name, spf: spfRecords, hasDmarc: !dmarc.findings.some((f) => f.id === "dmarc.missing") })),
        ...mxHosts,
        ...spf,
        ...dmarcFindings,
        ...dkimFindings,
        ...extras.findings,
      ],
      [
        ...recordsOf(mxAns, "MX").map(toRow),
        ...recordsOf(txt, "TXT").filter((r) => isSpf(r.data)).map(toRow),
        ...dmarc.records,
        ...dkim.records,
        ...extras.records,
      ],
    ),
  );

  // DNS
  const dnsFindings: Finding[] = [];
  let nsHosts = recordsOf(ns, "NS").map((r) => r.data);
  const soaApex = recordsOf(soa, "SOA")[0];
  // A name inside another zone (www., audit.…) has no name servers of its own: the
  // zone's apply (RFC 1034, section 4.2), so those are the ones judged, as with the
  // DMARC and CAA it inherits.
  if (nsHosts.length === 0 && !soaApex) {
    const labels = name.split(".");
    for (let i = 1; i < labels.length - 1 && !nsHosts.length; i++) {
      const zone = labels.slice(i).join(".");
      const parent = await safe(() => resolver(zone, "NS"), null);
      const hosts = parent && !lookupFailed(parent) ? recordsOf(parent, "NS").map((r) => r.data) : [];
      if (hosts.length) {
        nsHosts = hosts;
        dnsFindings.push(finding("dns.ns-parent", "info", { name, zone }));
      }
    }
    if (!nsHosts.length) dnsFindings.push(finding("dns.no-zone", "info", { name }));
  }
  if (nsHosts.length === 1) dnsFindings.push(finding("dns.ns-single", "warn", { ns: nsHosts.join(", ") }));
  else if (nsHosts.length > 1) dnsFindings.push(finding("dns.ns", "ok", { count: nsHosts.length, ns: nsHosts.join(", ") }));
  const nsProvider = dnsProvider(nsHosts);
  if (nsProvider) id.dnsProvider = nsProvider;
  else if (nsHosts.length) id.nsHosts = [...nsHosts].sort();
  if (nsProvider) dnsFindings.push(finding("dns.provider", "info", { provider: nsProvider }));

  const v4 = recordsOf(a, "A").map((r) => r.data);
  const v6 = recordsOf(aaaa, "AAAA").map((r) => r.data);
  if (v4.length === 0 && v6.length === 0) dnsFindings.push(finding("dns.no-address", "info"));
  else {
    dnsFindings.push(finding("dns.address", "ok", { ips: [...v4, ...v6].join(", ") }));
    dnsFindings.push(v6.length ? finding("dns.ipv6", "ok") : finding("dns.no-ipv6", "info"));
  }

  // CAA is inherited from the closest ancestor that has it (RFC 8659, section 3).
  // A lookup that fails is not "no CAA": a CA may refuse to issue (sections 6.1 and 6.3).
  let caaRecords = recordsOf(caa, "CAA");
  let caaOwner = name;
  let caaFailed = lookupFailed(caa) ? name : undefined;
  const labels = name.split(".");
  for (let i = 1; !caaFailed && caaRecords.length === 0 && i < labels.length - 1; i++) {
    caaOwner = labels.slice(i).join(".");
    const parent = await safe(() => resolver(caaOwner, "CAA"), null);
    if (!parent || lookupFailed(parent)) caaFailed = caaOwner;
    else caaRecords = recordsOf(parent, "CAA");
  }
  if (caaFailed) {
    caaRecords = [];
    dnsFindings.push(finding("dns.caa-lookup-error", "warn", { name: caaFailed }));
  } else if (caaRecords.length) {
    const caa = summarizeCaa(caaRecords.map((r) => r.data));
    // Only issue restricts regular names: iodef, contactemail or issuewild alone leave
    // every authority free to issue for the domain (RFC 8659, sections 3 and 4.3).
    dnsFindings.push(caa.issue.length ? finding("dns.caa", "ok", caa.params) : finding("dns.caa-no-issue", "warn", caa.params));
    if (caaOwner !== name) dnsFindings.push(finding("dns.caa-inherited", "info", { domain: caaOwner }));
  } else {
    // Without knowing which CAs sign the domain and its subdomains, a copy-paste CAA
    // could block renewals. Cloudflare adds its own CAs, but not those of subdomains
    // served elsewhere (AWS, Google…), so nothing is proposed here; Certificate
    // Transparency fills it in below when it answers.
    dnsFindings.push(finding(nsProvider === "Cloudflare" ? "dns.caa-missing-cloudflare" : "dns.caa-missing", "warn", { domain: name }));
  }

  // Attack surface from Certificate Transparency, while the rest goes on.
  // Third-party intelligence (Shodan InternetDB, AlienVault OTX), while the rest goes on.
  const intelP = checkIntel({ domain: name, ips: [...recordsOf(a, "A"), ...recordsOf(aaaa, "AAAA")].map((r) => r.data) }, opts.fetch, opts.log);
  const surfaceP = checkSurface(
    name,
    resolver,
    caaRecords.map((r) => r.data),
    { fetch: opts.fetch, log: opts.log, now: opts.now },
  );

  const hasDs = recordsOf(ds, "DS").length > 0;
  const [wildcard, dane, nsNets] = await Promise.all([
    checkWildcard(name, resolver),
    receivesMail ? checkDane(mx.map((m) => m.host), resolver, mxAns.ad) : Promise.resolve({ findings: [], records: [] }),
    nsNetworks(nsHosts, resolver, opts),
  ]);
  if (soa.ad) dnsFindings.push(finding("dns.dnssec", "ok"));
  else if (hasDs) dnsFindings.push(finding("dns.dnssec-unvalidated", "fail"));
  else dnsFindings.push(finding(nsProvider === "Cloudflare" ? "dns.dnssec-off-cloudflare" : "dns.dnssec-off", "warn"));
  // DANE belongs with the mail findings.
  const mailSection = sections.find((s) => s.id === "mail");
  mailSection?.findings.push(...dane.findings);
  mailSection?.records.push(...dane.records);
  if (hasDs) dnsFindings.push(...checkDnssecAlgorithms(recordsOf(ds, "DS").map((r) => r.data)));
  dnsFindings.push(...checkSoa(soaApex?.data), ...nsNets, ...wildcard.findings);

  // Hosting of the first address
  const firstIp = v4[0] ?? v6[0];
  if (firstIp) {
    const [asn, geo] = await Promise.all([
      safe(() => lookupAsn(firstIp, opts.fetch, undefined, opts.log), null),
      safe(() => lookupGeo(firstIp, opts.fetch, undefined, opts.log), null),
    ]);
    if (geo) id.location = geo.country ?? "multi";
    if (asn?.holder) {
      // A CDN's addresses only prove who serves the traffic, not where the site lives.
      const cdn = cdnOf(asn.asn);
      if (cdn) id.cdn = cdn;
      dnsFindings.push(finding(cdn ? "dns.cdn" : "dns.hosting", "info", { ip: firstIp, asn: asn.asn ?? "?", holder: asn.holder, cdn: cdn ?? "" }));
      Object.assign(id, { hostingIp: firstIp, hostingAsn: asn.asn, hostingHolder: asn.holder });
    }
  }

  // The website under www, which often lives somewhere else (CDN, hosting, SaaS).
  let wwwRows: DnsRecord[] = [];
  if (!name.startsWith("www.")) {
    const www = await safe(() => resolver(`www.${name}`, "A"), null);
    wwwRows = www?.answers ?? [];
    const target = www ? (recordsOf(www, "CNAME").at(-1)?.data ?? recordsOf(www, "A")[0]?.data) : undefined;
    const wwwIp = www ? recordsOf(www, "A")[0]?.data : undefined;
    if (target) {
      const asn = wwwIp ? await safe(() => lookupAsn(wwwIp, opts.fetch, undefined, opts.log), null) : null;
      dnsFindings.push(finding("web.www", "info", { host: `www.${name}`, target, holder: asn?.holder ?? "?", asn: asn?.asn ?? "?" }));
    } else dnsFindings.push(finding("web.no-www", "info", { host: `www.${name}` }));
  }

  // Third parties: verification tokens and the services SPF lets send mail.
  const txtAll = recordsOf(txt, "TXT").map((r) => r.data);
  const verifications = verificationsOf(txtAll);
  const senders = sendersOf(txtAll.find(isSpf));
  if (verifications.length) dnsFindings.push(finding("int.verifications", "info", { count: verifications.length, list: verifications.map((v) => v.service).join(", ") }));
  if (senders.length) dnsFindings.push(finding("int.senders", "info", { count: senders.length, list: senders.map((v) => v.service).join(", ") }));
  if (!verifications.length && !senders.length) dnsFindings.push(finding("int.none", "info"));

  // Everything but Certificate Transparency is usually ready in a second or two;
  // crt.sh may take twenty. With `onPartial`, the report is delivered first without
  // it (the surface marked as "being checked") and again when it arrives.
  const assemble = async (surface: SurfaceResult, partial = false): Promise<Section[]> => {
    const dnsF = [...dnsFindings];
    const secs = sections.map((sec) => ({ ...sec, findings: [...sec.findings] }));
    // The first report does not wait for Shodan and OTX either: they come with the full one.
    const intelReady = partial ? await Promise.race([intelP, Promise.resolve(null)]) : await intelP;
    // Behind a CDN, Shodan describes the provider's shared edge (rtve.es on Fastly showed
    // 405 CVEs): say whose infrastructure it is instead of letting it read as the domain's.
    // The network of each address is checked, not assumed from the first one.
    const intel = await Promise.all(
      (intelReady ?? [finding("intel.pending", "info")]).map(async (f) => {
        if (f.id !== "intel.shodan") return f;
        const ip = String(f.params?.ip);
        const cdn = cdnOf((await safe(() => lookupAsn(ip, opts.fetch, undefined, opts.log), null))?.asn);
        return cdn ? finding("intel.shodan-cdn", "info", { ...f.params, cdn }) : f;
      }),
    );
    dnsF.push(...surface.findings, ...intel);
    // A CAA proposal built from the authorities that issue the domain's certificates
    // today (CT), so it does not block renewals. Without CT data the original advice
    // stays: on Cloudflare any CAA is safe because Cloudflare adds its own CAs.
    const caaAt = dnsF.findIndex((f) => f.id === "dns.caa-missing" || f.id === "dns.caa-missing-cloudflare");
    if (caaAt >= 0) {
      const f = dnsF[caaAt]!;
      dnsF[caaAt] = surface.caaIds?.length
        ? withSuggest(finding("dns.caa-missing-ct", f.status, { ...f.params, domain: name, cas: surface.caaIds.join(", "), cloudflare: f.id.endsWith("cloudflare") ? "yes" : "" }), [
            ...surface.caaIds.map((ca) => ({ type: "CAA", name, value: `0 issue "${ca}"` })),
            { type: "CAA", name, value: '0 iodef "mailto:{mailbox}"', input: "mailbox" as const, optional: true },
          ])
        : f;
    }

    const rows = (ans: DnsAnswer, type: RRType) => recordsOf(ans, type).map(toRow);
    secs.push(
      section("dns", dnsF, [
        ...rows(soa, "SOA"),
        ...rows(ns, "NS"),
        ...a.answers.filter((r) => r.type === "CNAME").map(toRow),
        ...rows(a, "A"),
        ...rows(aaaa, "AAAA"),
        ...caaRecords.map(toRow),
        ...rows(ds, "DS"),
        ...rows(txt, "TXT").filter((r) => !isSpf(r.data)),
        ...wwwRows.map(toRow),
        ...wildcard.records,
        ...surface.records,
      ]),
    );

    const web = await webP;
    if (web?.length) secs.push(section("web", web));

    // Registration
    secs.push(section("registration", await regP));

    // A name that is an alias (CNAME) can hold no other record (RFC 1034, section 3.6.2;
    // RFC 2181, section 10.1): what the queries returned belongs to the target, and a
    // record suggested at the name could not be published. Say so and drop those.
    const alias = [a, aaaa, mxAns, txt].flatMap((ans) => recordsOf(ans, "CNAME")).find((r) => r.name === name);
    if (alias) {
      const target = recordsOf(a, "CNAME").at(-1)?.data ?? alias.data;
      for (const sec of secs) {
        sec.findings = sec.findings.map((f) => {
          if (!f.suggest?.some((sg) => sg.name === name)) return f;
          const kept: Finding = { ...f, suggest: f.suggest.filter((sg) => sg.name !== name) };
          if (!kept.suggest?.length) delete kept.suggest;
          return kept;
        });
      }
      secs.find((sec) => sec.id === "dns")?.findings.unshift(finding("dns.alias", "info", { name, target }));
    }
    return secs;
  };
  if (onSections) {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const quick = await Promise.race([surfaceP, new Promise<null>((r) => (timer = setTimeout(() => r(null), opts.partialAfterMs ?? PARTIAL_AFTER_MS)))]);
    clearTimeout(timer);
    if (quick) return assemble(quick);
    onSections(await assemble({ findings: [finding("ct.pending", "info")], records: [] }, true));
  }
  return assemble(await surfaceP);
}

/** Networks of reverse proxies and CDNs: traffic goes through them, the origin stays hidden. */
const CDN_ASNS: Record<number, string> = {
  13335: "Cloudflare",
  209242: "Cloudflare",
  54113: "Fastly",
  20940: "Akamai",
  16625: "Akamai",
  19551: "Imperva",
};
const cdnOf = (asn?: number) => (asn ? CDN_ASNS[asn] : undefined);

/**
 * Networks (AS) of the name servers. All of them in one network is common and
 * fine with anycast providers, so it is reported as information, not a fault.
 */
async function nsNetworks(nsHosts: string[], resolver: Resolver, opts: AuditOptions): Promise<Finding[]> {
  const hosts = nsHosts.slice(0, 4);
  if (hosts.length < 2) return [];
  const ips = (await Promise.all(hosts.map((h) => safe(() => resolver(h, "A"), null)))).map((a) => (a ? recordsOf(a, "A")[0]?.data : undefined)).filter((ip): ip is string => Boolean(ip));
  const asns = await Promise.all([...new Set(ips)].map((ip) => safe(() => lookupAsn(ip, opts.fetch, undefined, opts.log), null)));
  const nets = [...new Set(asns.filter((a) => a?.asn).map((a) => `AS${a!.asn} ${a!.holder ?? ""}`.trim()))];
  if (!nets.length) return [];
  return [finding(nets.length > 1 ? "dns.ns-networks" : "dns.ns-one-network", "info", { networks: nets.join(", "), count: nets.length })];
}

/** Age under which a domain counts as newly registered. */
const RECENT_DAYS = 30;

async function registrationFindings(name: string, opts: AuditOptions, id: Identity): Promise<Finding[]> {
  let reg;
  try {
    reg = await lookupDomain(name, opts.fetch, undefined, opts.log);
  } catch {
    return [finding("reg.error", "info")];
  }
  if (!reg) return [finding("reg.unavailable", "info", { tld: name.split(".").pop() ?? "" })];

  Object.assign(id, {
    registrar: reg.registrar,
    created: reg.created?.slice(0, 10),
    registeredDomain: reg.domain,
    holder: reg.registrant,
    holderRedacted: reg.registrantRedacted,
  });
  const out: Finding[] = [];
  if (reg.domain !== name) out.push(finding("reg.parent", "info", { domain: reg.domain }));
  if (reg.registrar) out.push(finding("reg.registrar", "info", { registrar: reg.registrar }));
  if (reg.created) {
    const date = reg.created.slice(0, 10);
    const age = Math.floor(((opts.now ?? new Date()).getTime() - Date.parse(reg.created)) / 86_400_000);
    // Newly registered domains are a known spam signal: worth seeing, not a fault.
    out.push(age >= 0 && age < RECENT_DAYS ? finding("reg.recent", "info", { date, days: age }) : finding("reg.created", "info", { date }));
  }
  if (!reg.expires) out.push(finding("reg.expiry-unknown", "info"));
  if (reg.expires) {
    const days = Math.floor((Date.parse(reg.expires) - (opts.now ?? new Date()).getTime()) / 86_400_000);
    const date = reg.expires.slice(0, 10);
    if (days < 0) out.push(finding("reg.expired", "fail", { date }));
    else if (days < 30) out.push(finding("reg.expires-soon", "warn", { date, days }));
    else out.push(finding("reg.expires", "ok", { date, days }));
  }
  out.push(...lockFindings(reg.status, name));
  return out;
}

/**
 * Registry statuses, read in their EPP form (clientTransferProhibited, RFC 5731,
 * section 2.3) or their RDAP form ("client transfer prohibited", RFC 8056, section 2;
 * RFC 9083, section 10.2.2), which some registries use without the client/server prefix.
 */
export function lockFindings(status: string[], name: string): Finding[] {
  const norm = new Map(status.map((s) => [s.toLowerCase().replace(/[\s_-]/g, ""), s]));
  const found = (...keys: string[]) => keys.filter((k) => norm.has(k)).map((k) => norm.get(k)!);
  const out: Finding[] = [];
  // The domain is on its way out, or not published in the DNS at all (RFC 3915, section 3.1; RFC 5731, section 2.3).
  const redemption = found("redemptionperiod", "pendingrestore");
  if (redemption.length) out.push(finding("reg.redemption", "fail", { status: redemption.join(", ") }));
  const deleting = found("pendingdelete");
  if (deleting.length && !redemption.length) out.push(finding("reg.pending-delete", "fail", { status: deleting.join(", ") }));
  const hold = found("clienthold", "serverhold");
  if (hold.length) out.push(finding("reg.hold", "fail", { status: hold.join(", ") }));

  // A registry lock blocks changes at the registry itself: all three server
  // statuses at once, or the generic "locked" of registries such as SIDN (.nl).
  const serverLock = found("serverupdateprohibited", "serverdeleteprohibited", "servertransferprohibited");
  const registryLock = serverLock.length === 3 ? serverLock : found("locked");
  const transfer = [...new Set([...found("clienttransferprohibited", "servertransferprohibited", "transferprohibited"), ...registryLock])];
  // Many country registries (.nl, .de…) do not use EPP transfer statuses: transfers
  // need an auth code instead. Without any status to read, the lock is unknown.
  const ccTld = /^[a-z]{2}$/.test(name.split(".").pop() ?? "");
  const anyLock = [...norm.keys()].some((s) => /prohibited|locked/.test(s));
  out.push(
    transfer.length
      ? finding("reg.transfer-lock", "ok", { status: transfer.join(", ") })
      : ccTld && !anyLock
        ? finding("reg.lock-unknown", "info", { status: status.join(", ") || "—" })
        : finding("reg.no-transfer-lock", "warn"),
  );
  if (registryLock.length) out.push(finding("reg.registry-lock", "ok", { status: registryLock.join(", ") }));
  return out;
}

async function auditIp(ip: string, version: 4 | 6, opts: AuditOptions, id: Identity): Promise<Section[]> {
  const special = specialRange(ip, version);
  if (special) {
    id.special = special;
    return [section("ip", [finding("ip.special", "info", { ip, range: special })])];
  }

  const ptrName = reverseName(ip, version);
  const [ptrAns, reg, asn, intel, geo] = await Promise.all([
    safe(() => opts.resolver(ptrName, "PTR"), null),
    safe(() => lookupIp(ip, opts.fetch, undefined, opts.log), null),
    safe(() => lookupAsn(ip, opts.fetch, undefined, opts.log), null),
    checkIntel({ ips: [ip] }, opts.fetch, opts.log),
    safe(() => lookupGeo(ip, opts.fetch, undefined, opts.log), null),
  ]);

  const out: Finding[] = [];
  const records: RecordRow[] = [];
  const ptrs = ptrAns ? recordsOf(ptrAns, "PTR") : [];
  records.push(...ptrs.map(toRow));
  if (ptrs.length === 0) out.push(finding("ip.no-ptr", "warn"));
  else {
    const host = ptrs[0]?.data ?? "";
    out.push(finding("ip.ptr", "ok", { host }));
    const forward = await safe(() => opts.resolver(host, version === 4 ? "A" : "AAAA"), null);
    const addrs = forward ? recordsOf(forward, version === 4 ? "A" : "AAAA").map((r) => (version === 6 ? normalizeIPv6(r.data) : r.data)) : [];
    out.push(
      addrs.includes(ip)
        ? finding("ip.fcrdns", "ok", { host })
        : withSuggest(finding("ip.no-fcrdns", "warn", { host }), [{ type: version === 4 ? "A" : "AAAA", name: host, value: ip }]),
    );
  }

  if (asn?.asn) out.push(finding("ip.asn", "info", { asn: asn.asn, holder: asn.holder ?? "?", prefix: asn.prefix ?? "?" }));
  else out.push(finding("ip.not-announced", "info"));
  // Without registry data the holder is simply unknown: say so instead of leaving a gap.
  if (!reg) out.push(finding("ip.registry-unknown", "info", { ip }));
  if (reg) {
    if (reg.organization) out.push(finding("ip.owner", "info", { owner: reg.organization }));
    if (reg.name || reg.range) out.push(finding("ip.network", "info", { name: reg.name ?? "?", range: reg.range ?? "?" }));
    if (reg.country) out.push(finding("ip.country", "info", { country: reg.country }));
  }
  out.push(...intel);
  Object.assign(id, {
    ptr: ptrs[0]?.data,
    holder: reg?.organization,
    network: reg?.name,
    range: reg?.range,
    country: reg?.country,
    asn: asn?.asn,
    asHolder: asn?.holder,
    prefix: asn?.prefix,
    location: geo ? (geo.country ?? "multi") : undefined,
  });
  return [section("ip", out, records)];
}

function resolverParams(check: ResolverCheck) {
  const [a, b] = check.providers;
  return { a: RESOLVER_NAMES[a] ?? a, b: RESOLVER_NAMES[b] ?? b };
}

export async function audit(target: Target, opts: AuditOptions): Promise<Report> {
  const id: Identity = {};
  // The cross-check with the second resolver does not depend on the rest: start it now.
  const crossP = target.kind === "domain" ? crossCheck(target.name, opts) : Promise.resolve([]);
  const build = async (sections: Section[]): Promise<Report> => {
    // Drop empty fields so the report (and its JSON) only carries what was found.
    const identity = Object.fromEntries(Object.entries(id).filter(([, v]) => v !== undefined && v !== "")) as Identity;
    const report: Report = {
      query: target.kind === "domain" ? target.name : target.ip,
      kind: target.kind,
      generatedAt: (opts.now ?? new Date()).toISOString(),
      ...(Object.keys(identity).length ? { identity } : {}),
      sections,
    };
    const dns = sections.find((s) => s.id === "dns");
    if (target.kind === "domain" && dns && !dns.findings.some((f) => ["dns.nxdomain", "dns.servfail", "dns.dnssec-broken"].includes(f.id))) {
      const checks = await crossP;
      if (checks.length) {
        report.resolverCheck = checks;
        // DNSSEC: both resolvers validate independently. Confirm it with the second
        // one, or warn when they disagree, instead of trusting a single AD bit.
        const ns = checks.find((c) => c.type === "NS");
        const i = dns.findings.findIndex((f) => f.id === "dns.dnssec");
        if (ns && i >= 0) {
          dns.findings[i] = ns.ad[1]
            ? finding("dns.dnssec-both", "ok", resolverParams(ns))
            : finding("dns.dnssec-disagree", "warn", resolverParams(ns));
        }
        const differ = checks.filter((c) => !c.same);
        dns.findings.push(
          differ.length
            ? finding("dns.resolvers-differ", "warn", { items: differ.map((c) => `${c.name} ${c.type}`).join(", "), ...resolverParams(checks[0]!) })
            : finding("dns.resolvers-agree", "ok", { count: checks.length, ...resolverParams(checks[0]!) }),
        );
      }
    }
    return report;
  };
  const onPartial = opts.onPartial;
  const sections =
    target.kind === "domain"
      ? await auditDomain(target.name, opts, id, onPartial && ((secs) => void build(secs).then(onPartial)))
      : await auditIp(target.ip, target.version, opts, id);
  return build(sections);
}
