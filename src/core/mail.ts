/** MX, MTA-STS, TLS-RPT and BIMI checks. */
import { lookupFailed, recordsOf, type DnsRecord, type Resolver } from "./doh";
import { isIPv4 } from "./ip";
import { finding, withSuggest, type Finding, type RecordRow } from "./types";

export interface Mx {
  priority: number;
  host: string;
}

export function parseMx(records: DnsRecord[]): Mx[] {
  return records
    .map((r) => {
      const [prio = "", host = ""] = r.data.split(/\s+/);
      return { priority: Number(prio), host: host.replace(/\.$/, "") };
    })
    .sort((a, b) => a.priority - b.priority);
}

export interface MailProvider {
  name: string;
  /** SPF include published by the provider (checked in DNS, 2026-09). */
  spf?: string;
}

const MX_PROVIDERS: Array<[RegExp, MailProvider]> = [
  [/(^|\.)google\.com$|(^|\.)googlemail\.com$/, { name: "Google (Gmail / Workspace)", spf: "_spf.google.com" }],
  [/\.mail\.protection\.outlook\.com$/, { name: "Microsoft 365", spf: "spf.protection.outlook.com" }],
  // MX with DNSSEC and DANE that Microsoft 365 hands out since 2024 (e.g. sidn-nl.v-v1.mx.microsoft).
  [/\.mx\.microsoft$/, { name: "Microsoft 365", spf: "spf.protection.outlook.com" }],
  [/\.mx\.cloudflare\.net$/, { name: "Cloudflare Email Routing", spf: "_spf.mx.cloudflare.net" }],
  [/\.zoho\.eu$/, { name: "Zoho Mail", spf: "zohomail.eu" }],
  [/\.zoho\.com$/, { name: "Zoho Mail", spf: "zohomail.com" }],
  [/\.zoho\.in$/, { name: "Zoho Mail", spf: "zohomail.in" }],
  [/\.protonmail\.ch$/, { name: "Proton Mail", spf: "_spf.protonmail.ch" }],
  [/\.messagingengine\.com$/, { name: "Fastmail", spf: "spf.messagingengine.com" }],
  [/\.ovh\.net$/, { name: "OVHcloud", spf: "mx.ovh.com" }],
  [/\.ionos\.(es|de)$|\.kundenserver\.de$/, { name: "IONOS", spf: "_spf-eu.ionos.com" }],
  // IONOS in other countries: which include applies could not be confirmed, so none is proposed.
  [/\.ionos\.[a-z.]+$/, { name: "IONOS" }],
  [/\.secureserver\.net$/, { name: "GoDaddy", spf: "secureserver.net" }],
  [/\.icloud\.com$/, { name: "iCloud", spf: "icloud.com" }],
  [/\.yandex\.(net|ru)$/, { name: "Yandex", spf: "_spf.yandex.net" }],
  [/\.mimecast\.com$/, { name: "Mimecast" }],
  [/\.pphosted\.com$/, { name: "Proofpoint" }],
  // Only Amazon's inbound mail servers: any EC2 host also ends in amazonaws.com.
  [/^inbound-smtp\.[a-z0-9-]+\.amazonaws\.com$/, { name: "Amazon SES / WorkMail", spf: "amazonses.com" }],
];

export function mxProvider(hosts: string[]): MailProvider | null {
  for (const host of hosts) {
    for (const [re, provider] of MX_PROVIDERS) if (re.test(host)) return provider;
  }
  return null;
}

/** Records that tell the world a domain neither sends nor receives mail. */
export function noMailRecords(domain: string, hasSpf: boolean, hasDmarc: boolean) {
  return [
    { type: "MX", name: domain, value: "0 ." },
    ...(hasSpf ? [] : [{ type: "TXT", name: domain, value: "v=spf1 -all" }]),
    ...(hasDmarc ? [] : [{ type: "TXT", name: `_dmarc.${domain}`, value: "v=DMARC1; p=reject;" }]),
  ];
}

export interface MxContext {
  domain: string;
  spf: string[];
  hasDmarc: boolean;
}

/** True if an SPF record authorises at least one sender (anything besides `all`). */
export function spfAuthorisesSenders(spf: string[]): boolean {
  return spf.some((r) => r.trim().split(/\s+/).slice(1).some((t) => !/^[+\-~?]?all$/i.test(t)));
}

export function checkMx(mx: Mx[], ctx?: MxContext): Finding[] {
  if (mx.length === 0) {
    const none = finding("mx.none", "info");
    // Only suggest the "no mail" records if the domain does not send mail either.
    if (!ctx || spfAuthorisesSenders(ctx.spf)) return [none];
    return [withSuggest(none, noMailRecords(ctx.domain, ctx.spf.length > 0, ctx.hasDmarc))];
  }
  if (mx.length === 1 && mx[0]?.host === "") return [finding("mx.null", "ok")];
  // A null MX must be the only MX (RFC 7505, section 3): mixed with others, senders get contradictory instructions.
  if (mx.some((m) => m.host === "")) return [finding("mx.null-mixed", "fail", { hosts: mx.map((m) => `${m.priority} ${m.host || "."}`).join(", ") })];
  const out: Finding[] = [finding("mx.found", "ok", { count: mx.length, hosts: mx.map((m) => `${m.priority} ${m.host}`).join(", ") })];
  const bad = mx.filter((m) => isIPv4(m.host) || m.host.includes(":"));
  if (bad.length) out.push(finding("mx.ip-literal", "fail", { hosts: bad.map((m) => m.host).join(", ") }));
  const provider = mxProvider(mx.map((m) => m.host));
  if (provider) out.push(finding("mx.provider", "info", { provider: provider.name }));
  return out;
}

/** Checked per audit: more MX than this is unusual and each costs two queries. */
const MAX_MX_CHECKED = 10;

/**
 * Each MX target must be a host name with addresses, not an alias (RFC 2181,
 * section 10.3; RFC 5321, section 5.1). A target that does not resolve loses the
 * mail sent to it; a lookup that fails proves nothing and is left out.
 */
export async function checkMxHosts(hosts: string[], resolver: Resolver): Promise<Finding[]> {
  const unresolvable: string[] = [];
  const aliases: string[] = [];
  await Promise.all(
    hosts
      .filter((h) => h && !isIPv4(h) && !h.includes(":"))
      .slice(0, MAX_MX_CHECKED)
      .map(async (host) => {
        try {
          const [a, aaaa] = await Promise.all([resolver(host, "A"), resolver(host, "AAAA")]);
          if (lookupFailed(a) && lookupFailed(aaaa)) return;
          const alias = recordsOf(a, "CNAME").find((r) => r.name === host) ?? recordsOf(aaaa, "CNAME").find((r) => r.name === host);
          if (alias) aliases.push(`${host} → ${recordsOf(a, "CNAME").at(-1)?.data ?? alias.data}`);
          if (recordsOf(a, "A").length + recordsOf(aaaa, "AAAA").length === 0) unresolvable.push(host);
        } catch {
          /* no answer at all: nothing to say */
        }
      }),
  );
  const out: Finding[] = [];
  if (unresolvable.length) out.push(finding("mx.unresolvable", "fail", { hosts: unresolvable.sort().join(", ") }));
  if (aliases.length) out.push(finding("mx.cname", "warn", { hosts: aliases.sort().join(", ") }));
  return out;
}

async function txtWith(name: string, prefix: RegExp, resolver: Resolver): Promise<DnsRecord[]> {
  try {
    return recordsOf(await resolver(name, "TXT"), "TXT").filter((r) => prefix.test(r.data));
  } catch {
    return [];
  }
}

const toRow = ({ name, type, ttl, data }: DnsRecord): RecordRow => ({ name, type, ttl, data });

/** Optional hardening records for domains that receive mail. */
/** MTA-STS policy (RFC 8461, section 3.2) listing the domain's real MX hosts, in testing mode. */
export function mtaStsPolicy(mxHosts: string[]): string {
  return ["version: STSv1", "mode: testing", ...mxHosts.map((h) => `mx: ${h}`), "max_age: 86400"].join("\r\n") + "\r\n";
}

async function resolves(name: string, resolver: Resolver): Promise<boolean> {
  try {
    const [a, aaaa] = await Promise.all([resolver(name, "A"), resolver(name, "AAAA")]);
    return recordsOf(a, "A").length + recordsOf(aaaa, "AAAA").length > 0;
  } catch {
    return false;
  }
}

/** Tag value of a `k=v; k=v` record, case-insensitive. */
function tag(record: string, key: string): string | undefined {
  const m = new RegExp(`(?:^|;)\\s*${key}\\s*=\\s*([^;]*)`, "i").exec(record);
  return m?.[1]?.trim();
}

export async function checkMailExtras(
  domain: string,
  resolver: Resolver,
  mxHosts: string[] = [],
): Promise<{ findings: Finding[]; records: RecordRow[] }> {
  const policyHost = `mta-sts.${domain}`;
  const [sts, tlsrpt, bimi, hostExists] = await Promise.all([
    txtWith(`_mta-sts.${domain}`, /^v=STSv1/i, resolver),
    // Only records beginning with "v=TLSRPTv1;" count, and there must be exactly one (RFC 8460, section 3).
    txtWith(`_smtp._tls.${domain}`, /^v=TLSRPTv1;/, resolver),
    txtWith(`default._bimi.${domain}`, /^v=BIMI1/i, resolver),
    resolves(policyHost, resolver),
  ]);
  const policyFile = { url: `https://${policyHost}/.well-known/mta-sts.txt`, content: mtaStsPolicy(mxHosts) };
  const findings: Finding[] = [];

  // MTA-STS needs both the TXT and the HTTPS policy. The policy cannot be read from a
  // browser (CORS), but whether its host exists can: without it the TXT does nothing.
  // With the host present nothing is proven (mode testing protects nothing, and a
  // wildcard makes any name resolve), so the result is "not verified", never "ok".
  if (!sts.length) {
    findings.push({
      ...withSuggest(finding("mta-sts.missing", "info", { domain }), [
        { type: "TXT", name: `_mta-sts.${domain}`, value: `v=STSv1; id=${new Date().toISOString().slice(0, 10).replace(/-/g, "")}01` },
      ]),
      files: [policyFile],
    });
  } else {
    const record = sts[0]?.data ?? "";
    const id = tag(record, "id");
    if (sts.length > 1 || !id || !/^[a-z0-9]{1,32}$/i.test(id)) findings.push(finding("mta-sts.invalid", "warn", { record }));
    else if (!hostExists) findings.push({ ...finding("mta-sts.no-host", "warn", { host: policyHost }), files: [policyFile] });
    else findings.push(finding("mta-sts.unverified", "info", { host: policyHost }));
  }

  if (!tlsrpt.length) {
    findings.push(
      withSuggest(finding("tls-rpt.missing", "info"), [
        { type: "TXT", name: `_smtp._tls.${domain}`, value: "v=TLSRPTv1; rua=mailto:{mailbox}", input: "mailbox" },
      ]),
    );
  } else {
    const rua = tag(tlsrpt[0]?.data ?? "", "rua");
    const valid = tlsrpt.length === 1 && rua && /^(mailto:|https:)/i.test(rua);
    findings.push(valid ? finding("tls-rpt.found", "ok", { rua }) : finding("tls-rpt.invalid", "warn", { record: tlsrpt.map((r) => r.data).join(" | ") }));
  }

  if (!bimi.length) findings.push(finding("bimi.missing", "info"));
  else {
    const record = bimi[0]?.data ?? "";
    findings.push(finding(tag(record, "a") ? "bimi.found" : "bimi.found-no-vmc", "ok", { record }));
  }

  return { findings, records: [...sts, ...tlsrpt, ...bimi].map(toRow) };
}
