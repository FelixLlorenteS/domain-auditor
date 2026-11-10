/** Plain-language verdict per area, derived from the findings. */
import type { Finding, Report } from "./types";

export type Level = "good" | "partial" | "bad" | "unknown";

export interface Verdict {
  area: "spoofing" | "dns" | "web" | "registration" | "sending";
  level: Level;
  /** Message id in i18n: `verdict.<area>.<reason>`. */
  reason: string;
}

const has = (findings: Finding[], ...ids: string[]) => findings.some((f) => ids.includes(f.id));

function spoofing(mail: Finding[]): Verdict {
  const v = (level: Level, reason: string): Verdict => ({ area: "spoofing", level, reason });
  // Without an answer from _dmarc nothing can be said either way.
  if (has(mail, "dmarc.lookup-error")) return v("unknown", "unverified");
  // A record receivers ignore (`v=dmarc1`) is no record, unless a parent's applies.
  if (has(mail, "dmarc.missing", "dmarc.multiple", "dmarc.invalid-policy") || (has(mail, "dmarc.bad-version") && !has(mail, "dmarc.found"))) return v("bad", "no-dmarc");
  if (has(mail, "spf.all-pass")) return v("bad", "spf-open");
  if (has(mail, "dmarc.p-none", "dmarc.p-missing", "dmarc.testing")) return v("bad", "monitor-only");
  const spfBroken = has(mail, "spf.missing", "spf.missing-provider", "spf.multiple", "spf.syntax", "spf.too-many-lookups", "spf.include-missing", "spf.loop");
  const noDkim = !has(mail, "dkim.found", "dkim.rsa-1024", "dkim.found-delegated", "dkim.rsa-1024-delegated");
  if (spfBroken && noDkim) return v("bad", "no-auth");
  if (spfBroken || has(mail, "dkim.weak", "dkim.weak-delegated", "dmarc.sp-none")) return v("partial", "gaps");
  if (has(mail, "dmarc.p-quarantine")) return v("partial", "quarantine");
  return v("good", "protected");
}

function fromStatuses(area: Verdict["area"], findings: Finding[]): Verdict {
  if (findings.some((f) => f.status === "fail")) return { area, level: "bad", reason: "problems" };
  if (findings.some((f) => f.status === "warn")) return { area, level: "partial", reason: "improvable" };
  return { area, level: "good", reason: "fine" };
}

export function verdicts(report: Report): Verdict[] {
  const section = (id: string) => report.sections.find((s) => s.id === id)?.findings ?? [];
  if (report.kind === "ip") {
    const ip = section("ip");
    if (has(ip, "ip.special")) return [];
    const level: Level = has(ip, "ip.fcrdns") ? "good" : has(ip, "ip.ptr") ? "partial" : "bad";
    return [{ area: "sending", level, reason: level === "good" ? "fine" : level === "partial" ? "no-fcrdns" : "no-ptr" }];
  }
  const dns = section("dns");
  if (has(dns, "dns.nxdomain", "dns.servfail", "dns.dnssec-broken")) return [{ area: "dns", level: "bad", reason: "broken" }];

  const out: Verdict[] = [];
  const mail = section("mail");
  // A domain with no mail at all is protected by the null-MX trio, not by DMARC reports.
  if (has(mail, "mx.none") && !has(mail, "spf.found")) out.push(has(mail, "dmarc.p-reject") ? { area: "spoofing", level: "partial", reason: "no-mail-reject" } : { area: "spoofing", level: "bad", reason: "no-mail" });
  else out.push(spoofing(mail));
  out.push(fromStatuses("dns", dns));
  // Only the desktop app checks the website; a domain without one has no verdict here.
  const web = section("web");
  if (web.length && !has(web, "https.no-web")) out.push(fromStatuses("web", web));
  const reg = section("registration");
  out.push(has(reg, "reg.unavailable", "reg.error") ? { area: "registration", level: "unknown", reason: "unknown" } : fromStatuses("registration", reg));
  return out;
}
