/**
 * Checks of the website itself, only possible outside a browser: a web page
 * cannot read another site's headers, its TLS handshake or a file served without
 * CORS. The desktop app provides a `WebProbe` that makes these connections from
 * the user's computer, like a browser visiting the site; the web version has no
 * probe and these checks are simply not run.
 *
 * - HTTPS: HTTP redirects to HTTPS, and HSTS (RFC 6797).
 * - TLS: certificate valid for the name, days to expiry, and whether TLS 1.0 and
 *   1.1 are still accepted (deprecated by RFC 8996).
 * - Security headers of the home page (clickjacking, MIME sniffing, CSP…).
 * - security.txt (RFC 9116).
 * - The MTA-STS policy file, which the web version can only announce as
 *   "not verified" (RFC 8461).
 */
import type { RawLog } from "./raw";
import { finding, type Finding } from "./types";

export interface HttpResult {
  url: string;
  status: number;
  /** Header names in lower case; repeated headers joined with ", ". */
  headers: Record<string, string>;
  /** First bytes of the body (the probe caps it). */
  body: string;
}

export interface TlsResult {
  protocol: string | null;
  cipher?: string;
  /** The chain is trusted and valid for the name. */
  authorized: boolean;
  /** Why it is not (e.g. CERT_HAS_EXPIRED, ERR_TLS_CERT_ALTNAME_INVALID). */
  authError?: string;
  cert?: { subject: string; issuer: string; validFrom: string; validTo: string; san: string[] };
}

export type TlsVersion = "TLSv1" | "TLSv1.1" | "TLSv1.2" | "TLSv1.3";

export interface WebProbe {
  /** One GET request, without following redirects. HTTPS certificates are validated. */
  request(url: string): Promise<HttpResult>;
  /** A TLS handshake on port 443; with `version`, only that version is offered. */
  tls(host: string, version?: TlsVersion): Promise<TlsResult>;
}

/** Error raised by a probe when the connection itself failed (refused, timeout, bad certificate…). */
export const errorCode = (err: unknown): string => {
  const e = err as { code?: string; message?: string };
  return e?.code || String(e?.message ?? err).replace(/^Error( invoking remote method '[^']+')?: (Error: )?/, "") || "error";
};

const CERT_ERRORS = /CERT|SELF_SIGNED|UNABLE_TO_(GET|VERIFY)|ALTNAME|DEPTH_ZERO|UNABLE_TO_GET_ISSUER/i;

function logged(log: RawLog | undefined, label: string, url: string) {
  const at = new Date().toISOString();
  const started = Date.now();
  return {
    ok(status: number, body: string, finalUrl?: string) {
      log?.push({ source: "web", label, url, status, ms: Date.now() - started, at, body, ...(finalUrl && finalUrl !== url ? { finalUrl } : {}) });
    },
    fail(error: string) {
      log?.push({ source: "web", label, url, status: null, ms: Date.now() - started, at, error });
    },
  };
}

const headerText = (r: HttpResult) => `HTTP ${r.status}\n${Object.entries(r.headers).map(([k, v]) => `${k}: ${v}`).join("\n")}`;

async function get(probe: WebProbe, url: string, log?: RawLog, withBody = false): Promise<HttpResult> {
  const entry = logged(log, `web GET ${url}`, url);
  try {
    const r = await probe.request(url);
    entry.ok(r.status, withBody ? `${headerText(r)}\n\n${r.body}` : headerText(r));
    return r;
  } catch (err) {
    entry.fail(errorCode(err));
    throw err;
  }
}

const isRedirect = (s: number) => s >= 300 && s < 400;

/** Follows redirects by hand (at most `max`), so every hop is logged and can be judged. */
async function follow(probe: WebProbe, url: string, log?: RawLog, max = 5, withBody = false): Promise<{ hops: HttpResult[]; final: HttpResult }> {
  const hops: HttpResult[] = [];
  let current = url;
  for (let i = 0; i <= max; i++) {
    const r = await get(probe, current, log, withBody);
    hops.push(r);
    const location = r.headers["location"];
    if (!isRedirect(r.status) || !location) return { hops, final: r };
    current = new URL(location, current).toString();
  }
  return { hops, final: hops[hops.length - 1]! };
}

/** `max-age` of a Strict-Transport-Security header (RFC 6797, section 6.1.1), or null if unreadable. */
export function hstsMaxAge(value: string): number | null {
  // Only the first header counts when several are sent (RFC 6797, section 8.1).
  const first = value.split(",")[0] ?? "";
  const m = /(?:^|;)\s*max-age\s*=\s*"?(\d+)"?\s*(?:;|$)/i.exec(first);
  return m ? Number(m[1]) : null;
}

/** One year: what the HSTS preload list requires and the usual recommendation. */
export const HSTS_MIN = 31_536_000;

/** A bot challenge or a refusal: its headers are not the site's real ones. */
export const isBlocked = (r: HttpResult) => [401, 403, 429, 503].includes(r.status) || "cf-mitigated" in r.headers;

function checkHsts(value: string | undefined, host: string, final?: HttpResult): Finding {
  // A site often redirects the bare domain to www and sends HSTS only there: the
  // bare domain, the one people type, stays unprotected (RFC 6797, section 8.1).
  const elsewhere = final && !isBlocked(final) ? final.headers["strict-transport-security"] : undefined;
  if (!value && elsewhere && (hstsMaxAge(elsewhere) ?? 0) > 0) return finding("https.hsts-final-only", "warn", { host, final: new URL(final!.url).host });
  if (!value) return finding("https.no-hsts", "warn", { host });
  const age = hstsMaxAge(value);
  if (age === null) return finding("https.hsts-invalid", "warn", { host, value });
  if (age === 0) return finding("https.hsts-off", "warn", { host });
  const subdomains = /(?:^|;)\s*includesubdomains\s*(?:;|$)/i.test(value.split(",")[0] ?? "");
  const days = Math.round(age / 86_400);
  if (age < HSTS_MIN) return finding("https.hsts-short", "warn", { host, days });
  return finding(subdomains ? "https.hsts" : "https.hsts-host", "ok", { host, days });
}

/** A version number in a Server or X-Powered-By header: "nginx/1.18.0", "PHP/7.4.3". */
const VERSION_LEAK = /\/\s*\d+(\.\d+)+/;

export function checkHeaders(h: Record<string, string>, url: string): Finding[] {
  const out: Finding[] = [];
  const csp = h["content-security-policy"];
  const frameAncestors = csp && /(?:^|;)\s*frame-ancestors\s/i.test(csp);
  const xfo = (h["x-frame-options"] ?? "").trim().toUpperCase();
  out.push(
    frameAncestors || xfo === "DENY" || xfo === "SAMEORIGIN"
      ? finding("hdr.frame", "ok", { via: frameAncestors ? "CSP frame-ancestors" : `X-Frame-Options: ${xfo}` })
      : finding("hdr.no-frame", "warn", { url }),
  );
  out.push((h["x-content-type-options"] ?? "").trim().toLowerCase() === "nosniff" ? finding("hdr.nosniff", "ok") : finding("hdr.no-nosniff", "warn", { url }));
  if (!csp) out.push(finding("hdr.no-csp", "info", { url }));
  else if (/(?:^|;)\s*script-src[^;]*'unsafe-inline'/i.test(csp) || (!/script-src/i.test(csp) && /default-src[^;]*'unsafe-inline'/i.test(csp)))
    out.push(finding("hdr.csp-unsafe", "info", { url }));
  else out.push(finding("hdr.csp", "ok"));
  const referrer = h["referrer-policy"];
  if (referrer && /unsafe-url/i.test(referrer)) out.push(finding("hdr.referrer-unsafe", "warn", { value: referrer }));
  else if (referrer) out.push(finding("hdr.referrer", "ok", { value: referrer }));
  const leaks = ["server", "x-powered-by", "x-aspnet-version"].map((k) => [k, h[k]] as const).filter(([, v]) => v && VERSION_LEAK.test(v));
  if (leaks.length) out.push(finding("hdr.version-leak", "info", { headers: leaks.map(([k, v]) => `${k}: ${v}`).join(" · ") }));
  return out;
}

/** Fields of a security.txt (RFC 9116, section 2.4), lower-case names; signed files are read too. */
export function parseSecurityTxt(text: string): Record<string, string[]> {
  const fields: Record<string, string[]> = {};
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#") || line.startsWith("-----")) continue;
    const m = /^([A-Za-z-]+):\s*(.+)$/.exec(line);
    if (!m) continue;
    const key = m[1]!.toLowerCase();
    (fields[key] ??= []).push(m[2]!.trim());
  }
  return fields;
}

export async function checkSecurityTxt(host: string, probe: WebProbe, now: Date, log?: RawLog): Promise<Finding> {
  const url = `https://${host}/.well-known/security.txt`;
  let res: HttpResult;
  try {
    // Redirects are allowed, but only to HTTPS (RFC 9116, section 3).
    const { hops, final } = await follow(probe, url, log, 3, true);
    res = final;
    if (hops.some((h, i) => i > 0 && !h.url.startsWith("https://"))) return finding("sectxt.missing", "info", { host });
  } catch {
    return finding("sectxt.unavailable", "info", { host });
  }
  // A page that answers everything with HTML (a "soft 404") is not a security.txt.
  const type = res.headers["content-type"] ?? "";
  if (res.status !== 200 || !/^text\/plain/i.test(type)) return finding("sectxt.missing", "info", { host });
  const fields = parseSecurityTxt(res.body);
  const contact = fields["contact"] ?? [];
  const expires = fields["expires"] ?? [];
  if (!contact.length || expires.length !== 1) return finding("sectxt.invalid", "warn", { url, missing: [!contact.length && "Contact", expires.length !== 1 && "Expires"].filter(Boolean).join(", ") });
  const when = new Date(expires[0]!);
  if (Number.isNaN(when.getTime())) return finding("sectxt.invalid", "warn", { url, missing: "Expires" });
  if (when < now) return finding("sectxt.expired", "warn", { url, date: expires[0]!.slice(0, 10) });
  return finding("sectxt.found", "ok", { contact: contact.slice(0, 2).join(", "), date: expires[0]!.slice(0, 10) });
}

/** An MTA-STS policy (RFC 8461, section 3.2), or the reason it is not one. */
export function parseMtaStsPolicy(text: string): { mode: string; mx: string[]; maxAge: number } | { error: string } {
  const fields: Record<string, string[]> = {};
  for (const line of text.split(/\r?\n/)) {
    const m = /^\s*([a-z_]+)\s*:\s*(.*?)\s*$/i.exec(line);
    if (m) (fields[m[1]!.toLowerCase()] ??= []).push(m[2]!);
  }
  if (fields["version"]?.[0] !== "STSv1") return { error: "version" };
  const mode = fields["mode"]?.[0] ?? "";
  if (!["enforce", "testing", "none"].includes(mode)) return { error: "mode" };
  const maxAge = Number(fields["max_age"]?.[0]);
  if (!/^\d{1,10}$/.test(fields["max_age"]?.[0] ?? "") || maxAge > 31_557_600) return { error: "max_age" };
  const mx = fields["mx"] ?? [];
  if (mode !== "none" && !mx.length) return { error: "mx" };
  return { mode, mx, maxAge };
}

/** Whether an MX host matches a policy pattern; `*.` covers exactly one label (RFC 8461, section 4.1). */
export function mxMatches(host: string, pattern: string): boolean {
  const h = host.toLowerCase().replace(/\.$/, "");
  const p = pattern.toLowerCase().replace(/\.$/, "");
  if (p.startsWith("*.")) {
    const rest = p.slice(2);
    return h.endsWith(`.${rest}`) && !h.slice(0, -rest.length - 1).includes(".");
  }
  return h === p;
}

export async function checkMtaStsPolicy(domain: string, mxHosts: string[], probe: WebProbe, log?: RawLog): Promise<Finding> {
  const host = `mta-sts.${domain}`;
  const url = `https://${host}/.well-known/mta-sts.txt`;
  let res: HttpResult;
  try {
    res = await get(probe, url, log, true);
  } catch (err) {
    const code = errorCode(err);
    return finding(CERT_ERRORS.test(code) ? "mta-sts.policy-cert" : "mta-sts.policy-error", "warn", { host, reason: code });
  }
  // Redirects must not be followed (RFC 8461, section 3.3).
  if (res.status !== 200) return finding(isRedirect(res.status) ? "mta-sts.policy-redirect" : "mta-sts.policy-error", "warn", { host, reason: `HTTP ${res.status}` });
  const policy = parseMtaStsPolicy(res.body);
  if ("error" in policy) return finding("mta-sts.policy-invalid", "warn", { url, field: policy.error });
  const uncovered = mxHosts.filter((mx) => mx && !policy.mx.some((p) => mxMatches(mx, p)));
  if (policy.mode !== "none" && uncovered.length) return finding("mta-sts.policy-mx", "warn", { missing: uncovered.join(", "), patterns: policy.mx.join(", ") });
  if (policy.mode === "none") return finding("mta-sts.policy-none", "info", { host });
  if (policy.mode === "testing") return finding("mta-sts.policy-testing", "info", { host, days: Math.round(policy.maxAge / 86_400) });
  return finding("mta-sts.enforce", "ok", { patterns: policy.mx.join(", "), days: Math.round(policy.maxAge / 86_400) });
}

const DAY = 86_400_000;

/**
 * What the server does when it refuses an old version: an alert, or closing the
 * connection. Anything else (timeout, our own library unable to offer it) proves
 * nothing, so it can never read as "refused".
 */
export const REFUSED = /ALERT|ECONNRESET|WRONG_VERSION|UNSUPPORTED_PROTOCOL$|EPIPE|hang up|VERSION_TOO_LOW|NO_SHARED_CIPHER|HANDSHAKE_FAILURE|UNEXPECTED_EOF|ECONNREFUSED/i;

/** One handshake offering only an old version: true accepted, false refused, null unknown. */
async function legacyAccepted(host: string, v: "TLSv1" | "TLSv1.1", probe: WebProbe, log?: RawLog): Promise<boolean | null> {
  const e = logged(log, `web TLS ${host}:443 ${v} only`, `tls://${host}:443?version=${v}`);
  try {
    const r = await probe.tls(host, v);
    e.ok(0, JSON.stringify({ protocol: r.protocol, cipher: r.cipher }));
    return r.protocol === v;
  } catch (err) {
    const code = errorCode(err);
    e.fail(code);
    return REFUSED.test(code) ? false : null;
  }
}

async function checkTls(host: string, probe: WebProbe, now: Date, log?: RawLog): Promise<Finding[]> {
  const entry = logged(log, `web TLS ${host}:443`, `tls://${host}:443`);
  // The normal handshake and the old versions, offered one at a time, all at once.
  const [tls, tls10, tls11] = await Promise.all([
    probe.tls(host).then(
      (r) => (entry.ok(0, JSON.stringify(r, null, 2)), r),
      (err: unknown) => (entry.fail(errorCode(err)), null),
    ),
    legacyAccepted(host, "TLSv1", probe, log),
    legacyAccepted(host, "TLSv1.1", probe, log),
  ]);
  if (!tls) return [finding("tls.unreachable", "info", { host })];
  const out: Finding[] = [];
  const c = tls.cert;
  if (!tls.authorized) {
    const code = tls.authError ?? "?";
    out.push(finding(/EXPIRED/i.test(code) ? "tls.expired" : /ALTNAME|HOSTNAME/i.test(code) ? "tls.wrong-name" : "tls.untrusted", "fail", { host, code, issuer: c?.issuer ?? "?" }));
  } else if (c) {
    const days = Math.floor((new Date(c.validTo).getTime() - now.getTime()) / DAY);
    out.push(
      days < 14
        ? finding("tls.expires-soon", "warn", { host, days, issuer: c.issuer })
        : finding("tls.cert", "ok", { host, days, issuer: c.issuer, protocol: tls.protocol ?? "?" }),
    );
  }
  // A refused handshake is the good answer; anything unclear is never read as one.
  const legacy = [tls10 && "TLS 1.0", tls11 && "TLS 1.1"].filter(Boolean);
  out.push(
    legacy.length
      ? finding("tls.legacy", "warn", { host, versions: legacy.join(", ") })
      : tls10 === null || tls11 === null
        ? finding("tls.legacy-unknown", "info", { host })
        : finding("tls.no-legacy", "ok", { host }),
  );
  if (tls.protocol === "TLSv1.2") out.push(finding("tls.no-13", "info", { host }));
  return out;
}

/**
 * Every web check for a domain. `host` is the name that serves the website (the
 * domain itself, or www. when only that one has addresses).
 */
export async function checkWeb(host: string, probe: WebProbe, now: Date, log?: RawLog): Promise<Finding[]> {
  // Every connection at once: against a distant server each one takes a second or more.
  const [http, https, tlsFindings, securityTxt] = await Promise.all([
    follow(probe, `http://${host}/`, log).catch(() => null),
    follow(probe, `https://${host}/`, log).catch((err: unknown) => errorCode(err)),
    checkTls(host, probe, now, log),
    checkSecurityTxt(host, probe, now, log),
  ]);
  const out: Finding[] = [];
  // 1. Plain HTTP: it should only send the visitor to HTTPS.
  if (http) {
    const { hops, final } = http;
    if (hops.length > 1 && final.url.startsWith("https://")) out.push(finding("https.redirect", "ok", { host, to: final.url }));
    else out.push(finding("https.no-redirect", "warn", { host, status: final.status }));
  }
  // 2. HTTPS, its first answer (HSTS belongs to this host) and the final page (headers).
  if (typeof https === "string") {
    // Our own lookup failed: nothing is known about the site.
    if (/ENOTFOUND|EAI_AGAIN|BLOCKED_PRIVATE_ADDRESS/.test(https)) return [finding("https.unresolved", "info", { host, code: https })];
    if (CERT_ERRORS.test(https)) out.push(finding("https.cert-error", "fail", { host, code: https }));
    else if (!http) return [finding("https.no-web", "info", { host })];
    else out.push(finding("https.unavailable", "fail", { host, code: https }));
  } else {
    const first = https.hops[0]!;
    const final = https.final;
    out.push(checkHsts(first.headers["strict-transport-security"], host, final));
    if (!http) out.push(finding("https.http-closed", "ok", { host }));
    if (isBlocked(final)) out.push(finding("hdr.blocked", "info", { url: final.url, status: final.status }));
    else out.push(...checkHeaders(final.headers, final.url));
  }
  out.push(...tlsFindings, securityTxt);
  return out;
}
