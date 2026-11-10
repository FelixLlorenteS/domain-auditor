/**
 * DKIM (RFC 6376). Selectors cannot be listed through DNS, so this probes the
 * ones used by common mail providers. Not finding one does not mean DKIM is off.
 */
import { lookupFailed, recordsOf, type Resolver } from "./doh";
import { parseTags } from "./dmarc";
import { finding, type Finding, type Params, type RecordRow } from "./types";

export const COMMON_SELECTORS = [
  "default",
  "google", // Google Workspace
  "selector1", // Microsoft 365
  "selector2",
  "k1", // Mailchimp, Brevo
  "k2",
  "s1",
  "s2",
  "dkim",
  "mail",
  "smtp",
  "email",
  "mandrill",
  "mxvault",
  "zoho", // Zoho Mail
  "protonmail", // Proton Mail
  "protonmail2",
  "protonmail3",
  "fm1", // Fastmail
  "fm2",
  "fm3",
  "sig1", // iCloud
  "cf2024-1", // Cloudflare
  "mailjet",
  "sendgrid",
  "smtpapi",
  "amazonses",
  "everlytickey1",
  "20230601", // Gmail
  "hs1", // HubSpot
  "hs2",
  "zendesk1", // Zendesk
  "zendesk2",
  "dkim1",
  "dkim2",
  "key1",
  "key2",
];

/** A selector the user typed: DNS label characters only, lower-case. */
export function cleanSelector(raw: string): string | null {
  const s = raw.trim().toLowerCase().replace(/\._domainkey.*$/, "");
  return /^[a-z0-9](?:[a-z0-9._-]{0,61}[a-z0-9])?$/.test(s) ? s : null;
}

function base64ToBytes(b64: string): Uint8Array | null {
  try {
    const bin = atob(b64.replace(/\s+/g, ""));
    return Uint8Array.from(bin, (c) => c.charCodeAt(0));
  } catch {
    return null;
  }
}

interface Tlv {
  tag: number;
  start: number;
  end: number;
}

function readTlv(b: Uint8Array, offset: number): Tlv | null {
  const tag = b[offset];
  let len = b[offset + 1];
  if (tag === undefined || len === undefined) return null;
  let start = offset + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n < 1 || n > 4) return null;
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + (b[start + i] ?? 0);
    start += n;
  }
  const end = start + len;
  return end <= b.length ? { tag, start, end } : null;
}

/** Size in bits of an RSA public key given as base64 SubjectPublicKeyInfo or RSAPublicKey. */
export function rsaKeyBits(b64: string): number | null {
  const b = base64ToBytes(b64);
  if (!b) return null;
  const outer = readTlv(b, 0);
  if (outer?.tag !== 0x30) return null;
  let inner = readTlv(b, outer.start);
  if (inner?.tag === 0x30) {
    // SubjectPublicKeyInfo: AlgorithmIdentifier, then BIT STRING wrapping RSAPublicKey.
    const bits = readTlv(b, inner.end);
    if (bits?.tag !== 0x03) return null;
    const rsa = readTlv(b, bits.start + 1);
    if (rsa?.tag !== 0x30) return null;
    inner = readTlv(b, rsa.start);
  }
  if (inner?.tag !== 0x02) return null;
  let start = inner.start;
  while (start < inner.end && b[start] === 0) start++;
  if (start >= inner.end) return null;
  const top = b[start] ?? 0;
  return (inner.end - start) * 8 - (Math.clz32(top) - 24);
}

export interface DkimResult {
  findings: Finding[];
  records: RecordRow[];
}

export async function checkDkim(domain: string, resolver: Resolver, selectors = COMMON_SELECTORS): Promise<DkimResult> {
  const results = await Promise.all(
    selectors.map(async (selector) => {
      try {
        const answer = await resolver(`${selector}._domainkey.${domain}`, "TXT");
        const rows = recordsOf(answer, "TXT").filter((r) => /(^|;)\s*(v\s*=\s*DKIM1|p\s*=)/i.test(r.data));
        // A CNAME means the key is published and rotated by another provider.
        const cnames = recordsOf(answer, "CNAME");
        const via = cnames[cnames.length - 1]?.data;
        return { selector, rows, cnames, via };
      } catch {
        return { selector, rows: [], cnames: [], via: undefined };
      }
    }),
  );

  const found = results.filter((r) => r.rows.length > 0);
  const records = found.flatMap((r) => [...r.cnames, ...r.rows].map(({ name, type, ttl, data }) => ({ name, type, ttl, data })));
  if (found.length === 0) return { findings: [await withoutSelector(domain, resolver, selectors.length)], records };

  const out: Finding[] = [];
  for (const { selector, rows, via } of found) {
    const d = via ? "-delegated" : "";
    const base: Params = via ? { selector, via } : { selector };
    const tags = parseTags(rows[0]?.data ?? "");
    const key = tags.get("p") ?? "";
    const alg = (tags.get("k") ?? "rsa").toLowerCase();
    if (!key) {
      out.push(finding("dkim.revoked", "info", base));
      continue;
    }
    // Unknown key types MUST be ignored (RFC 6376, section 3.6.1): the key validates nothing.
    if (alg !== "rsa" && alg !== "ed25519") {
      out.push(finding("dkim.unknown-type", "warn", { ...base, alg }));
      continue;
    }
    // A key limited to SHA-1: rsa-sha1 MUST NOT be used for verifying (RFC 8301, section 3.1).
    const hashes = tags.get("h")?.toLowerCase().split(":").map((h) => h.trim());
    if (hashes && !hashes.includes("sha256")) {
      out.push(finding("dkim.sha1", "fail", { ...base, h: hashes.join(":") }));
      continue;
    }
    if (alg === "rsa") {
      const bits = rsaKeyBits(key);
      if (bits === null) out.push(finding("dkim.bad-key", "fail", base));
      else if (bits < 1024) out.push(finding(`dkim.weak${d}`, "fail", { ...base, bits }));
      else if (bits < 2048) out.push(finding(`dkim.rsa-1024${d}`, "warn", { ...base, bits }));
      else out.push(finding(`dkim.found${d}`, "ok", { ...base, alg: "RSA", bits }));
    } else {
      out.push(finding(`dkim.found${d}`, "ok", { ...base, alg: "Ed25519", bits: 256 }));
    }
    if (/(^|:)y(:|$)/.test(tags.get("t") ?? "")) out.push(finding("dkim.testing", "warn", base));
  }
  return { findings: out, records };
}

/**
 * No common selector answered. An NXDOMAIN for `_domainkey.<domain>` means there is
 * nothing below it, so no key at all (RFC 8020, section 2); a NOERROR means some
 * name exists below it, so keys exist under a selector that is not on the list.
 * A wildcard zone answers for any name, so then nothing can be told.
 */
async function withoutSelector(domain: string, resolver: Resolver, count: number): Promise<Finding> {
  const unknown = finding("dkim.not-found", "info", { count });
  try {
    const [node, probe] = await Promise.all([resolver(`_domainkey.${domain}`, "TXT"), resolver(`da-check-${Date.now().toString(36)}.${domain}`, "TXT")]);
    if (lookupFailed(node) || lookupFailed(probe)) return unknown;
    if (node.status === 3) return finding("dkim.no-domainkey", "warn", { domain });
    if (node.status === 0 && probe.status === 3) return finding("dkim.selector-unknown", "info", { count, domain });
    return unknown;
  } catch {
    return unknown;
  }
}
