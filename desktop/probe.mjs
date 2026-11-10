/**
 * Network probe of the desktop app: the connections a web page cannot make (a
 * site's headers, its TLS handshake, files served without CORS). It runs in
 * Electron's main process and is reached from the page only through the narrow
 * IPC API of preload.cjs.
 *
 * Safety: it only speaks HTTP(S) and TLS to public addresses. A name that
 * resolves to a private, loopback or link-local address is refused, so a domain
 * pointing at 192.168.1.1 cannot turn the app into a scanner of the user's own
 * network. Bodies are capped and every connection has a timeout.
 */
import { lookup as dnsLookup } from "node:dns";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import tls from "node:tls";

const TIMEOUT_MS = 10_000;
const MAX_BODY = 64 * 1024;
const UA = "Mozilla/5.0 (compatible; DomainAuditor/1.0; +https://felixllorente.com)";
const HOST_RE = /^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\.?$/i;

/** Private, loopback, link-local, CGNAT, multicast and reserved ranges. */
export function isPrivateAddress(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split(".").map(Number);
    return (
      a === 0 || a === 10 || a === 127 || a >= 224 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 198 && (b === 18 || b === 19))
    );
  }
  const v6 = ip.toLowerCase();
  if (v6.startsWith("::ffff:")) return isPrivateAddress(v6.slice(7));
  return v6 === "::" || v6 === "::1" || /^f[cd]/.test(v6) || /^fe[89ab]/.test(v6) || v6.startsWith("ff");
}

/**
 * Addresses of a name through DNS over HTTPS (Cloudflare, then Google), the same
 * view the rest of the audit has. The system resolver may differ: a filtering
 * DNS at home or at work would otherwise make a site look offline.
 */
async function dohAddresses(hostname) {
  for (const base of ["https://cloudflare-dns.com/dns-query", "https://dns.google/resolve"]) {
    try {
      const ask = async (type) => {
        const res = await fetch(`${base}?name=${encodeURIComponent(hostname)}&type=${type}`, { headers: { accept: "application/dns-json" }, signal: AbortSignal.timeout(5_000) });
        const j = await res.json();
        if (j.Status !== 0 && j.Status !== 3) throw new Error(`rcode ${j.Status}`);
        return (j.Answer ?? []).filter((a) => a.type === (type === "A" ? 1 : 28)).map((a) => ({ address: a.data, family: type === "A" ? 4 : 6 }));
      };
      const [v4, v6] = await Promise.all([ask("A"), ask("AAAA").catch(() => [])]);
      return [...v4, ...v6];
    } catch {
      /* next resolver */
    }
  }
  return null;
}

/** Name resolution for every connection: DoH first, the system as a fallback, never a private address. */
export function safeLookup(hostname, options, callback) {
  const done = (addresses) => {
    const list = addresses.filter((a) => !isPrivateAddress(a.address));
    if (!list.length) {
      const e = new Error("BLOCKED_PRIVATE_ADDRESS");
      e.code = "BLOCKED_PRIVATE_ADDRESS";
      return callback(e);
    }
    if (options?.all) return callback(null, list);
    callback(null, list[0].address, list[0].family);
  };
  dohAddresses(hostname).then((viaDoh) => {
    if (viaDoh?.length) return done(viaDoh);
    dnsLookup(hostname, { ...options, all: true }, (err, addresses) => (err ? callback(err) : done(addresses)));
  });
}

export function validHost(host) {
  return typeof host === "string" && HOST_RE.test(host) && !net.isIP(host);
}

function fail(err) {
  return { error: err?.code || err?.message || String(err) };
}

/** One GET, no redirects followed. Returns { url, status, headers, body } or { error }. */
export function request(url) {
  return new Promise((resolve) => {
    let u;
    try {
      u = new URL(url);
    } catch {
      return resolve({ error: "BAD_URL" });
    }
    if (!/^https?:$/.test(u.protocol) || !validHost(u.hostname) || u.username || u.password) return resolve({ error: "BAD_URL" });
    const mod = u.protocol === "https:" ? https : http;
    const req = mod.request(
      u,
      {
        method: "GET",
        agent: false,
        lookup: safeLookup,
        timeout: TIMEOUT_MS,
        rejectUnauthorized: true,
        headers: { "user-agent": UA, accept: "text/html,text/plain,*/*;q=0.8", "accept-encoding": "identity" },
      },
      (res) => {
        const headers = {};
        for (const [k, v] of Object.entries(res.headers)) headers[k.toLowerCase()] = Array.isArray(v) ? v.join(", ") : String(v ?? "");
        const chunks = [];
        let size = 0;
        const done = () => resolve({ url: u.toString(), status: res.statusCode ?? 0, headers, body: Buffer.concat(chunks).toString("utf8") });
        res.on("data", (c) => {
          if (size >= MAX_BODY) return;
          chunks.push(c.subarray(0, MAX_BODY - size));
          size += c.length;
          if (size >= MAX_BODY) {
            res.destroy();
            done();
          }
        });
        res.on("end", done);
        res.on("error", () => done());
      },
    );
    req.on("timeout", () => req.destroy(Object.assign(new Error("TIMEOUT"), { code: "TIMEOUT" })));
    req.on("error", (e) => resolve(fail(e)));
    req.end();
  });
}

const VERSIONS = new Set(["TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"]);
/** Errors raised by our own TLS library when it cannot offer a version at all: not the server's answer. */
const CLIENT_SIDE = /NO_PROTOCOLS_AVAILABLE|NO_CIPHERS?_(AVAILABLE|MATCH)|UNSUPPORTED_PROTOCOL_FOR_CUSTOM_KEY|invalid.*(min|max)Version|ERR_TLS_INVALID_PROTOCOL_VERSION/i;

function name(dn) {
  if (!dn) return "";
  return dn.O || dn.CN || Object.values(dn).join(", ");
}

/**
 * A TLS handshake. With `version`, only that version is offered. Electron's TLS
 * library (BoringSSL) still speaks TLS 1.0 and 1.1 as a client, so a refusal is
 * the server's; a system OpenSSL may refuse them itself (see CLIENT_SIDE).
 */
export function tlsProbe(host, version, port = 443) {
  return new Promise((resolve) => {
    if (!validHost(host) || (version !== undefined && !VERSIONS.has(version))) return resolve({ error: "BAD_HOST" });
    const opts = {
      host,
      port,
      servername: host,
      lookup: safeLookup,
      rejectUnauthorized: false,
      timeout: TIMEOUT_MS,
      ...(version ? { minVersion: version, maxVersion: version } : {}),
    };
    let socket;
    const finish = (r) => {
      socket?.destroy();
      resolve(r);
    };
    try {
      socket = tls.connect(opts, () => {
        const c = socket.getPeerCertificate();
        const cert =
          c && c.valid_to
            ? {
                subject: name(c.subject),
                issuer: name(c.issuer),
                validFrom: new Date(c.valid_from).toISOString(),
                validTo: new Date(c.valid_to).toISOString(),
                san: (c.subjectaltname ?? "").split(/,\s*/).filter(Boolean).map((s) => s.replace(/^DNS:/, "")),
              }
            : undefined;
        finish({
          protocol: socket.getProtocol(),
          cipher: socket.getCipher()?.name,
          authorized: socket.authorized,
          ...(socket.authorized ? {} : { authError: String(socket.authorizationError ?? "UNKNOWN") }),
          ...(cert ? { cert } : {}),
        });
      });
    } catch (e) {
      // Our library refused the options (e.g. a version it was built without).
      return resolve({ error: CLIENT_SIDE.test(String(e?.code ?? e?.message)) ? "CLIENT_UNSUPPORTED" : fail(e).error });
    }
    socket.on("timeout", () => finish({ error: "TIMEOUT" }));
    socket.on("error", (e) => {
      const code = String(e?.code ?? e?.message ?? e);
      finish({ error: CLIENT_SIDE.test(code) || CLIENT_SIDE.test(String(e?.message)) ? "CLIENT_UNSUPPORTED" : code });
    });
  });
}
