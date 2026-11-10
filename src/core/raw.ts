/**
 * Log of every HTTP request an audit makes, with the response body exactly as
 * received, so anyone can check the report against the raw data and repeat the
 * queries themselves.
 */

export type RawSource = "cloudflare" | "google" | "rdap" | "ripestat" | "crtsh" | "certspotter" | "shodan" | "otx" | "web";

export interface RawEntry {
  source: RawSource;
  /** Short human label, e.g. `example.com TXT`. */
  label: string;
  url: string;
  /** Final URL after redirects (an RDAP server may redirect to another one). */
  finalUrl?: string;
  /** Request headers that matter to repeat the query. */
  accept?: string;
  status: number | null;
  ms: number;
  at: string;
  body?: string;
  error?: string;
}

export type RawLog = RawEntry[];

export interface LoggedResponse {
  ok: boolean;
  status: number;
  url: string;
  text: string;
}

/**
 * fetch() that records the exchange in `log` (if given) and returns the body as
 * text, so it is stored untouched before any parsing.
 */
export async function loggedFetch(
  doFetch: typeof fetch,
  url: string,
  meta: { source: RawSource; label: string; accept?: string; timeoutMs: number; log?: RawLog },
): Promise<LoggedResponse> {
  const started = performance.now();
  const at = new Date().toISOString();
  const entry: RawEntry = { source: meta.source, label: meta.label, url, status: null, ms: 0, at };
  if (meta.accept) entry.accept = meta.accept;
  try {
    const res = await doFetch(url, {
      headers: meta.accept ? { accept: meta.accept } : {},
      signal: AbortSignal.timeout(meta.timeoutMs),
    });
    const text = await res.text();
    entry.status = res.status;
    entry.body = text;
    if (res.url && res.url !== url) entry.finalUrl = res.url;
    return { ok: res.ok, status: res.status, url: res.url || url, text };
  } catch (err) {
    entry.error = String(err);
    throw err;
  } finally {
    entry.ms = Math.round(performance.now() - started);
    meta.log?.push(entry);
  }
}

/** Shell command that repeats a logged request. */
export function curlCommand(entry: RawEntry): string {
  const header = entry.accept ? ` -H 'accept: ${entry.accept}'` : "";
  return `curl -sL${header} '${entry.url}'`;
}
