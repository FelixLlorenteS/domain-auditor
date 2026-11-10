/**
 * Runs the public mail test of internet.nl (the Dutch Internet Standards
 * Platform) and reads its verdicts, to compare them with the auditor's.
 *
 * The public site has no API without an account: GET /mail/<domain>/ starts the
 * test, /mail/probes/<domain>/ reports progress and /mail/<domain>/results
 * redirects to the finished report, whose panels read "Passed: SPF policy",
 * "Failed: DANE existence"… Results are cached for a day in validation/out.
 */
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { browserFetch } from "./truth";

export type NlStatus = "pass" | "fail" | "reco" | "info" | "not-tested" | "error";

export interface NlResult {
  domain: string;
  url: string;
  /** Test name → status, first occurrence (the mail address domain, not the MX domains). */
  tests: Record<string, NlStatus>;
}

const BASE = "https://internet.nl";
const CACHE = "validation/out/internetnl";
const DAY = 86_400_000;

const STATUS: Record<string, NlStatus> = {
  Passed: "pass",
  Failed: "fail",
  Recommendation: "reco",
  Information: "info",
  Warning: "reco",
  "Not testable": "not-tested",
  Error: "error",
};

const text = (html: string) =>
  html
    .replace(/<[^>]+>/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&#39;|&#x27;/g, "'")
    .replace(/\s+/g, " ")
    .trim();

export function parseResults(html: string): Record<string, NlStatus> {
  const tests: Record<string, NlStatus> = {};
  for (const m of html.matchAll(/<h3 class="panel-title"\s*>([\s\S]*?)<\/h3>/g)) {
    const [status = "", name = ""] = text(m[1] ?? "").split(/:\s*/, 2);
    if (name && !(name in tests)) tests[name] = STATUS[status] ?? "error";
  }
  return tests;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export async function internetNl(domain: string): Promise<NlResult> {
  mkdirSync(CACHE, { recursive: true });
  const file = `${CACHE}/${domain}.json`;
  if (existsSync(file) && Date.now() - statSync(file).mtimeMs < DAY) return JSON.parse(readFileSync(file, "utf8")) as NlResult;
  const get = (path: string) => browserFetch(`${BASE}${path}`, { signal: AbortSignal.timeout(60_000) });
  await get(`/mail/${domain}/`);
  for (let i = 0; i < 60; i++) {
    const probes = (await (await get(`/mail/probes/${domain}/`)).json()) as Array<{ done: boolean }>;
    if (probes.every((p) => p.done)) break;
    await sleep(5_000);
  }
  const res = await get(`/mail/${domain}/results`);
  const result: NlResult = { domain, url: res.url, tests: parseResults(await res.text()) };
  writeFileSync(file, JSON.stringify(result, null, 2));
  return result;
}
