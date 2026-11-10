/**
 * "Raw data" view: every request the audit made and the response exactly as
 * received, plus the Cloudflare/Google comparison, so the report can be checked.
 */
import { curlCommand, type RawEntry, type RawLog, type RawSource } from "../core/raw";
import type { Report } from "../core/types";
import { uiText, type Lang } from "../i18n";
import { escapeHtml } from "./layout";

const SOURCE_NAMES: Record<RawSource, string> = {
  cloudflare: "Cloudflare DoH",
  google: "Google DoH",
  rdap: "RDAP",
  ripestat: "RIPEstat",
  crtsh: "crt.sh",
  certspotter: "Cert Spotter",
  shodan: "Shodan InternetDB",
  otx: "AlienVault OTX",
  web: "Web (HTTPS/TLS)",
};

function pretty(body: string | undefined): string {
  if (body === undefined) return "";
  try {
    return JSON.stringify(JSON.parse(body), null, 2);
  } catch {
    return body;
  }
}

function statusClass(e: RawEntry): string {
  if (e.error || e.status === null) return "s-fail";
  if (e.status >= 400 && e.status !== 404) return "s-fail";
  if (e.status === 404) return "s-info";
  return "s-ok";
}

/** DNS RCODE inside a DoH answer, shown next to the HTTP status. */
function rcode(e: RawEntry): string {
  if (e.source !== "cloudflare" && e.source !== "google") return "";
  try {
    const code = (JSON.parse(e.body ?? "") as { Status?: number }).Status;
    const names: Record<number, string> = { 0: "NOERROR", 2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED" };
    return code === undefined ? "" : ` · ${names[code] ?? `RCODE ${code}`}`;
  } catch {
    return "";
  }
}

function renderEntry(e: RawEntry, i: number, lang: Lang): string {
  const t = uiText(lang);
  const status = e.error ? t.rawError : `HTTP ${e.status}${rcode(e)}`;
  return `
    <details class="raw-entry" data-search="${escapeHtml(`${e.source} ${e.label} ${e.url}`.toLowerCase())}">
      <summary>
        <span class="badge ${statusClass(e)}">${escapeHtml(status)}</span>
        <span class="raw-source">${SOURCE_NAMES[e.source]}</span>
        <code class="raw-label">${escapeHtml(e.label)}</code>
        <span class="raw-ms">${e.ms} ms</span>
      </summary>
      <div class="raw-body">
        <dl>
          <dt>URL</dt><dd><a href="${escapeHtml(e.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(e.url)} ↗</a></dd>
          ${e.finalUrl ? `<dt>${t.rawRedirect}</dt><dd><a href="${escapeHtml(e.finalUrl)}" target="_blank" rel="noopener noreferrer">${escapeHtml(e.finalUrl)} ↗</a></dd>` : ""}
          ${e.accept ? `<dt>Accept</dt><dd><code>${escapeHtml(e.accept)}</code></dd>` : ""}
          <dt>${t.rawTime}</dt><dd>${escapeHtml(new Date(e.at).toLocaleTimeString(lang === "es" ? "es-ES" : "en-GB"))}</dd>
          ${e.error ? `<dt>${t.rawError}</dt><dd>${escapeHtml(e.error)}</dd>` : ""}
        </dl>
        <div class="raw-cmd">
          <code>${escapeHtml(curlCommand(e))}</code>
          <button type="button" class="copy" data-copy-raw="curl" data-i="${i}">${t.copy}</button>
        </div>
        ${
          e.body !== undefined
            ? `<div class="raw-response">
                 <div class="raw-response-head"><span>${t.rawResponse}</span>
                   <button type="button" class="copy" data-copy-raw="body" data-i="${i}">${t.rawCopyOriginal}</button></div>
                 <pre><code>${escapeHtml(pretty(e.body))}</code></pre>
               </div>`
            : ""
        }
      </div>
    </details>`;
}

function renderComparison(report: Report, lang: Lang): string {
  const t = uiText(lang);
  const checks = report.resolverCheck ?? [];
  if (!checks.length) return "";
  const cell = (values: string[]) =>
    values.length ? values.map((v) => `<code>${escapeHtml(v)}</code>`).join("") : `<span class="raw-none">${t.rawNoRecords}</span>`;
  return `
    <section class="card" aria-labelledby="h-compare">
      <h3 id="h-compare">${t.rawCompareTitle}</h3>
      <p class="raw-intro">${t.rawCompareIntro}</p>
      <div class="table-wrap"><table class="raw-compare">
        <thead><tr><th>${t.colName}</th><th>${t.colType}</th><th>${SOURCE_NAMES[checks[0]!.providers[0] as RawSource]}</th><th>${SOURCE_NAMES[checks[0]!.providers[1] as RawSource]}</th><th></th></tr></thead>
        <tbody>${checks
          .map(
            (c) => `<tr class="${c.same ? "same" : "differ"}">
              <td><code>${escapeHtml(c.name)}</code></td><td>${c.type}</td>
              <td>${cell(c.answers[0])}</td><td>${cell(c.answers[1])}</td>
              <td class="raw-verdict">${c.same ? `✓ ${t.rawSame}` : `≠ ${t.rawDiffer}`}</td></tr>`,
          )
          .join("")}</tbody>
      </table></div>
    </section>`;
}

export function renderRaw(el: HTMLElement, report: Report, log: RawLog, lang: Lang, toolbar: string): void {
  const t = uiText(lang);
  const bySource = (["cloudflare", "google", "rdap", "ripestat", "crtsh", "certspotter", "shodan", "otx", "web"] as RawSource[])
    .map((s) => [s, log.filter((e) => e.source === s).length] as const)
    .filter(([, n]) => n);
  const totalMs = log.length ? Math.max(...log.map((e) => Date.parse(e.at) + e.ms)) - Math.min(...log.map((e) => Date.parse(e.at))) : 0;

  el.innerHTML = `
    <section class="card raw-head" aria-labelledby="h-raw">
      <div class="summary-head">
        <div>
          <h2 id="h-raw">${t.rawTitle} · ${escapeHtml(report.query)}</h2>
          <div class="meta">${log.length} ${t.rawQueries} · ${bySource.map(([s, n]) => `${SOURCE_NAMES[s]} ${n}`).join(" · ")} · ${totalMs} ms</div>
        </div>
      </div>
      ${toolbar}
      <p class="raw-intro">${t.rawIntro}</p>
      <label class="raw-filter"><span class="sr-only">${t.rawFilter}</span>
        <input type="search" placeholder="${escapeHtml(t.rawFilter)}" spellcheck="false" autocomplete="off" id="raw-filter" /></label>
    </section>
    ${renderComparison(report, lang)}
    <section class="card" aria-labelledby="h-requests">
      <h3 id="h-requests">${t.rawRequests}</h3>
      <div class="raw-list">${log.map((e, i) => renderEntry(e, i, lang)).join("")}</div>
      <p class="raw-empty" hidden>${t.searchEmpty}</p>
    </section>`;

  const filter = el.querySelector<HTMLInputElement>("#raw-filter")!;
  filter.addEventListener("input", () => {
    const terms = filter.value.toLowerCase().split(/\s+/).filter(Boolean);
    let shown = 0;
    el.querySelectorAll<HTMLElement>(".raw-entry").forEach((d) => {
      const match = terms.every((term) => (d.dataset.search ?? "").includes(term));
      d.hidden = !match;
      if (match) shown++;
    });
    el.querySelector<HTMLElement>(".raw-empty")!.hidden = shown > 0;
  });

  el.querySelectorAll<HTMLButtonElement>("button[data-copy-raw]").forEach((btn) =>
    btn.addEventListener("click", async () => {
      const entry = log[Number(btn.dataset.i)];
      if (!entry) return;
      const text = btn.dataset.copyRaw === "curl" ? curlCommand(entry) : (entry.body ?? "");
      try {
        await navigator.clipboard.writeText(text);
        const label = btn.textContent;
        btn.textContent = t.copiedShort;
        setTimeout(() => (btn.textContent = label), 1800);
      } catch {
        /* clipboard unavailable */
      }
    }),
  );
}
