import "@fontsource-variable/jetbrains-mono";
import "@fontsource-variable/geist";
import "./style.css";

import { audit } from "./core/audit";
import { createResolver, queryProvider } from "./core/doh";
import { externalLinks, externalTitle } from "./ui/external";
import { clientReportHtml } from "./ui/client-report";
import { compareReports } from "./ui/compare";
import { forget, previousReport, saveReport } from "./ui/history";
import type { RawLog } from "./core/raw";
import { renderRaw } from "./ui/raw";
import { evidenceFor, expectedFor } from "./ui/observed";
import { buildControls, confidenceOf, hasGap, isAssessed, needsAction, scoreOf, severityOf, TEXT as CTEXT, type Control, type ControlGroup, type ControlState, type GroupId } from "./ui/controls";
import { reportMarkdown } from "./ui/markdown";
import { ATTACK_NOTICE, riskOf, techniqueUrl, type Technique } from "./ui/attack";
import { InputError, parseTarget } from "./core/input";
import type { Finding, RecordRow, Report } from "./core/types";
import { verdicts, type Verdict } from "./core/summary";
import { cleanSelector } from "./core/dkim";
import { message, uiText, verdictText, type Lang, type MessageContext } from "./i18n";
import { escapeHtml, footer, header, initialLang, keepLangInLinks, rich, saveLang, trackHeaderHeight } from "./ui/layout";
import { wikiAnchor } from "./wiki/content";
import { initPalette, type PaletteItem } from "./ui/palette";
import { wikiItems } from "./wiki/search";
import { desktop } from "./desktop";

const EXAMPLES = ["felixllorente.com", "gmail.com", "1.1.1.1", "2001:4860:4860::8888"];

let lang: Lang = initialLang();
let lastReport: Report | null = null;
let lastRaw: RawLog = [];
/** The report of this target saved in the browser before the current one, to show what changed. */
let previous: Report | null = null;
let running = 0;
/** A first report is on screen and Certificate Transparency is still being checked. */
let completing = false;
type View = "report" | "raw";
let view: View = new URLSearchParams(location.search).get("view") === "raw" ? "raw" : "report";

const app = document.querySelector<HTMLDivElement>("#app")!;

function shell(): void {
  const t = uiText(lang);
  document.documentElement.lang = lang;
  app.innerHTML = `
    <div class="glow" aria-hidden="true"></div>
    <div class="wrap">
      ${header(lang, view === "raw" ? "raw" : "audit")}
      <main data-view="${view}">
        <section class="hero">
          <h1 class="hero-title"><span>${t.heroLine1}</span><span>${t.heroLine2}</span></h1>
          <p class="hero-sub">${escapeHtml(desktop ? t.heroSubDesktop : t.heroSub)}</p>
          <form class="search" id="form" novalidate role="search">
            <label class="sr-only" for="q">${escapeHtml(t.placeholder)}</label>
            <input id="q" name="q" type="text" inputmode="url" autocomplete="off" autocapitalize="off" spellcheck="false"
              placeholder="${escapeHtml(t.placeholder)}" />
            <button class="search-btn" id="submit" type="submit">${t.submit}</button>
          </form>
          <div class="examples">
            <span>${t.examples}:</span>
            ${EXAMPLES.map((e) => `<button type="button" data-example="${e}">${e}</button>`).join("")}
          </div>
          <p class="hero-note">${escapeHtml(desktop ? t.heroNoteDesktop : t.heroNote)}</p>
          <div id="message" class="message" role="status" aria-live="polite"></div>
        </section>
        <section class="howto" aria-labelledby="h-howto">
          <h2 id="h-howto">${t.howtoTitle}</h2>
          <ol>${t.howto.map(([title, text]) => `<li><h3>${escapeHtml(title)}</h3><p>${rich(text)}</p></li>`).join("")}</ol>
        </section>
        <div id="report" class="report"></div>
        <section class="notes">
          <div><h2>${t.privacyTitle}</h2><p>${escapeHtml(desktop ? t.privacyDesktop : t.privacy)}</p></div>
          <div><h2>${t.limitsTitle}</h2><p>${escapeHtml(desktop ? t.limitsDesktop : t.limits)}</p></div>
        </section>
      </main>
      ${footer(lang)}
    </div>`;
  keepLangInLinks(app, lang);
  trackHeaderHeight();
  document.querySelector("#search")!.addEventListener("click", () => palette.open());
  document.querySelector("#nav-raw")!.addEventListener("click", (e) => {
    e.preventDefault();
    showView("raw");
  });
  document.querySelector("#nav-audit")!.addEventListener("click", (e) => {
    if (!lastReport) return;
    e.preventDefault();
    showView("report");
  });

  const form = document.querySelector<HTMLFormElement>("#form")!;
  const input = document.querySelector<HTMLInputElement>("#q")!;
  input.addEventListener("focus", () => input.select());
  // A new audit from the search box starts without the previous domain's DKIM selectors.
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    dkimSelectors = [];
    void run(input.value);
  });
  document.querySelectorAll<HTMLButtonElement>("[data-example]").forEach((b) =>
    b.addEventListener("click", () => {
      input.value = b.dataset.example ?? "";
      dkimSelectors = [];
      void run(input.value);
    }),
  );
  document.querySelector("#lang")!.addEventListener("click", () => {
    lang = lang === "es" ? "en" : "es";
    saveLang(lang);
    const value = input.value;
    shell();
    document.querySelector<HTMLInputElement>("#q")!.value = value;
    renderView();
  });
}

function setMessage(text: string, loading = false): void {
  const el = document.querySelector<HTMLDivElement>("#message")!;
  el.textContent = text;
  el.classList.toggle("loading", loading);
}

/** DKIM selectors typed by the user, kept in the URL (`sel=a,b`) so links can be shared. */
let dkimSelectors: string[] = (new URLSearchParams(location.search).get("sel") ?? "")
  .split(",")
  .map((s) => cleanSelector(s))
  .filter((s): s is string => s !== null);

function syncUrl(query?: string): void {
  const url = new URL(location.href);
  if (query) url.searchParams.set("q", query);
  else url.searchParams.delete("q");
  if (dkimSelectors.length) url.searchParams.set("sel", dkimSelectors.join(","));
  else url.searchParams.delete("sel");
  url.searchParams.set("lang", lang);
  if (view === "raw") url.searchParams.set("view", "raw");
  else url.searchParams.delete("view");
  history.replaceState(null, "", url);
}

/** Renders the current view (friendly report or raw data) into #report. */
function renderView(): void {
  const el = document.querySelector<HTMLDivElement>("#report")!;
  const main = document.querySelector("main")!;
  main.dataset.view = view;
  main.classList.toggle("has-report", lastReport !== null);
  document.querySelectorAll<HTMLAnchorElement>(".nav-links a").forEach((a) => a.removeAttribute("aria-current"));
  document.querySelector(view === "raw" ? "#nav-raw" : "#nav-audit")?.setAttribute("aria-current", "page");
  if (view === "raw") {
    if (lastReport) {
      renderRaw(el, lastReport, lastRaw, lang, toolbar());
      wireToolbar(el, lastReport);
    }
    else el.innerHTML = `<section class="card"><p class="raw-intro">${uiText(lang).rawNone}</p></section>`;
  } else if (lastReport) renderReport(lastReport);
  else el.innerHTML = "";
}

function showView(next: View): void {
  view = next;
  renderView();
  syncUrl(lastReport?.query);
  window.scrollTo({ top: 0, behavior: "instant" });
}

async function run(raw: string): Promise<void> {
  const t = uiText(lang);
  const reportEl = document.querySelector<HTMLDivElement>("#report")!;
  let target;
  try {
    target = parseTarget(raw);
  } catch (err) {
    setMessage(err instanceof InputError && err.code === "empty" ? t.empty : t.invalid);
    return;
  }

  const id = ++running;
  const button = document.querySelector<HTMLButtonElement>("#submit")!;
  button.disabled = true;
  reportEl.innerHTML = "";
  setMessage(t.running, true);
  try {
    // A first report as soon as everything but Certificate Transparency is in;
    // the full one replaces it when crt.sh answers. Only the full one is saved.
    let done = false;
    const { report, log } = await freshAudit(target, (partial, partialLog) => {
      if (id !== running || done) return;
      if (lastReport?.query !== partial.query) previous = previousReport(partial.query) ?? null;
      lastReport = partial;
      lastRaw = partialLog;
      completing = true;
      renderView();
      setMessage(t.completing, true);
      syncUrl(partial.query);
      window.scrollTo({ top: 0, behavior: "smooth" });
    });
    done = true;
    if (id !== running) return;
    const wasPartial = completing;
    completing = false;
    // The previous report of this target, unless it is the one already on screen.
    const saved = previousReport(report.query);
    if (lastReport?.query !== report.query) previous = saved ?? null;
    saveReport(report);
    lastReport = report;
    lastRaw = log;
    setMessage("");
    document.querySelector<HTMLInputElement>("#q")!.value = report.query;
    // Re-rendering keeps the reader where they are when the first report was already on screen.
    const y = window.scrollY;
    renderView();
    syncUrl(report.query);
    if (wasPartial) window.scrollTo({ top: y });
    else window.scrollTo({ top: 0, behavior: "smooth" });
  } catch {
    completing = false;
    if (id === running) setMessage(t.failed);
  } finally {
    if (id === running) button.disabled = false;
  }
}

/** A full audit with a new resolver (no cache), every request logged for "Raw data". */
async function freshAudit(target: ReturnType<typeof parseTarget>, onPartial?: (report: Report, log: RawLog) => void): Promise<{ report: Report; log: RawLog }> {
  const log: RawLog = [];
  const report = await audit(target, {
    dkimSelectors,
    resolver: createResolver({ log }),
    secondOpinion: (provider, name, type) => queryProvider(provider, name, type, { log }),
    checkingDisabled: (name, type) => queryProvider("cloudflare", name, type, { log, cd: true }),
    log,
    ...(desktop ? { web: desktop } : {}),
    ...(onPartial ? { onPartial: (r: Report) => onPartial(r, log) } : {}),
  });
  return { report, log };
}

/**
 * "Is it fixed yet?": audits again from scratch and says, for one control, what
 * changed. If nothing did and the control still has a problem, the TTL of its
 * records tells how long resolvers may keep serving the previous answer.
 */
async function recheck(controlId: string, button: HTMLButtonElement): Promise<void> {
  const t = uiText(lang);
  const x = CTEXT[lang];
  const before = lastReport;
  if (!before) return;
  button.disabled = true;
  button.textContent = t.rechecking;
  let message: string;
  try {
    const { report, log } = await freshAudit(parseTarget(before.query));
    const change = compareReports(before, report).changes.find((c) => c.id === controlId);
    const control = buildControls(report).flatMap((g) => g.controls).find((c) => c.id === controlId);
    const state = control?.state ?? "na";
    if (change) message = t.recheckNow.replace("{to}", x.states[change.to]).replace("{from}", x.states[change.from]);
    else {
      message = t.recheckSame.replace("{state}", x.states[state].toLowerCase());
      const rows = control?.evidence ? evidenceFor(control.evidence, control.findings[0]!.section, report.query).rows : [];
      const ttl = Math.max(0, ...rows.map((r) => r.ttl ?? 0));
      if ((state === "fail" || state === "warn") && ttl > 0) message += ` ${t.recheckTtl.replace("{min}", String(Math.ceil(ttl / 60)))}`;
    }
    saveReport(report);
    lastReport = report;
    lastRaw = log;
    renderView();
    revealControl(controlId);
  } catch {
    message = t.recheckFailed;
    button.disabled = false;
    button.textContent = t.recheck;
  }
  const msg = document.querySelector<HTMLElement>(`#c-${controlId} .recheck-msg`);
  if (msg) msg.textContent = message;
}

/** What changed since the report saved in this browser for the same target. */
function renderChanges(report: Report): string {
  if (!previous || previous.query !== report.query) return "";
  const t = uiText(lang);
  const x = CTEXT[lang];
  const diff = compareReports(previous, report);
  const date = new Date(previous.generatedAt).toLocaleString(lang === "es" ? "es-ES" : "en-GB");
  const label = { worse: t.changesWorse, better: t.changesBetter, changed: t.changesChanged };
  const score = (s: { passed: number; total: number }) => (s.total ? `${s.passed}/${s.total}` : "—");
  const items = diff.changes
    .map(
      (c) =>
        `<li class="chg-${c.kind}"><span class="chg-kind">${label[c.kind]}</span> <a href="#c-${c.id}" data-open-control="${c.id}">${x.controls[c.id] ?? c.id}</a>: ${x.states[c.from]} → ${x.states[c.to]}</li>`,
    )
    .join("");
  return `
    <section class="changes" aria-labelledby="h-changes">
      <h3 id="h-changes">${t.changesTitle}</h3>
      <p class="changes-note">${escapeHtml(t.changesSince.replace("{date}", date))} ${escapeHtml(t.changesScore.replace("{before}", score(diff.before)).replace("{after}", score(diff.after)))}</p>
      ${items ? `<ul>${items}</ul>` : `<p>${t.changesNone}</p>`}
      <button type="button" class="linklike" data-forget>${t.forgetHistory}</button>
    </section>`;
}

/**
 * Any print of a report (the button or Ctrl+P) produces the client report, a
 * document of its own laid out for A4, never the web page with its folds.
 */
function enterPrint(): boolean {
  if (!lastReport || view !== "report") return false;
  document.getElementById("client-report")?.remove();
  const holder = document.createElement("div");
  holder.id = "client-report";
  holder.innerHTML = clientReportHtml(lastReport, lang, identityRows(lastReport), contextOf(lastReport));
  document.body.append(holder);
  document.documentElement.classList.add("printing-report");
  return true;
}
function leavePrint(): void {
  document.documentElement.classList.remove("printing-report");
  document.getElementById("client-report")?.remove();
}
window.addEventListener("beforeprint", () => void enterPrint());
window.addEventListener("afterprint", leavePrint);

/** Desktop app: the client report goes straight to a PDF file the user picks. */
async function savePdf(btn: HTMLButtonElement): Promise<void> {
  const t = uiText(lang);
  if (!desktop || !lastReport || !enterPrint()) return;
  const label = btn.innerHTML;
  btn.disabled = true;
  btn.textContent = t.savingPdf;
  try {
    const day = lastReport.generatedAt.slice(0, 10);
    const r = await desktop.savePdf(`${lang === "es" ? "informe" : "report"}-${lastReport.query}-${day}.pdf`);
    btn.textContent = r.saved ? t.pdfSaved : label;
  } catch {
    btn.innerHTML = label;
  } finally {
    leavePrint();
    btn.disabled = false;
    setTimeout(() => (btn.innerHTML = label), 2000);
  }
}

/** Name as most DNS panels expect it: `@` for the apex, the label for names under it. */
function relativeName(name: string, domain: string): string {
  if (name === domain) return "@";
  return name.endsWith(`.${domain}`) ? name.slice(0, -domain.length - 1) : name;
}

const MAILBOX_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function valueHtml(value: string): string {
  return escapeHtml(value).replace("{mailbox}", `<span class="slot" data-slot="mailbox">${uiText(lang).mailboxSlot}</span>`);
}

function renderSuggestions(f: Finding, domain: string): string {
  const t = uiText(lang);
  if (!f.suggest?.length) return "";
  const heading = f.suggest.some((s) => s.action === "replace") ? t.recordReplace : f.suggest.length > 1 ? t.recordsAdd : t.recordAdd;
  const needsMailbox = f.suggest.some((s) => s.input === "mailbox");
  const rows = f.suggest
    .map((s) => {
      const rel = relativeName(s.name, domain);
      const locked = s.input === "mailbox";
      return `
        <tr>
          <td data-label="${t.colType}"><code>${s.type}</code>${s.optional ? `<span class="optional">${t.optional}</span>` : ""}</td>
          <td data-label="${t.colName}"><code>${escapeHtml(rel)}</code>${rel !== s.name ? `<span class="fqdn">${escapeHtml(s.name)}</span>` : ""}</td>
          <td data-label="${t.colValue}" class="value"><code>${valueHtml(s.value)}</code></td>
          <td><button type="button" class="copy" data-copy="${escapeHtml(s.value)}"${locked ? " data-needs-mailbox disabled" : ""}>${t.copy}</button></td>
        </tr>`;
    })
    .join("");
  const apex = f.suggest.some((s) => s.name === domain);
  return `
    <div class="suggest">
      <div class="suggest-title">${heading}</div>
      ${
        needsMailbox
          ? `<label class="mailbox">${t.mailboxLabel}
               <input type="email" autocomplete="email" spellcheck="false" placeholder="${escapeHtml(t.mailboxPlaceholder)}" data-mailbox />
             </label>`
          : ""
      }
      <table class="suggest-table">
        <thead><tr><th>${t.colType}</th><th>${t.colName}</th><th>${t.colValue}</th><th></th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
      ${apex ? `<p class="hint">${t.nameHint}</p>` : ""}
    </div>`;
}

function renderFiles(f: Finding): string {
  const t = uiText(lang);
  return (f.files ?? [])
    .map(
      (file) => `
      <div class="suggest">
        <div class="suggest-title">${t.fileToPublish}</div>
        <p class="file-url"><code>${escapeHtml(file.url)}</code></p>
        <div class="file-box">
          <pre><code>${escapeHtml(file.content.replace(/\r\n/g, "\n"))}</code></pre>
          <button type="button" class="copy" data-copy="${escapeHtml(file.content)}">${t.copy}</button>
        </div>
      </div>`,
    )
    .join("");
}

const isProblem = (f: Finding) => f.status === "fail" || f.status === "warn";

const circle = `<circle cx="12" cy="12" r="9" />`;
const ICON: Record<ControlState, string> = {
  ok: `<svg viewBox="0 0 24 24" aria-hidden="true">${circle}<path d="m8 12.5 2.8 2.8L16 9.5" /></svg>`,
  fail: `<svg viewBox="0 0 24 24" aria-hidden="true">${circle}<path d="m9 9 6 6m0-6-6 6" /></svg>`,
  warn: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3.5 2.5 20h19Z" /><path d="M12 10v4.5m0 2.8v.2" /></svg>`,
  info: `<svg viewBox="0 0 24 24" aria-hidden="true">${circle}<path d="M12 11v5.5m0-8.8v.2" /></svg>`,
  optional: `<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="9" stroke-dasharray="3 3" /></svg>`,
  na: `<svg viewBox="0 0 24 24" aria-hidden="true">${circle}<path d="M8 12h8" /></svg>`,
  unknown: `<svg viewBox="0 0 24 24" aria-hidden="true">${circle}<path d="M9.5 9.5a2.5 2.5 0 1 1 3.5 2.3c-.6.3-1 .9-1 1.6v.4m0 3v.2" /></svg>`,
};

const zoneLine = (r: RecordRow) => `${r.name}  ${r.ttl !== undefined ? `${r.ttl}  ` : ""}${r.type}  ${r.data}`;

/** Group each verdict points to. */
const VERDICT_GROUP: Record<Verdict["area"], GroupId> = { spoofing: "mail-auth", dns: "dns-integrity", web: "web", registration: "registration", sending: "ip" };

/**
 * Evidence first: the query, whether both resolvers agree, the records as they
 * came back and a link to the original response. The checks below are read
 * from this, so anyone can verify them.
 */
/**
 * What the DNS answered to the query behind an empty evidence box, read from the
 * raw log: NOERROR without data, or NXDOMAIN (the name does not exist). Null when
 * it cannot be told (several queries with different answers, or no log).
 */
function emptyAnswer(where: string): "noerror" | "nxdomain" | null {
  const pattern = new RegExp(`^${where.replace(/[.*+?^${}()|[\]\\]/g, "\\$&").replace(/…/g, ".*").replace(/<selector>/g, "[^ ]+")}$`);
  const codes = new Set(
    lastRaw
      .filter((e) => (e.source === "cloudflare" || e.source === "google") && pattern.test(e.label) && e.body)
      .map((e) => {
        try {
          return (JSON.parse(e.body!) as { Status?: number }).Status;
        } catch {
          return undefined;
        }
      }),
  );
  if (codes.size !== 1) return null;
  const [code] = [...codes];
  return code === 0 ? "noerror" : code === 3 ? "nxdomain" : null;
}

function renderEvidence(c: Control, report: Report, ctx: MessageContext): string {
  const x = CTEXT[lang];
  const domain = report.query;
  const section = c.findings[0]!.section;
  const parts: string[] = [];
  let body = "";
  if (c.evidence) {
    const ev = evidenceFor(c.evidence, section, domain);
    parts.push(`<code>${escapeHtml(ev.where)}</code>`);
    const ctFailed = c.findings.some(({ f }) => f.id === "ct.unavailable");
    const pre = (rows: RecordRow[]) => `<pre><code>${rows.map((r) => escapeHtml(zoneLine(r))).join("\n")}</code></pre>`;
    // Long evidence (many DKIM keys, subdomains) shows the first lines; the rest folds.
    // Nothing found is evidence too: say what the DNS answered, and whether that is the good outcome.
    const answer = ev.rows.length || ctFailed ? null : emptyAnswer(ev.where);
    const emptyText = ctFailed
      ? x.ctFailed
      : c.state === "ok"
        ? `${answer === "nxdomain" ? x.emptyNxdomain : answer === "noerror" ? x.emptyNoerror : x.emptyNone}${x.emptyExpected}`
        : answer === "nxdomain" ? x.emptyNxdomain : answer === "noerror" ? x.emptyNoerror : x.empty;
    body = !ev.rows.length
      ? `<pre class="ev-empty"><code>${emptyText}</code></pre>`
      : ev.rows.length > 8
        ? `${pre(ev.rows.slice(0, 6))}<details class="ev-more"><summary>${x.evMore.replace("{n}", String(ev.rows.length))}</summary>${pre(ev.rows.slice(6))}</details>`
        : pre(ev.rows);
  } else if (c.id === "resolvers" && report.resolverCheck?.length) {
    body = `<ul class="ev-list">${report.resolverCheck
      .map((k) => `<li class="${k.same ? "same" : "differ"}"><code>${escapeHtml(`${k.name} ${k.type}`)}</code> ${k.same ? "=" : "≠"}</li>`)
      .join("")}</ul>`;
  } else {
    const details = c.findings.map(({ f }) => message(lang, f.id, f.params, ctx).detail).filter(Boolean) as string[];
    if (details.length) body = `<ul class="ev-list">${details.map((d) => `<li>${rich(d)}</li>`).join("")}</ul>`;
  }
  if (c.check) {
    parts.push(`<span class="${c.check.same ? "agree" : "differ"}">${c.check.same ? x.agree : x.differ}</span>`);
    if (!c.check.same) {
      body += `<ul class="ev-list">${c.check.providers
        .map((p, i) => `<li><strong>${escapeHtml(p)}:</strong> <code>${escapeHtml(c.check!.answers[i]!.join(" | ") || "—")}</code></li>`)
        .join("")}</ul>`;
    }
  } else if (c.evidence) {
    const primary = lastRaw.find((e) => e.source === "cloudflare" || e.source === "google")?.source === "google" ? "Google" : "Cloudflare";
    parts.push(x.single.replace("{primary}", primary));
  }
  if (c.rawFilter) parts.push(`<button type="button" class="linklike" data-raw-filter="${escapeHtml(c.rawFilter)}">${x.viewRaw}</button>`);
  if (!body && parts.length <= 1) return "";
  return `<div class="ctl-part"><h4>${x.evidence}${parts.length ? ` · ${parts.join(" · ")}` : ""}</h4>${body}</div>`;
}

function renderCheck({ f }: { f: Finding }, ctx: MessageContext): string {
  const t = uiText(lang);
  const m = message(lang, f.id, f.params, ctx);
  const anchor = wikiAnchor(f.id);
  const ref = m.tech?.match(/RFC \d+/)?.[0];
  return `
    <li class="check s-${f.status}" data-finding="${escapeHtml(f.id)}">
      <span class="ck-icon">${ICON[f.status]}</span>
      <div class="ck-body">
        <div class="ck-title">${rich(m.title)}${ref ? `<span class="ck-ref">${ref}</span>` : ""}</div>
        ${m.detail ? `<div class="finding-detail">${rich(m.detail)}</div>` : ""}
        ${m.what ? `<p class="what">${rich(m.what)}</p>` : ""}
        ${m.context ? `<p class="context"><strong>${t.contextLabel}</strong> ${rich(m.context)}</p>` : ""}
        ${
          m.tech || anchor
            ? `<div class="finding-links">
                ${m.tech ? `<details class="tech"><summary>${t.techDetail}</summary><p>${rich(m.tech)}</p></details>` : ""}
                ${anchor ? `<a class="more" href="/wiki/?lang=${lang}#${anchor}">${t.moreInfo} →</a>` : ""}
              </div>`
            : ""
        }
      </div>
    </li>`;
}

/** Steps, exact records and files for the findings that need them. */
function fixOf(findings: Finding[], domain: string, ctx: MessageContext): string {
  // The same step ("go to the DNS panel") is given once, not once per finding.
  const seen = new Set<string>();
  return findings
    .map((f) => {
      const m = message(lang, f.id, f.params, ctx);
      const own = (m.steps ?? []).filter((st) => !seen.has(st) && (seen.add(st), true));
      const steps = own.length ? `<ol class="steps">${own.map((st) => `<li>${rich(st)}</li>`).join("")}</ol>` : "";
      return steps + renderFiles(f) + renderSuggestions(f, domain);
    })
    .filter(Boolean)
    .join("");
}

const techniqueChip = (t: Technique) =>
  `<a class="attack" href="${techniqueUrl(t.id)}" target="_blank" rel="noopener" title="${escapeHtml(t.tactic)}"><b>${t.id}</b> ${escapeHtml(t.name)}<span>${escapeHtml(t.tactic)}</span></a>`;

/** The attacker's view: what a gap allows (or what the control stops), with ATT&CK techniques. */
function renderRisk(c: Control): string {
  const x = CTEXT[lang];
  if (c.state === "na") return "";
  // The risk text is about the protection itself; a side warning shows what it adds instead.
  const fine = !hasGap(c);
  const r = riskOf(c.id, fine, lang);
  if (!r) return "";
  return `
    <div class="ctl-part ctl-risk${fine ? " fine" : ""}">
      <h4>${fine ? x.prevents : x.risk}</h4>
      <p>${rich(r.text)}</p>
      ${r.techniques.length ? `<div class="attacks"><span class="attacks-label">${x.related}</span>${r.techniques.map(techniqueChip).join("")}</div>` : ""}
    </div>`;
}

function renderAction(c: Control, report: Report, ctx: MessageContext): string {
  const x = CTEXT[lang];
  const domain = report.query;
  const expected = c.evidence ? `<p class="expected"><strong>${x.expected}</strong> ${rich(expectedFor(c.evidence, domain, lang))}</p>` : "";
  const problems = c.findings.map(({ f }) => f).filter(isProblem);
  let body: string;
  if (problems.length) {
    const fix = fixOf(problems, domain, ctx);
    const hasRecord = problems.some((f) => f.suggest?.length || f.files?.length);
    body = fix + (hasRecord ? "" : expected);
  } else {
    const withFix = c.findings.map(({ f }) => f).filter((f) => f.suggest?.length || f.files?.length);
    if (c.state === "optional") body = `<p>${x.actionOptional}</p>${withFix.length ? fixOf(withFix, domain, ctx) : expected}`;
    else if (withFix.length) body = fixOf(withFix, domain, ctx);
    else body = `<p class="${c.state === "ok" ? "action-ok" : "action-none"}">${c.state === "ok" ? x.actionNone : x.actionInfo}</p>`;
  }
  return `<div class="ctl-part ctl-action"><h4>${x.action}</h4>${body}</div>`;
}

/**
 * The line shown next to a control: its most severe finding. Among equals, a
 * specific one ("fake mail is rejected") beats the generic "has DMARC".
 */
function headlineOf(c: Control): Finding {
  const top = c.findings.filter(({ f }) => f.status === c.findings[0]!.f.status).map(({ f }) => f);
  return top.find((f) => f.id === "reg.recent") ?? top.find((f) => !f.id.endsWith(".found")) ?? top[0]!;
}

function renderControl(c: Control, report: Report, ctx: MessageContext): string {
  const t = uiText(lang);
  const x = CTEXT[lang];
  const head = headlineOf(c);
  const assessed = c.findings.filter(({ f }) => f.status !== "info");
  const tally = assessed.length > 1 ? ` · ${assessed.filter(({ f }) => f.status === "ok").length}/${assessed.length}` : "";
  // Selectors cannot be listed through DNS: let the user try a specific one
  // (e.g. the s= of a DKIM-Signature header), whatever was found already.
  const dkimForm =
    c.id === "dkim"
      ? `<form class="dkim-try" data-dkim-form>
           <label>${t.dkimTry}
             <input type="text" spellcheck="false" autocomplete="off" placeholder="${escapeHtml(t.dkimPlaceholder)}" />
           </label>
           <button type="submit" class="copy">${t.dkimButton}</button>
           <span class="dkim-msg" role="status"></span>
         </form>`
      : "";
  return `
    <details class="control st-${c.state}" id="c-${c.id}" data-state="${c.state}"${needsAction(c) ? " open" : ""}>
      <summary>
        <span class="ctl-icon">${ICON[c.state]}</span>
        <span class="ctl-name">${x.controls[c.id] ?? c.id}</span>
        <span class="ctl-head">${rich(message(lang, head.id, head.params, ctx).title)}</span>
        <span class="ctl-state">${x.states[c.state]}${tally}</span>
      </summary>
      <div class="ctl-body">
        <p class="recheck"><button type="button" class="btn-ghost" data-recheck="${c.id}">${t.recheck}</button> <span class="recheck-msg" role="status"></span></p>
        <p class="ctl-tags">${needsAction(c) ? `<span class="sev sev-${severityOf(c)}">${x.severity[severityOf(c)]}</span>` : ""}<span>${x.confidence[confidenceOf(c)]}</span></p>
        ${renderEvidence(c, report, ctx)}
        <div class="ctl-part"><h4>${x.checks}</h4><ul class="checks">${c.findings.map((cf) => renderCheck(cf, ctx)).join("")}</ul></div>
        ${renderRisk(c)}
        ${renderAction(c, report, ctx)}
        ${dkimForm}
      </div>
    </details>`;
}

function renderGroup(g: ControlGroup, report: Report, ctx: MessageContext): string {
  const x = CTEXT[lang];
  const assessed = g.controls.filter(isAssessed);
  const optional = g.controls.filter((c) => c.state === "optional").length;
  const meta = [
    assessed.length ? x.groupOk.replace("{n}", String(assessed.filter((c) => c.state === "ok").length)).replace("{total}", String(assessed.length)) : "",
    optional ? (optional === 1 ? x.groupOptionalOne : x.groupOptional.replace("{n}", String(optional))) : "",
  ]
    .filter(Boolean)
    .join(" · ");
  return `
    <section class="card ctl-group" id="g-${g.id}" aria-labelledby="h-g-${g.id}">
      <div class="ctl-group-head"><h3 id="h-g-${g.id}">${x.groups[g.id]}</h3><span>${meta}</span></div>
      <div class="ctl-list">${g.controls.map((c) => renderControl(c, report, ctx)).join("")}</div>
    </section>`;
}

/** Three figures: how many controls pass, how many need action, how far the data can be trusted. */
function renderMetrics(groups: ControlGroup[], report: Report): string {
  const x = CTEXT[lang];
  const controls = groups.flatMap((g) => g.controls);
  const score = scoreOf(report, groups);
  const actions = controls.filter(needsAction).length;
  const checks = report.resolverCheck ?? [];
  const differ = checks.filter((c) => !c.same).length;
  const all = report.sections.flatMap((s) => s.findings);
  const dnssec = all.some((f) => f.id === "dns.dnssec" || f.id === "dns.dnssec-both");
  const ctDown = all.some((f) => f.id === "ct.unavailable");
  const ctPending = all.some((f) => f.id === "ct.pending");
  const trust =
    report.kind === "ip"
      ? `<span>${x.trustIp}</span>`
      : `<span class="${differ ? "differ" : "agree"}">${
          differ ? x.trustDiffer.replace("{n}", String(differ)).replace("{total}", String(checks.length)) : x.trustAgree.replace("{same}", String(checks.length)).replace("{total}", String(checks.length))
        }</span><span class="${dnssec ? "agree" : "muted"}">${dnssec ? x.trustDnssec : x.trustNoDnssec}</span><span class="${ctDown ? "differ" : ctPending ? "muted" : "agree"}">${ctDown ? x.trustCtDown : ctPending ? x.trustCtPending : x.trustCt}</span>`;
  const actionText = actions === 0 ? x.metricActionsNone : actions === 1 ? x.metricActionsOne : x.metricActionsValue.replace("{n}", String(actions));
  return `
    <div class="metrics">
      <div class="metric"><span>${x.metricControls}</span><strong>${score.total ? x.metricControlsValue.replace("{ok}", String(score.passed)).replace("{total}", String(score.total)) : x.metricNotEvaluable}</strong>${
        score.unverified ? `<span class="muted">${x.metricUnverified.replace("{n}", String(score.unverified))}</span>` : ""
      }${score.notApplicable ? `<span class="muted">${x.metricNa.replace("{n}", String(score.notApplicable))}</span>` : ""}${score.extrasTotal ? `<span class="muted">${x.metricExtras.replace("{n}", String(score.extras)).replace("{total}", String(score.extrasTotal))}</span>` : ""}</div>
      <div class="metric${actions ? " has-actions" : ""}"><span>${x.metricActions}</span><strong>${actionText}</strong></div>
      <div class="metric trust"><span>${x.metricTrust}</span>${trust}</div>
    </div>`;
}

const SEV_ORDER = ["high", "medium", "low"];

/** Controls that need action, most severe first; each link opens its control. */
function renderPlan(groups: ControlGroup[], ctx: MessageContext): string {
  const x = CTEXT[lang];
  const items = groups
    .flatMap((g) => g.controls.filter(needsAction).map((c) => ({ c, g })))
    .sort((a, b) => SEV_ORDER.indexOf(severityOf(a.c)) - SEV_ORDER.indexOf(severityOf(b.c)) || (a.c.state === b.c.state ? 0 : a.c.state === "fail" ? -1 : 1));
  if (!items.length) return `<section class="card plan plan-clear"><h3>${x.plan}</h3><p>${x.planNone}</p></section>`;
  return `
    <section class="card plan" aria-labelledby="h-plan">
      <h3 id="h-plan">${x.plan} <span class="todo-count">${items.length}</span></h3>
      <ol>
        ${items
          .map(({ c, g }) => {
            const head = headlineOf(c);
            return `<li class="st-${c.state}"><a href="#c-${c.id}" data-open-control="${c.id}">
              <span class="ctl-icon">${ICON[c.state]}</span>
              <span class="plan-name">${x.controls[c.id] ?? c.id}</span>
              <span class="plan-title">${rich(message(lang, head.id, head.params, ctx).title)}</span>
              <span class="sev sev-${severityOf(c)}">${x.severity[severityOf(c)]}</span>
              <span class="plan-group">${(hasGap(c) ? (riskOf(c.id, false, lang)?.techniques ?? []).map((t) => t.id).join(" · ") : "") || x.groups[g.id]}</span></a></li>`;
          })
          .join("")}
      </ol>
    </section>`;
}

/** Every DNS record collected, for whoever wants to read them all at once. */
function renderRecords(report: Report): string {
  const t = uiText(lang);
  const rows = report.sections.flatMap((s) => s.records);
  if (!rows.length) return "";
  return `
    <section class="card">
      <details class="records"><summary>${CTEXT[lang].records} (${rows.length})</summary>
        <div class="table-wrap"><table>
          <thead><tr><th>${t.columns.name}</th><th>${t.columns.type}</th><th>${t.columns.ttl}</th><th>${t.columns.data}</th></tr></thead>
          <tbody>${rows.map((r) => `<tr><td>${escapeHtml(r.name)}</td><td>${r.type}</td><td>${r.ttl ?? ""}</td><td class="data">${escapeHtml(r.data)}</td></tr>`).join("")}</tbody>
        </table></div>
      </details>
    </section>`;
}

/** Country code (ISO 3166) to its name in the current language. */
function countryName(code: string): string {
  try {
    return `${new Intl.DisplayNames([lang === "es" ? "es-ES" : "en-GB"], { type: "region" }).of(code.toUpperCase()) ?? code} (${code.toUpperCase()})`;
  } catch {
    return code;
  }
}

/** Geolocation of an address (RIPEstat): a country, or several for anycast and CDNs. */
function locationText(code?: string): string | undefined {
  if (!code) return undefined;
  return code === "multi" ? uiText(lang).idLocationMulti : countryName(code);
}

/** Links to other tools for the same target; they open only when clicked. */
function renderExternal(report: Report): string {
  const links = externalLinks(report, lang);
  if (!links.length) return "";
  const { title, note } = externalTitle(lang);
  return `
    <section class="external" aria-labelledby="h-external">
      <h3 id="h-external">${escapeHtml(title)}</h3>
      <p class="external-note">${escapeHtml(note)}</p>
      <ul>${links
        .map((l) => `<li><a href="${escapeHtml(l.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(l.name)}</a> <span>${escapeHtml(l.what)}</span></li>`)
        .join("")}</ul>
    </section>`;
}

/**
 * "Who it is": the first thing the report answers. For an IP, its reverse name,
 * block holder and the network announcing it; for a domain, holder, registrar and
 * where its DNS, mail and website live. Only data found by the queries is shown.
 */
/** Rows of the "who it is" card, also used by the Markdown copy. */
function identityRows(report: Report): Array<[string, string]> {
  const t = uiText(lang);
  const id = report.identity ?? {};
  const rows: Array<[string, string]> = [];
  const add = (label: string, value: string | undefined) => {
    if (value) rows.push([label, value]);
  };
  const date = (iso?: string) =>
    iso ? new Date(`${iso}T00:00:00Z`).toLocaleDateString(lang === "es" ? "es-ES" : "en-GB", { timeZone: "UTC" }) : undefined;

  if (report.kind === "ip") {
    if (id.special) rows.push([t.idTitle, t.idSpecial]);
    // The reverse name goes in the headline; without one, say so in the list.
    if (!id.ptr && !id.special) add(t.idPtr, "—");
    add(t.idOwnerIp, id.holder);
    add(t.idAnnouncedBy, id.asn ? `AS${id.asn} · ${id.asHolder ?? ""}${id.prefix ? ` · ${id.prefix}` : ""}` : undefined);
    add(t.idNetwork, [id.network, id.range].filter(Boolean).join(" · ") || undefined);
    add(t.idCountry, id.country ? countryName(id.country) : undefined);
    add(t.idLocation, locationText(id.location));
  } else {
    add(t.idHolder, id.holder ?? (id.holderRedacted ? t.idHolderRedacted : id.registrar ? t.idHolderUnknown : undefined));
    add(t.idRegistrar, id.registrar);
    add(t.idCreated, date(id.created));
    if (id.registeredDomain && id.registeredDomain !== report.query) add(t.idRegisteredDomain, id.registeredDomain);
    // A recognised provider, or else the published names as they are.
    const list = (hosts?: string[]) => (hosts?.length ? hosts.slice(0, 2).join(", ") + (hosts.length > 2 ? "…" : "") : undefined);
    add(t.idDns, id.dnsProvider ?? list(id.nsHosts));
    add(t.idMail, id.noMail ? t.idNoMail : (id.mailProvider ?? list(id.mxHosts)));
    add(t.idWeb, id.cdn ? `${id.cdn} (proxy/CDN) · AS${id.hostingAsn ?? "?"}` : id.hostingHolder ? `${id.hostingHolder} · AS${id.hostingAsn ?? "?"}` : undefined);
    add(t.idLocationWeb, locationText(id.location));
  }
  if (report.kind === "ip" && id.ptr) rows.unshift([t.idPtr, id.ptr]);
  return rows;
}

function renderIdentity(report: Report): string {
  const t = uiText(lang);
  const id = report.identity ?? {};
  // The reverse name goes in the headline, not in the list.
  const rows = identityRows(report).filter(([k]) => !(report.kind === "ip" && id.ptr && k === t.idPtr));
  if (!rows.length) return "";
  const headline = report.kind === "ip" && id.ptr ? `<span class="identity-name">→ ${escapeHtml(id.ptr)}</span>` : "";
  return `
    <div class="identity" aria-label="${t.idTitle}">
      ${headline}
      <dl>${rows.map(([k, v]) => `<div><dt>${escapeHtml(k)}</dt><dd>${escapeHtml(v)}</dd></div>`).join("")}</dl>
    </div>`;
}

/** One line saying where the data came from. */
function renderSources(report: Report): string {
  const t = uiText(lang);
  const names: Record<string, string> = { cloudflare: "Cloudflare", google: "Google" };
  const primary = report.resolverCheck?.[0]?.providers[0] ?? lastRaw.find((e) => e.source === "cloudflare" || e.source === "google")?.source ?? "cloudflare";
  const other = primary === "cloudflare" ? "google" : "cloudflare";
  // The cross-check only runs for domains; for an IP the line does not mention it.
  const template = report.resolverCheck?.length ? t.sourcesLine : t.sourcesLineNoCheck;
  const line = template.replace("{count}", String(lastRaw.length)).replace("{primary}", names[primary] ?? primary).replace("{other}", names[other] ?? other);
  return `<p class="sources">${escapeHtml(line)}</p>`;
}

function renderVerdicts(report: Report): string {
  const t = uiText(lang);
  const list = verdicts(report);
  if (!list.length) return "";
  return `
    <div class="verdicts">
      ${list
        .map((v) => {
          const vt = verdictText(lang, v);
          return `
            <a class="verdict l-${v.level}" href="#g-${VERDICT_GROUP[v.area]}">
              <div class="verdict-head"><span class="verdict-area">${escapeHtml(vt.title)}</span><span class="verdict-level">${t.levels[v.level]}</span></div>
              <p>${rich(vt.text)}</p>
            </a>`;
        })
        .join("")}
    </div>`;
}

/** DNS provider detected from NS, so the advice names the user's panel. */
function contextOf(report: Report): MessageContext {
  const dnsProvider = report.sections.flatMap((sec) => sec.findings).find((f) => f.id === "dns.provider")?.params?.provider;
  return typeof dnsProvider === "string" ? { dnsProvider } : {};
}

const CODE_ICON = `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m8 7-5 5 5 5M16 7l5 5-5 5" /></svg>`;
const BACK_ICON = `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M20 12H4M10 6l-6 6 6 6" /></svg>`;

/** The same actions on the report and on the raw data: switch view, copy and download. */
function toolbar(): string {
  const t = uiText(lang);
  const toggle =
    view === "raw"
      ? `<button type="button" class="btn-raw" data-act="report">${BACK_ICON}${t.rawBack}</button>`
      : `<button type="button" class="btn-raw" data-act="raw">${CODE_ICON}${t.sourcesOpen}</button>`;
  return `
    <div class="toolbar">
      <div class="actions">
        ${toggle}
        ${desktop ? "" : `<button type="button" class="btn-ghost" data-act="link">${t.share}</button>`}
        <button type="button" class="btn-ghost" data-act="md" title="${escapeHtml(t.copyMdHint)}">${t.copyMd}</button>
        <button type="button" class="btn-ghost" data-act="json" title="${escapeHtml(t.jsonHint)}">${t.rawCopy}</button>
        <button type="button" class="btn-ghost" data-act="download" title="${escapeHtml(t.jsonHint)}">${t.exportJson}</button>
        ${view === "report" ? `<button type="button" class="btn-ghost" data-act="print"${completing ? " disabled" : ""}>${desktop ? t.savePdf : t.printReport}</button>` : ""}
      </div>
    </div>`;
}

/** Everything the audit collected: the report and every request with its original response. */
function fullJson(report: Report): string {
  return JSON.stringify({ query: report.query, generatedAt: report.generatedAt, report, requests: lastRaw }, null, 2);
}

function wireToolbar(root: HTMLElement, report: Report): void {
  const t = uiText(lang);
  const flash = (btn: HTMLButtonElement, text: string) => {
    const label = btn.innerHTML;
    btn.textContent = text;
    setTimeout(() => (btn.innerHTML = label), 2000);
  };
  const copy = async (btn: HTMLButtonElement, text: string, done: string) => {
    try {
      await navigator.clipboard.writeText(text);
      flash(btn, done);
    } catch {
      /* clipboard unavailable: the download still works */
    }
  };
  const on = (act: string, fn: (btn: HTMLButtonElement) => void) =>
    root.querySelector<HTMLButtonElement>(`.toolbar [data-act="${act}"]`)?.addEventListener("click", (e) => fn(e.currentTarget as HTMLButtonElement));

  on("raw", () => showView("raw"));
  on("report", () => showView("report"));
  on("link", (btn) => void copy(btn, location.href, t.copied));
  on("md", (btn) => void copy(btn, reportMarkdown(report, lang, identityRows(report), contextOf(report), location.href), t.copiedShort));
  on("json", (btn) => void copy(btn, fullJson(report), t.copiedShort));
  // The client report is a document of its own, laid out for A4: it is placed in the
  // page only while printing, and the browser's "Save as PDF" turns it into a file.
  on("print", (btn) => (desktop ? void savePdf(btn) : window.print()));
  on("download", () => {
    const blob = new Blob([fullJson(report)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `domain-auditor-${report.query.replace(/[^a-z0-9.-]/gi, "_")}.json`;
    a.click();
    URL.revokeObjectURL(a.href);
  });
}

function renderReport(report: Report): void {
  const t = uiText(lang);
  const x = CTEXT[lang];
  const ctx = contextOf(report);
  const groups = buildControls(report);
  const when = new Date(report.generatedAt).toLocaleString(lang === "es" ? "es-ES" : "en-GB");
  const el = document.querySelector<HTMLDivElement>("#report")!;
  el.innerHTML = `
    <section class="card" aria-labelledby="h-summary">
      <div class="summary-head">
        <div>
          <h2 id="h-summary">${escapeHtml(report.query)}</h2>
          <div class="meta">${t.generated}: ${escapeHtml(when)}</div>
        </div>
      </div>
      ${toolbar()}
      ${renderVerdicts(report)}
      ${renderMetrics(groups, report)}
      ${renderChanges(report)}
      ${renderIdentity(report)}
      <div class="filter-bar">
        <span class="filter-label">${t.filterShow}</span>
        <button type="button" class="chip" data-show="all" aria-pressed="true">${x.showAll}</button>
        <button type="button" class="chip" data-show="actions" aria-pressed="false">${x.showActions}</button>
      </div>
    </section>
    ${renderPlan(groups, ctx)}
    <section class="card context-card">
      ${renderExternal(report)}
      ${renderSources(report)}
      <p class="caveat">${escapeHtml(t.caveat)}</p>
    </section>
    ${groups.map((g) => renderGroup(g, report, ctx)).join("")}
    ${renderRecords(report)}
    <p class="attack-notice">${escapeHtml(ATTACK_NOTICE)}</p>`;

  el.querySelectorAll<HTMLButtonElement>("button[data-recheck]").forEach((btn) =>
    btn.addEventListener("click", () => void recheck(btn.dataset.recheck ?? "", btn)),
  );
  el.querySelector<HTMLButtonElement>("button[data-forget]")?.addEventListener("click", (e) => {
    forget(report.query);
    previous = null;
    (e.currentTarget as HTMLButtonElement).textContent = t.forgotten;
  });

  // "Only with action" hides controls that are fine, and groups left empty.
  el.querySelectorAll<HTMLButtonElement>("button[data-show]").forEach((btn) =>
    btn.addEventListener("click", () => {
      const only = btn.dataset.show === "actions";
      el.classList.toggle("only-actions", only);
      el.querySelectorAll<HTMLButtonElement>("button[data-show]").forEach((b) => b.setAttribute("aria-pressed", String(b === btn)));
      el.querySelectorAll<HTMLElement>(".ctl-group").forEach((g) => {
        g.hidden = only && !g.querySelector('.control[data-state="fail"], .control[data-state="warn"]');
      });
    }),
  );
  el.querySelectorAll<HTMLAnchorElement>("a[data-open-control]").forEach((a) =>
    a.addEventListener("click", (e) => {
      e.preventDefault();
      revealControl(a.dataset.openControl ?? "");
    }),
  );
  el.querySelectorAll<HTMLButtonElement>("button[data-raw-filter]").forEach((btn) =>
    btn.addEventListener("click", () => openRaw(btn.dataset.rawFilter ?? "")),
  );

  // Trying a DKIM selector re-runs the audit with it added.
  el.querySelectorAll<HTMLFormElement>("form[data-dkim-form]").forEach((form) =>
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      const input = form.querySelector("input")!;
      const sel = cleanSelector(input.value);
      if (!sel) {
        form.querySelector(".dkim-msg")!.textContent = t.dkimInvalid;
        return;
      }
      dkimSelectors = [...new Set([...dkimSelectors, sel])];
      void run(report.query);
    }),
  );

  // Mailbox fields fill `{mailbox}` in the values of their own suggestion box.
  el.querySelectorAll<HTMLInputElement>("input[data-mailbox]").forEach((input) =>
    input.addEventListener("input", () => {
      const box = input.closest(".suggest")!;
      const mailbox = input.value.trim();
      const valid = MAILBOX_RE.test(mailbox);
      box.querySelectorAll<HTMLElement>("[data-slot=mailbox]").forEach((slot) => {
        slot.textContent = valid ? mailbox : t.mailboxSlot;
        slot.classList.toggle("filled", valid);
      });
      box.querySelectorAll<HTMLButtonElement>("button[data-needs-mailbox]").forEach((btn) => (btn.disabled = !valid));
    }),
  );

  el.querySelectorAll<HTMLButtonElement>("button.copy").forEach((btn) =>
    btn.addEventListener("click", async () => {
      try {
        const mailbox = btn.closest(".suggest")?.querySelector<HTMLInputElement>("input[data-mailbox]")?.value.trim() ?? "";
        await navigator.clipboard.writeText((btn.dataset.copy ?? "").replace("{mailbox}", mailbox));
        btn.textContent = t.copiedShort;
        setTimeout(() => (btn.textContent = t.copy), 1800);
      } catch {
        /* clipboard unavailable: the value can still be selected by hand */
      }
    }),
  );

  wireToolbar(el, report);
}

/** Opens a control (showing everything again if filtered) and scrolls to it. */
function revealControl(id: string): void {
  const el = document.querySelector<HTMLElement>("#report")!;
  el.querySelector<HTMLButtonElement>('button[data-show="all"]')?.click();
  const target = document.getElementById(`c-${id}`) as HTMLDetailsElement | null;
  if (!target) return;
  target.open = true;
  target.scrollIntoView({ behavior: "smooth", block: "start" });
  target.classList.remove("flash");
  void target.offsetWidth;
  target.classList.add("flash");
}

/** Raw data view filtered to one control's queries, with the first match open. */
function openRaw(filter: string): void {
  showView("raw");
  const input = document.querySelector<HTMLInputElement>("#raw-filter");
  if (!input) return;
  input.value = filter;
  input.dispatchEvent(new Event("input"));
  const first = document.querySelector<HTMLDetailsElement>(".raw-entry:not([hidden])");
  if (first) first.open = true;
}

function searchItems(): PaletteItem[] {
  const t = uiText(lang);
  const x = CTEXT[lang];
  const items: PaletteItem[] = [];
  if (lastReport) {
    const ctx = contextOf(lastReport);
    for (const g of buildControls(lastReport)) {
      for (const c of g.controls) {
        const name = x.controls[c.id] ?? c.id;
        const titles = c.findings.map(({ f }) => message(lang, f.id, f.params, ctx));
        items.push({
          label: name,
          hint: `${x.states[c.state]} · ${x.groups[g.id]}`,
          group: t.searchGroupSections,
          // Ids and texts of its findings, so "p=reject" or "rua" finds DMARC.
          keywords: `${c.id} ${c.findings.map(({ f }) => f.id.replace(/[.-]/g, " ")).join(" ")} ${titles.map((m) => `${m.title} ${m.detail ?? ""}`).join(" ")}`,
          run: () => revealControl(c.id),
        });
        c.findings.forEach(({ f }, i) => {
          const m = titles[i]!;
          items.push({
            label: m.title,
            hint: `${t.status[f.status]} · ${name}`,
            group: t.searchGroupReport,
            keywords: `${f.id.replace(/[.-]/g, " ")} ${m.detail ?? ""} ${m.tech ?? ""}`,
            run: () => revealControl(c.id),
          });
        });
      }
    }
  }
  return [...items, ...wikiItems(lang, (id) => location.assign(`/wiki/?lang=${lang}#${id}`))];
}

const palette = initPalette(() => lang, searchItems);

shell();
const initial = new URLSearchParams(location.search).get("q");
if (initial) {
  document.querySelector<HTMLInputElement>("#q")!.value = initial;
  void run(initial);
} else {
  document.querySelector<HTMLInputElement>("#q")!.focus();
}
