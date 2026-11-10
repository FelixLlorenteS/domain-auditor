import "@fontsource-variable/jetbrains-mono";
import "@fontsource-variable/geist";
import "../style.css";

import { uiText, type Lang } from "../i18n";
import { escapeHtml, footer, header, initialLang, keepLangInLinks, rich, saveLang, trackHeaderHeight } from "../ui/layout";
import { GROUPS, WIKI, type WikiEntry, type WikiGroup } from "./content";
import { EXTRA, type WikiTable } from "./extra";
import { JOURNEYS, RELATED } from "./links";
import { initPalette } from "../ui/palette";
import { wikiItems } from "./search";

const TITLES = new Map(WIKI.map((e) => [e.id, e.title]));
const titleOf = (id: string) => escapeHtml(TITLES.get(id)?.[lang] ?? id);

let lang: Lang = initialLang();
// The content is rendered by script, so jump to the anchor once it exists.
const jumpToHash = () => document.getElementById(decodeURIComponent(location.hash.slice(1)))?.scrollIntoView({ behavior: "instant" });
const app = document.querySelector<HTMLDivElement>("#app")!;

function renderTable(table: WikiTable): string {
  return `
    <div class="table-wrap"><table class="wiki-table">
      <thead><tr>${table.cols[lang].map((c) => `<th>${escapeHtml(c)}</th>`).join("")}</tr></thead>
      <tbody>${table.rows[lang].map((row) => `<tr>${row.map((cell) => `<td>${rich(cell)}</td>`).join("")}</tr>`).join("")}</tbody>
    </table></div>`;
}

function renderEntry(e: WikiEntry): string {
  const t = uiText(lang);
  const extra = EXTRA[e.id];
  return `
    <article class="card wiki-entry" id="${e.id}" aria-labelledby="t-${e.id}">
      <p class="tag">// ${GROUPS[e.group][lang]}</p>
      <h2 id="t-${e.id}"><a class="anchor" href="#${e.id}">${escapeHtml(e.title[lang])}</a></h2>
      <p class="wiki-summary">${rich(e.summary[lang])}</p>
      ${extra ? `<div class="plain"><span>${t.wikiPlain}</span><p>${rich(extra.plain[lang])}</p></div>` : ""}
      <h3>${t.wikiHow}</h3>
      ${e.body[lang].map((p) => `<p>${rich(p)}</p>`).join("")}
      ${e.example ? `<h3>${t.wikiExample}</h3><pre><code>${escapeHtml(e.example)}</code></pre>` : ""}
      ${extra?.tables?.length ? `<h3>${t.wikiTable}</h3>${extra.tables.map(renderTable).join("")}` : ""}
      ${extra?.pitfalls ? `<h3>${t.wikiPitfalls}</h3><ul class="pitfalls">${extra.pitfalls[lang].map((x) => `<li>${rich(x)}</li>`).join("")}</ul>` : ""}
      ${
        RELATED[e.id]?.length
          ? `<h3>${t.wikiRelated}</h3><ul class="related">${RELATED[e.id]!
              .map((r) => `<li><a href="#${r.id}">${titleOf(r.id)}</a><span>${rich(r.why[lang])}</span></li>`)
              .join("")}</ul>`
          : ""
      }
      <h3>${t.wikiChecks}</h3>
      <ul>${e.checks[lang].map((c) => `<li>${rich(c)}</li>`).join("")}</ul>
      <h3>${t.wikiRefs}</h3>
      <ul class="refs">${e.refs
        .map((r) => {
          const label = r.section ? `${r.label}, ${lang === "es" ? "sección" : "section"} ${r.section}` : r.label;
          return `<li><a href="${r.url}" rel="noopener" target="_blank">${escapeHtml(label)} ↗</a></li>`;
        })
        .join("")}</ul>
    </article>`;
}

function renderJourneys(): string {
  const t = uiText(lang);
  return `
    <section class="journeys" id="overview" aria-labelledby="t-overview">
      <p class="tag">// ${t.wikiOverviewTag}</p>
      <h2 id="t-overview">${t.wikiOverview}</h2>
      <p class="journeys-intro">${escapeHtml(t.wikiOverviewIntro)}</p>
      <div class="journey-list">
        ${JOURNEYS.map(
          (j) => `
          <article class="card journey">
            <h3>${escapeHtml(j.title[lang])}</h3>
            <p>${rich(j.intro[lang])}</p>
            <ol>
              ${j.steps
                .map(
                  (s) => `
                <li>
                  <p>${rich(s.text[lang])}</p>
                  <div class="chips">${s.ids.map((id) => `<a href="#${id}">${titleOf(id)}</a>`).join("")}</div>
                </li>`,
                )
                .join("")}
            </ol>
          </article>`,
        ).join("")}
      </div>
    </section>`;
}

function render(): void {
  const t = uiText(lang);
  document.documentElement.lang = lang;
  document.title = `${t.wikiTitle} · Domain Auditor`;
  const groups = Object.keys(GROUPS) as WikiGroup[];
  const toc = groups
    .map(
      (g) => `
        <li><span>${GROUPS[g][lang]}</span>
          <ul>${WIKI.filter((e) => e.group === g)
            .map((e) => `<li><a href="#${e.id}">${escapeHtml(e.title[lang])}</a></li>`)
            .join("")}</ul>
        </li>`,
    )
    .join("");

  app.innerHTML = `
    <div class="glow" aria-hidden="true"></div>
    <div class="wrap">
      ${header(lang, "wiki")}
      <main>
        <section class="wiki-hero">
          <h1 class="hero-title small"><span>${t.wikiTitle}</span></h1>
          <p class="hero-sub">${escapeHtml(t.wikiIntro)}</p>
        </section>
        <div class="wiki-layout">
          <nav class="wiki-toc" aria-label="${t.wikiContents}">
            <p class="tag">// ${t.wikiContents}</p>
            <a class="toc-overview" href="#overview">${t.wikiOverview}</a>
            <ul>${toc}</ul>
          </nav>
          <div class="wiki-entries">${renderJourneys()}${WIKI.map(renderEntry).join("")}</div>
        </div>
      </main>
      ${footer(lang)}
    </div>`;
  keepLangInLinks(app, lang);
  trackHeaderHeight();
  document.querySelector("#search")!.addEventListener("click", () => palette.open());
  watchScroll();

  document.querySelector("#lang")!.addEventListener("click", () => {
    lang = lang === "es" ? "en" : "es";
    saveLang(lang);
    render();
    if (location.hash) jumpToHash();
  });
}

let stopWatching: (() => void) | null = null;

/**
 * Scroll-spy: highlights in the contents the entry being read (the last one whose
 * top has passed the upper third of the screen) and keeps it visible inside the
 * contents box.
 */
function watchScroll(): void {
  stopWatching?.();
  const toc = document.querySelector<HTMLElement>(".wiki-toc");
  if (!toc) return;
  const links = new Map([...toc.querySelectorAll<HTMLAnchorElement>('a[href^="#"]')].map((a) => [a.hash.slice(1), a]));
  const sections = [...document.querySelectorAll<HTMLElement>("#overview, .wiki-entry")];
  let currentId: string | undefined;
  let frame = 0;

  const update = () => {
    frame = 0;
    const headerH = document.querySelector(".site-header")?.getBoundingClientRect().height ?? 0;
    const line = headerH + (window.innerHeight - headerH) * 0.25;
    let current: string | undefined;
    for (const s of sections) {
      if (s.getBoundingClientRect().top <= line) current = s.id;
      else break;
    }
    if (current === currentId) return;
    currentId = current;
    links.forEach((a, id) => (id === current ? a.setAttribute("aria-current", "location") : a.removeAttribute("aria-current")));
    const link = current ? links.get(current) : undefined;
    if (link && toc.scrollHeight > toc.clientHeight) {
      toc.scrollTo({ top: link.offsetTop - toc.clientHeight / 2, behavior: "smooth" });
    }
  };
  const onScroll = () => {
    if (!frame) frame = requestAnimationFrame(update);
  };
  window.addEventListener("scroll", onScroll, { passive: true });
  window.addEventListener("resize", onScroll);
  update();
  stopWatching = () => {
    window.removeEventListener("scroll", onScroll);
    window.removeEventListener("resize", onScroll);
    cancelAnimationFrame(frame);
  };
}

const palette = initPalette(
  () => lang,
  () =>
    wikiItems(lang, (id) => {
      history.replaceState(null, "", `#${id}`);
      jumpToHash();
    }),
);

render();
if (location.hash) requestAnimationFrame(jumpToHash);
