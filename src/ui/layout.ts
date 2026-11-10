/** Shared header, footer, language switch and HTML helpers for both pages. */
import { desktop } from "../desktop";
import { detectLang, uiText, type Lang } from "../i18n";

export const REPO_URL = "https://github.com/FelixLlorenteS/domain-auditor";
export const AUTHOR_URL = "https://felixllorente.com";

export function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}

/** Escapes the text and turns `code` spans into <code>. */
export function rich(s: string): string {
  return escapeHtml(s).replace(/`([^`]+)`/g, "<code>$1</code>");
}

export type Page = "audit" | "raw" | "wiki";

export function header(lang: Lang, page: Page): string {
  const t = uiText(lang);
  const current = (p: Page) => (p === page ? ' aria-current="page"' : "");
  return `
    <header class="site-header">
      <nav class="navbar" aria-label="Domain Auditor">
        <a class="brand" href="/">
          <svg class="brand-mark" viewBox="0 0 32 32" aria-hidden="true"><path d="M7 11l5 5-5 5M15 21h10" /></svg>
          <span>Domain<b>Auditor</b></span>
          ${desktop ? `<span class="desktop-badge" title="${escapeHtml(t.desktopBadgeHint)}">${t.desktopBadge}</span>` : ""}
        </a>
        <div class="nav-links">
          <a href="/" id="nav-audit"${current("audit")}>${t.navAudit}</a>
          <a href="/?view=raw" id="nav-raw"${current("raw")}>${t.navRaw}</a>
          <a href="/wiki/"${current("wiki")}>${t.navWiki}</a>
          <a href="${REPO_URL}" rel="noopener">GitHub</a>
        </div>
        <div class="nav-actions">
          <button type="button" class="nav-search" id="search" aria-keyshortcuts="Control+K Meta+K">
            <svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="11" cy="11" r="7" /><path d="m20 20-3.5-3.5" /></svg>
            <span>${t.search}</span><kbd>Ctrl K</kbd>
          </button>
          <button type="button" class="nav-cta" id="lang" lang="${lang === "es" ? "en" : "es"}">${t.language}</button>
        </div>
      </nav>
    </header>`;
}

export function footer(lang: Lang): string {
  const t = uiText(lang);
  return `
    <footer class="site-footer">
      <span>${t.by} <a href="${AUTHOR_URL}" rel="noopener">Félix Llorente</a></span>
      <a href="${REPO_URL}" rel="noopener">${t.source} · MIT</a>
    </footer>`;
}

let headerObserver: ResizeObserver | null = null;

/**
 * The header stays fixed on top, like on felixllorente.com. Its real height (two
 * rows on phones) goes into `--header-h`, which anchors and sticky elements use
 * so nothing ends up hidden under it.
 */
export function trackHeaderHeight(): void {
  const el = document.querySelector<HTMLElement>(".site-header");
  if (!el) return;
  const set = () => document.documentElement.style.setProperty("--header-h", `${Math.ceil(el.getBoundingClientRect().height)}px`);
  set();
  headerObserver?.disconnect();
  headerObserver = new ResizeObserver(set);
  headerObserver.observe(el);
}

export function initialLang(): Lang {
  return detectLang();
}

export function saveLang(lang: Lang): void {
  try {
    localStorage.setItem("lang", lang);
  } catch {
    /* storage unavailable */
  }
  const url = new URL(location.href);
  url.searchParams.set("lang", lang);
  history.replaceState(null, "", url);
}

/** Adds `?lang=` to internal links so the language is kept between pages. */
export function keepLangInLinks(root: ParentNode, lang: Lang): void {
  root.querySelectorAll<HTMLAnchorElement>('a[href^="/"]').forEach((a) => {
    const url = new URL(a.getAttribute("href") ?? "/", location.origin);
    url.searchParams.set("lang", lang);
    a.setAttribute("href", `${url.pathname}${url.search}${url.hash}`);
  });
}
