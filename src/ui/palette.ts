/**
 * Command palette (Ctrl/Cmd + K), like the one on felixllorente.com: filters by
 * every typed word over accent-free, lower-case text, with keyboard navigation.
 */
import { uiText, type Lang } from "../i18n";
import { escapeHtml, rich } from "./layout";

export interface PaletteItem {
  label: string;
  hint?: string;
  group: string;
  /** Extra words to match: ids, record types, technical detail. */
  keywords?: string;
  run: () => void;
}

export function normalize(text: string): string {
  return text
    .normalize("NFD")
    .replace(/[̀-ͯ]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9@.:_-]+/g, " ")
    .trim();
}

/** Items whose text contains every term of the query. */
export function filterItems(items: PaletteItem[], query: string): PaletteItem[] {
  const terms = normalize(query).split(" ").filter(Boolean);
  if (!terms.length) return items;
  return items.filter((item) => {
    const text = normalize(`${item.label} ${item.hint ?? ""} ${item.keywords ?? ""} ${item.group}`);
    return terms.every((term) => text.includes(term));
  });
}

let dialog: HTMLDivElement | null = null;

export function initPalette(getLang: () => Lang, getItems: () => PaletteItem[]): { open: () => void } {
  let active = 0;
  let results: PaletteItem[] = [];
  let restoreFocus: HTMLElement | null = null;

  function close(): void {
    dialog?.remove();
    dialog = null;
    document.body.style.overflow = "";
    restoreFocus?.focus();
  }

  function render(list: HTMLUListElement, query: string): void {
    const t = uiText(getLang());
    results = filterItems(getItems(), query);
    active = Math.min(active, Math.max(results.length - 1, 0));
    if (!results.length) {
      list.innerHTML = `<li class="palette-empty">${t.searchEmpty}</li>`;
      return;
    }
    let index = -1;
    const groups = [...new Set(results.map((r) => r.group))];
    list.innerHTML = groups
      .map(
        (g) => `
        <li class="palette-group" role="presentation">${escapeHtml(g)}</li>
        ${results
          .filter((r) => r.group === g)
          .map((r) => {
            index = results.indexOf(r);
            return `<li role="option" id="pal-${index}" data-index="${index}" aria-selected="${index === active}" class="palette-item">
                <span class="palette-label">${rich(r.label)}</span>
                ${r.hint ? `<span class="palette-hint">${rich(r.hint)}</span>` : ""}
              </li>`;
          })
          .join("")}`,
      )
      .join("");
    list.querySelector(`[data-index="${active}"]`)?.scrollIntoView({ block: "nearest" });
  }

  function open(): void {
    if (dialog) return;
    const t = uiText(getLang());
    restoreFocus = document.activeElement as HTMLElement;
    dialog = document.createElement("div");
    dialog.className = "palette-backdrop";
    dialog.innerHTML = `
      <div class="palette" role="dialog" aria-modal="true" aria-label="${t.searchLabel}">
        <div class="palette-input">
          <svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="11" cy="11" r="7" /><path d="m20 20-3.5-3.5" /></svg>
          <input type="text" placeholder="${escapeHtml(t.searchPlaceholder)}" aria-label="${escapeHtml(t.searchPlaceholder)}"
            role="combobox" aria-expanded="true" aria-controls="palette-list" autocomplete="off" spellcheck="false" />
          <kbd>Esc</kbd>
        </div>
        <ul id="palette-list" role="listbox"></ul>
        <p class="palette-foot">${t.searchHint}</p>
      </div>`;
    document.body.append(dialog);
    document.body.style.overflow = "hidden";
    const input = dialog.querySelector("input")!;
    const list = dialog.querySelector<HTMLUListElement>("#palette-list")!;
    active = 0;
    render(list, "");
    input.focus();

    const choose = (i: number) => {
      const item = results[i];
      if (!item) return;
      close();
      item.run();
    };
    input.addEventListener("input", () => {
      active = 0;
      render(list, input.value);
    });
    dialog.addEventListener("keydown", (e) => {
      if (e.key === "Escape") {
        e.preventDefault();
        close();
      } else if (e.key === "ArrowDown" || e.key === "ArrowUp") {
        e.preventDefault();
        if (!results.length) return;
        active = (active + (e.key === "ArrowDown" ? 1 : -1) + results.length) % results.length;
        render(list, input.value);
        input.setAttribute("aria-activedescendant", `pal-${active}`);
      } else if (e.key === "Enter") {
        e.preventDefault();
        choose(active);
      }
    });
    list.addEventListener("click", (e) => {
      const li = (e.target as HTMLElement).closest<HTMLElement>("[data-index]");
      if (li) choose(Number(li.dataset.index));
    });
    dialog.addEventListener("mousedown", (e) => {
      if (e.target === dialog) close();
    });
  }

  window.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
      e.preventDefault();
      if (dialog) close();
      else open();
    }
  });
  return { open };
}
