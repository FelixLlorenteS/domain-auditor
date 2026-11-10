/** Wiki entries as search items, shared by the audit page and the wiki. */
import { uiText, type Lang } from "../i18n";
import type { PaletteItem } from "../ui/palette";
import { WIKI } from "./content";
import { EXTRA } from "./extra";

export function wikiItems(lang: Lang, go: (id: string) => void): PaletteItem[] {
  const t = uiText(lang);
  return [
    { label: t.wikiOverview, hint: t.wikiOverviewIntro, group: t.searchGroupWiki, keywords: "overview journeys", run: () => go("overview") },
    ...WIKI.map((e) => ({
      label: e.title[lang],
      hint: e.summary[lang],
      group: t.searchGroupWiki,
      // Both languages and the plain-language summary, so "firma" or "signature" both find DKIM.
      keywords: `${e.id} ${e.title.es} ${e.title.en} ${EXTRA[e.id]?.plain[lang] ?? ""}`,
      run: () => go(e.id),
    })),
  ];
}
