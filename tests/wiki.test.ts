import { describe, expect, it } from "vitest";
import { MESSAGES } from "../src/i18n";
import { GROUPS, WIKI, wikiAnchor } from "../src/wiki/content";
import { EXTRA } from "../src/wiki/extra";
import { JOURNEYS, RELATED } from "../src/wiki/links";

describe("wiki", () => {
  const ids = new Set(WIKI.map((e) => e.id));

  it("has unique ids and known groups", () => {
    expect(ids.size).toBe(WIKI.length);
    for (const e of WIKI) expect(Object.keys(GROUPS)).toContain(e.group);
  });

  it("is complete in both languages and links over HTTPS", () => {
    for (const e of WIKI) {
      expect(e.body.es.length).toBe(e.body.en.length);
      expect(e.checks.es.length).toBe(e.checks.en.length);
      expect(e.refs.length).toBeGreaterThan(0);
      for (const r of e.refs) expect(r.url).toMatch(/^https:\/\//);
    }
  });

  it("has a plain-language summary for every entry, in both languages", () => {
    for (const e of WIKI) {
      const extra = EXTRA[e.id];
      expect(extra?.plain.es, e.id).toBeTruthy();
      expect(extra?.plain.en, e.id).toBeTruthy();
      for (const table of extra?.tables ?? []) {
        expect(table.rows.es.length).toBe(table.rows.en.length);
        for (const row of [...table.rows.es, ...table.rows.en]) expect(row.length).toBe(table.cols.es.length);
      }
      expect(extra?.pitfalls?.es.length ?? 0).toBe(extra?.pitfalls?.en.length ?? 0);
    }
    expect(Object.keys(EXTRA).sort()).toEqual(WIKI.map((e) => e.id).sort());
  });

  it("links only to existing entries and connects every entry", () => {
    const linked = new Set<string>();
    for (const j of JOURNEYS) for (const step of j.steps) for (const id of step.ids) {
      expect(ids.has(id), `journey ${j.id} → ${id}`).toBe(true);
      linked.add(id);
    }
    for (const [from, list] of Object.entries(RELATED)) {
      expect(ids.has(from), from).toBe(true);
      for (const r of list) {
        expect(ids.has(r.id), `${from} → ${r.id}`).toBe(true);
        expect(r.id).not.toBe(from);
        expect(r.why.es && r.why.en).toBeTruthy();
      }
    }
    // Every entry has related links, and every entry but the tool's own appears in a journey.
    for (const e of WIKI) expect(RELATED[e.id]?.length, e.id).toBeGreaterThan(0);
    for (const e of WIKI.filter((x) => x.group !== "tool" && x.id !== "special")) expect(linked.has(e.id), e.id).toBe(true);
  });

  it("explains every finding", () => {
    for (const id of Object.keys(MESSAGES.es)) {
      const anchor = wikiAnchor(id);
      expect(anchor, id).toBeDefined();
      expect(ids.has(anchor ?? ""), `${id} → ${anchor}`).toBe(true);
    }
  });
});
