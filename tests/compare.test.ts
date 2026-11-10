import { describe, expect, it } from "vitest";
import type { Finding, Report } from "../src/core/types";
import { compareReports } from "../src/ui/compare";
import { forget, MAX_ENTRIES, previousReport, saveReport } from "../src/ui/history";

const report = (findings: Finding[], query = "example.com", at = "2026-11-01T00:00:00.000Z"): Report => ({
  query,
  kind: "domain",
  generatedAt: at,
  sections: [{ id: "mail", findings, records: [] }],
});

describe("compareReports", () => {
  it("says what got better and what got worse, worst first", () => {
    const before = report([
      { id: "dmarc.found", status: "ok" },
      { id: "dmarc.p-none", status: "warn" },
      { id: "spf.found", status: "ok" },
      { id: "spf.lookups", status: "ok" },
    ]);
    const after = report([
      { id: "dmarc.found", status: "ok" },
      { id: "dmarc.p-reject", status: "ok" },
      { id: "spf.found", status: "ok" },
      { id: "spf.syntax", status: "fail" },
    ]);
    const { changes, before: b, after: a } = compareReports(before, after);
    expect(changes.map((c) => [c.id, c.kind, c.from, c.to])).toEqual([
      ["spf", "worse", "ok", "fail"],
      ["dmarc", "better", "warn", "ok"],
    ]);
    expect(changes[0]?.added).toEqual(["spf.syntax"]);
    expect(changes[1]?.removed).toEqual(["dmarc.p-none"]);
    expect([b.passed, a.passed]).toEqual([1, 1]);
  });

  it("does not call missing data a change (crt.sh down in one of the audits)", () => {
    const before = report([{ id: "ct.issuers-caa-ok", status: "ok" }, { id: "spf.found", status: "ok" }]);
    const after = report([{ id: "ct.unavailable", status: "info" }, { id: "spf.found", status: "ok" }]);
    expect(compareReports(before, after).changes).toEqual([]);
  });

  it("finds no change between identical reports", () => {
    const r = report([{ id: "spf.found", status: "ok" }]);
    expect(compareReports(r, r).changes).toEqual([]);
  });
});

/** An in-memory Storage, as localStorage behaves. */
function memory(): Storage {
  const m = new Map<string, string>();
  return {
    get length() {
      return m.size;
    },
    clear: () => m.clear(),
    getItem: (k) => m.get(k) ?? null,
    key: (i) => [...m.keys()][i] ?? null,
    removeItem: (k) => void m.delete(k),
    setItem: (k, v) => void m.set(k, v),
  };
}

describe("history", () => {
  it("keeps the last report of each target, at most the newest ones", () => {
    const s = memory();
    for (let i = 0; i < MAX_ENTRIES + 3; i++) saveReport(report([], `d${i}.example`, `2026-11-01T00:00:${String(i).padStart(2, "0")}.000Z`), s);
    expect(previousReport("d0.example", s)).toBeUndefined();
    expect(previousReport(`d${MAX_ENTRIES + 2}.example`, s)?.query).toBe(`d${MAX_ENTRIES + 2}.example`);
    forget(`d${MAX_ENTRIES + 2}.example`, s);
    expect(previousReport(`d${MAX_ENTRIES + 2}.example`, s)).toBeUndefined();
    forget(undefined, s);
    expect(s.length).toBe(0);
  });

  it("works without storage at all (private window, blocked)", () => {
    const broken = { getItem: () => { throw new Error("blocked"); }, setItem: () => { throw new Error("blocked"); } } as unknown as Storage;
    expect(() => saveReport(report([]), broken)).not.toThrow();
    expect(previousReport("example.com", broken)).toBeUndefined();
  });
});
