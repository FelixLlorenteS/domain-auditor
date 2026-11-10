/**
 * Differences between two reports of the same target, control by control: what
 * got better, what got worse and what changed without a clear direction. It is
 * what "is it fixed yet?" and "what changed since last time" both need.
 */
import type { Report } from "../core/types";
import { buildControls, scoreOf, type ControlState, type Score } from "./controls";

export type ChangeKind = "better" | "worse" | "changed";

export interface ControlChange {
  id: string;
  from: ControlState;
  to: ControlState;
  kind: ChangeKind;
  /** Problems (warning or failure) that appeared or went away. */
  added: string[];
  removed: string[];
}

export interface ReportDiff {
  changes: ControlChange[];
  before: Score;
  after: Score;
}

/** Higher is better. States that pass no judgement sit in the middle. */
const RANK: Record<ControlState, number> = { fail: 0, warn: 1, unknown: 2, info: 2, optional: 2, na: 2, ok: 3 };

const problems = (findings: Array<{ f: { id: string; status: string } }>) =>
  new Set(findings.filter(({ f }) => f.status === "fail" || f.status === "warn").map(({ f }) => f.id));

export function compareReports(before: Report, after: Report): ReportDiff {
  const controls = (r: Report) => new Map(buildControls(r).flatMap((g) => g.controls).map((c) => [c.id, c]));
  const a = controls(before);
  const b = controls(after);
  const changes: ControlChange[] = [];
  for (const id of new Set([...a.keys(), ...b.keys()])) {
    const ca = a.get(id);
    const cb = b.get(id);
    // A control missing from one report (a source did not answer, as crt.sh often)
    // cannot be compared: absence of data is not a change in the domain.
    if (!ca || !cb) continue;
    // Nor can one still being checked (the first, partial report of an audit).
    if ([...ca.findings, ...cb.findings].some(({ f }) => f.id.endsWith(".pending"))) continue;
    const from: ControlState = ca.state;
    const to: ControlState = cb.state;
    const pa = problems(ca.findings);
    const pb = problems(cb.findings);
    const added = [...pb].filter((x) => !pa.has(x));
    const removed = [...pa].filter((x) => !pb.has(x));
    if (from === to && !added.length && !removed.length) continue;
    const delta = RANK[to] - RANK[from];
    // Going to or from "not verified" says nothing about the domain itself.
    const unverified = from === "unknown" || to === "unknown";
    const kind: ChangeKind = unverified
      ? "changed"
      : delta > 0 || (delta === 0 && removed.length && !added.length) ? "better" : delta < 0 || (delta === 0 && added.length && !removed.length) ? "worse" : "changed";
    changes.push({ id, from, to, kind, added, removed });
  }
  const order: Record<ChangeKind, number> = { worse: 0, changed: 1, better: 2 };
  changes.sort((x, y) => order[x.kind] - order[y.kind] || x.id.localeCompare(y.id));
  return { changes, before: scoreOf(before, buildControls(before)), after: scoreOf(after, buildControls(after)) };
}
