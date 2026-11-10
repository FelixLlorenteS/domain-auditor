/**
 * The last report of each target, kept only in this browser (localStorage), to
 * show what changed when the same domain is audited again. Nothing leaves the
 * browser, it can be wiped at any time, and every access is guarded: in a
 * private window or with storage blocked the page simply works without it.
 */
import type { Report } from "../core/types";

const KEY = "domain-auditor:history";
/** Targets kept; the oldest are dropped first. */
export const MAX_ENTRIES = 20;

type Store = Record<string, Report>;

function read(storage: Storage | undefined): Store {
  try {
    const raw = storage?.getItem(KEY);
    return raw ? (JSON.parse(raw) as Store) : {};
  } catch {
    return {};
  }
}

function write(storage: Storage | undefined, store: Store): void {
  try {
    storage?.setItem(KEY, JSON.stringify(store));
  } catch {
    /* full or blocked: history is a convenience, never required */
  }
}

const defaultStorage = (): Storage | undefined => {
  try {
    return globalThis.localStorage;
  } catch {
    return undefined;
  }
};

/** The report saved last time for this target, if any. */
export function previousReport(query: string, storage = defaultStorage()): Report | undefined {
  return read(storage)[query];
}

/** Saves a report as the latest one of its target, keeping at most MAX_ENTRIES targets. */
export function saveReport(report: Report, storage = defaultStorage()): void {
  const store = read(storage);
  delete store[report.query];
  store[report.query] = report;
  const keys = Object.keys(store).sort((a, b) => (store[a]!.generatedAt < store[b]!.generatedAt ? -1 : 1));
  for (const k of keys.slice(0, Math.max(0, keys.length - MAX_ENTRIES))) delete store[k];
  write(storage, store);
}

/** Forgets one target, or every one. */
export function forget(query?: string, storage = defaultStorage()): void {
  if (!query) {
    try {
      storage?.removeItem(KEY);
    } catch {
      /* nothing to forget */
    }
    return;
  }
  const store = read(storage);
  delete store[query];
  write(storage, store);
}
