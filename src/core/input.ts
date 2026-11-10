import { isIPv4, normalizeIPv6 } from "./ip";
import type { Target } from "./types";

export class InputError extends Error {
  constructor(public readonly code: "empty" | "invalid") {
    super(code);
    this.name = "InputError";
  }
}

const LABEL_RE = /^(?!-)[a-z0-9_-]{1,63}(?<!-)$/;

/**
 * Turns what a person types (domain, URL, e-mail address, IPv4 or IPv6) into a target.
 * International domain names are converted to punycode.
 */
export function parseTarget(raw: string): Target {
  let s = raw.trim();
  if (!s) throw new InputError("empty");

  if (!s.includes("://") && s.includes("@")) s = s.slice(s.lastIndexOf("@") + 1);
  if (s.startsWith("[") && s.endsWith("]")) s = s.slice(1, -1);

  if (isIPv4(s)) return { kind: "ip", ip: s, version: 4 };
  const v6 = normalizeIPv6(s);
  if (v6) return { kind: "ip", ip: v6, version: 6 };

  let host: string;
  try {
    host = new URL(s.includes("://") ? s : `http://${s}`).hostname;
  } catch {
    throw new InputError("invalid");
  }

  if (host.startsWith("[")) {
    const ip = normalizeIPv6(host.slice(1, -1));
    if (ip) return { kind: "ip", ip, version: 6 };
    throw new InputError("invalid");
  }
  if (isIPv4(host)) return { kind: "ip", ip: host, version: 4 };

  const name = host.replace(/\.$/, "").toLowerCase();
  const labels = name.split(".");
  if (name.length > 253 || labels.length < 2 || !labels.every((l) => LABEL_RE.test(l))) {
    throw new InputError("invalid");
  }
  if (/^\d+$/.test(labels[labels.length - 1] ?? "")) throw new InputError("invalid");
  return { kind: "domain", name };
}
