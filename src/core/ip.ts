/** IP address helpers: validation, normalisation, reverse names and special ranges. */

const V4_OCTET = "(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)";
const V4_RE = new RegExp(`^${V4_OCTET}(\\.${V4_OCTET}){3}$`);

export function isIPv4(s: string): boolean {
  return V4_RE.test(s);
}

/** Returns the canonical (compressed, lower-case) form, or null if `s` is not IPv6. */
export function normalizeIPv6(s: string): string | null {
  if (!s.includes(":") || !/^[0-9a-fA-F:.]+$/.test(s)) return null;
  try {
    const host = new URL(`http://[${s}]/`).hostname;
    return host.slice(1, -1);
  } catch {
    return null;
  }
}

/** Expands an IPv6 address to its 8 groups of 4 hex digits. */
export function expandIPv6(s: string): string[] {
  const canonical = normalizeIPv6(s);
  if (!canonical) throw new Error(`Invalid IPv6 address: ${s}`);
  const [head = "", tail] = canonical.split("::");
  const left = head ? head.split(":") : [];
  const right = tail !== undefined && tail !== "" ? tail.split(":") : [];
  const missing = tail === undefined ? 0 : 8 - left.length - right.length;
  return [...left, ...Array<string>(missing).fill("0"), ...right].map((g) => g.padStart(4, "0"));
}

export function reverseName(ip: string, version: 4 | 6): string {
  if (version === 4) return `${ip.split(".").reverse().join(".")}.in-addr.arpa`;
  const nibbles = expandIPv6(ip).join("").split("");
  return `${nibbles.reverse().join(".")}.ip6.arpa`;
}

function v4ToInt(ip: string): number {
  return ip.split(".").reduce((acc, o) => acc * 256 + Number(o), 0);
}

const V4_SPECIAL: Array<[string, number, string]> = [
  ["0.0.0.0", 8, "this-network"],
  ["10.0.0.0", 8, "private"],
  ["100.64.0.0", 10, "cgnat"],
  ["127.0.0.0", 8, "loopback"],
  ["169.254.0.0", 16, "link-local"],
  ["172.16.0.0", 12, "private"],
  ["192.0.2.0", 24, "documentation"],
  ["192.168.0.0", 16, "private"],
  ["198.18.0.0", 15, "benchmark"],
  ["198.51.100.0", 24, "documentation"],
  ["203.0.113.0", 24, "documentation"],
  ["224.0.0.0", 4, "multicast"],
  ["240.0.0.0", 4, "reserved"],
];

/** Returns the kind of special-purpose range the address belongs to, or null if it is public. */
export function specialRange(ip: string, version: 4 | 6): string | null {
  if (version === 4) {
    const n = v4ToInt(ip);
    for (const [base, bits, kind] of V4_SPECIAL) {
      const size = 2 ** (32 - bits);
      const start = v4ToInt(base);
      if (n >= start && n < start + size) return kind;
    }
    return null;
  }
  const groups = expandIPv6(ip);
  const first = parseInt(groups[0] ?? "0", 16);
  if (groups.every((g) => g === "0000")) return "unspecified";
  if (groups.slice(0, 7).every((g) => g === "0000") && groups[7] === "0001") return "loopback";
  if ((first & 0xfe00) === 0xfc00) return "private";
  if ((first & 0xffc0) === 0xfe80) return "link-local";
  if ((first & 0xff00) === 0xff00) return "multicast";
  if (groups[0] === "2001" && groups[1] === "0db8") return "documentation";
  if (groups.slice(0, 5).every((g) => g === "0000") && groups[5] === "ffff") {
    const v4 = [groups[6], groups[7]]
      .flatMap((g) => [parseInt((g ?? "0").slice(0, 2), 16), parseInt((g ?? "0").slice(2), 16)])
      .join(".");
    return specialRange(v4, 4) ?? "ipv4-mapped";
  }
  return null;
}
