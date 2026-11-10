import { describe, expect, it } from "vitest";
import { expandIPv6, reverseName, specialRange } from "../src/core/ip";

describe("ip helpers", () => {
  it("expands IPv6", () => {
    expect(expandIPv6("2001:db8::1").join(":")).toBe("2001:0db8:0000:0000:0000:0000:0000:0001");
    expect(expandIPv6("::").every((g) => g === "0000")).toBe(true);
  });

  it("builds reverse names", () => {
    expect(reverseName("192.0.2.10", 4)).toBe("10.2.0.192.in-addr.arpa");
    expect(reverseName("2001:db8::1", 6)).toBe(`1.${"0.".repeat(23)}8.b.d.0.1.0.0.2.ip6.arpa`);
  });

  it("detects special ranges", () => {
    expect(specialRange("10.1.2.3", 4)).toBe("private");
    expect(specialRange("172.31.255.255", 4)).toBe("private");
    expect(specialRange("172.32.0.1", 4)).toBeNull();
    expect(specialRange("100.64.0.1", 4)).toBe("cgnat");
    expect(specialRange("8.8.8.8", 4)).toBeNull();
    expect(specialRange("::1", 6)).toBe("loopback");
    expect(specialRange("fd00::1", 6)).toBe("private");
    expect(specialRange("fe80::1", 6)).toBe("link-local");
    expect(specialRange("2001:db8::5", 6)).toBe("documentation");
    expect(specialRange("::ffff:c0a8:101", 6)).toBe("private");
    expect(specialRange("2606:4700::1111", 6)).toBeNull();
  });
});
