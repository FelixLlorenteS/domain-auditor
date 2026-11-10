import { describe, expect, it } from "vitest";
import { InputError, parseTarget } from "../src/core/input";

describe("parseTarget", () => {
  it.each([
    ["example.com", "example.com"],
    ["  Example.COM.  ", "example.com"],
    ["https://www.example.com/path?x=1", "www.example.com"],
    ["example.com:8443", "example.com"],
    ["user@example.org", "example.org"],
    ["mañana.es", "xn--maana-pta.es"],
  ])("reads %s as domain %s", (raw, name) => {
    expect(parseTarget(raw)).toEqual({ kind: "domain", name });
  });

  it.each([
    ["192.0.2.1", "192.0.2.1", 4],
    ["2001:DB8::1", "2001:db8::1", 6],
    ["[2001:db8::1]", "2001:db8::1", 6],
    ["http://[2001:db8::1]:8080/", "2001:db8::1", 6],
    ["http://198.51.100.7/", "198.51.100.7", 4],
  ])("reads %s as IP", (raw, ip, version) => {
    expect(parseTarget(raw)).toEqual({ kind: "ip", ip, version });
  });

  it.each(["", "   ", "localhost", "exa mple.com", "-bad.com", "256.1.1.1", "a..b"])("rejects %j", (raw) => {
    expect(() => parseTarget(raw)).toThrow(InputError);
  });
});
