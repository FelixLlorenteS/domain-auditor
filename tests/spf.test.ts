import { describe, expect, it } from "vitest";
import { checkSpf, countLookups, isDomainSpec, mergeSpf, parseSpf, withSoftfail } from "../src/core/spf";
import type { Resolver } from "../src/core/doh";
import { fakeResolver } from "./helpers";

const ids = (f: { id: string }[]) => f.map((x) => x.id);

describe("parseSpf", () => {
  it("parses mechanisms, qualifiers and modifiers", () => {
    const spf = parseSpf("v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 include:_spf.example.net a mx/24 ~all");
    expect(spf.all).toBe("~");
    expect(spf.errors).toEqual([]);
    expect(spf.terms.map((t) => t.mechanism)).toEqual(["ip4", "ip6", "include", "a", "mx", "all"]);
    expect(spf.terms[1]?.value).toBe("2001:db8::/32");
  });

  it("reports unknown and incomplete terms", () => {
    expect(parseSpf("v=spf1 ipv4:1.2.3.4 include -all").errors).toEqual(["ipv4:1.2.3.4", "include"]);
  });

  it("checks the value of each mechanism (RFC 7208, sections 5.1 to 5.7)", () => {
    const bad = ["ip4:300.1.1.1", "ip4:1.2.3.0/33", "ip4:01.2.3.4", "ip6:zz::1", "ip6:2001:db8::/129", "all:x", "a:example", "mx:1.2.3.4", "include:bad%host.example", "exists:"];
    expect(parseSpf(`v=spf1 ${bad.join(" ")} -all`).errors).toEqual(bad);
    const good = "v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 a a/24 a:mail.example.com//64 mx:example.com/24//64 ptr ptr:example.com exists:%{i}._spf.example.com include:_spf.example.net -all";
    expect(parseSpf(good).errors).toEqual([]);
  });

  it("accepts redirect and exp once each, with a valid domain (RFC 7208, section 6)", () => {
    expect(parseSpf("v=spf1 redirect=a.example redirect=b.example").errors).toEqual(["redirect=b.example"]);
    expect(parseSpf("v=spf1 -all exp=explain._spf.%{d} exp=x.example").errors).toEqual(["exp=x.example"]);
    expect(parseSpf("v=spf1 redirect=nodot -all").errors).toEqual(["redirect=nodot"]);
    // Unknown modifiers are ignored wherever they appear.
    expect(parseSpf("v=spf1 foo=bar foo=baz -all").errors).toEqual([]);
  });

  it("validates domain-spec with macros (RFC 7208, section 7.1)", () => {
    expect(isDomainSpec("_spf.example.com")).toBe(true);
    expect(isDomainSpec("%{i}._spf.%{d}")).toBe(true);
    expect(isDomainSpec("%{ir}.%{v}.%{d}.spf.has.pphosted.com")).toBe(true);
    expect(isDomainSpec("example")).toBe(false);
    expect(isDomainSpec("192.0.2.1")).toBe(false);
    expect(isDomainSpec("a.%{x}.example.com")).toBe(false);
  });
});

describe("countLookups", () => {
  it("counts nested includes and redirect", async () => {
    const resolver = fakeResolver({
      "a.example TXT": ["v=spf1 include:b.example mx -all"],
      "b.example TXT": ["v=spf1 a ip4:192.0.2.1 -all"],
      "r.example TXT": ["v=spf1 include:a.example -all"],
    });
    const tree = await countLookups(parseSpf("v=spf1 include:a.example redirect=r.example"), resolver);
    // include:a(1) → include:b(1) + mx(1) → a(1); redirect(1) → include:a(1) → 3
    expect(tree.lookups).toBe(4 + 1 + 4);
  });

  it("does not count a failed lookup as missing, nor as a void lookup", async () => {
    const resolver = fakeResolver({}, { servfail: ["_spf.provider.net", "gone.example"] });
    const tree = await countLookups(parseSpf("v=spf1 include:_spf.provider.net a:gone.example -all"), resolver, new Set(["example.com"]), "example.com");
    expect(tree.errors).toEqual(["_spf.provider.net"]);
    expect(tree.missing).toEqual([]);
    expect(tree.voids).toEqual([]);
  });

  it("stops following includes well past the limit", async () => {
    const zone: Record<string, string[]> = {};
    for (let i = 0; i < 60; i++) zone[`l${i}.example TXT`] = [`v=spf1 include:l${i + 1}.example -all`];
    let queries = 0;
    const base = fakeResolver(zone);
    const counting: Resolver = (n, t) => (queries++, base(n, t));
    const tree = await countLookups(parseSpf("v=spf1 include:l0.example -all"), counting, new Set(["example.com"]), "example.com");
    expect(tree.truncated).toBe(true);
    expect(tree.lookups).toBeGreaterThan(10);
    expect(queries).toBeLessThan(25);
  });

  it("detects loops and missing includes", async () => {
    const resolver = fakeResolver({ "loop.example TXT": ["v=spf1 include:loop.example -all"] });
    const tree = await countLookups(parseSpf("v=spf1 include:loop.example include:ghost.example -all"), resolver);
    expect(tree.loops).toEqual(["loop.example"]);
    expect(tree.missing).toEqual(["ghost.example"]);
  });
});

describe("checkSpf", () => {
  const resolver = fakeResolver({});

  it("fails without SPF and proposes a record", async () => {
    const [generic] = await checkSpf("example.com", [], true, resolver);
    expect(generic).toMatchObject({ id: "spf.missing", status: "fail" });
    expect(generic?.suggest).toEqual([{ type: "TXT", name: "example.com", value: "v=spf1 mx ~all", action: "add" }]);

    const [google] = await checkSpf("example.com", [], true, resolver, { name: "Google Workspace", spf: "_spf.google.com" });
    expect(google).toMatchObject({ id: "spf.missing-provider", params: { provider: "Google Workspace" } });
    expect(google?.suggest?.[0]?.value).toBe("v=spf1 include:_spf.google.com ~all");

    const [noMail] = await checkSpf("example.com", [], false, resolver);
    expect(noMail).toMatchObject({ id: "spf.missing-nomail", status: "warn" });
    expect(noMail?.suggest?.[0]?.value).toBe("v=spf1 -all");
  });

  it("proposes a merged record when there are several", async () => {
    const [f] = await checkSpf("example.com", ["v=spf1 include:a.example -all", "v=spf1 ip4:192.0.2.1 include:a.example ~all"], true, resolver);
    expect(f?.suggest?.[0]).toMatchObject({ value: "v=spf1 include:a.example ip4:192.0.2.1 -all", action: "replace" });
  });

  it("fails with multiple records", async () => {
    expect(ids(await checkSpf("example.com", ["v=spf1 -all", "v=spf1 ~all"], true, resolver))).toEqual(["spf.multiple"]);
  });

  it("flags +all and too many lookups", async () => {
    const many = `v=spf1 ${Array.from({ length: 11 }, (_, i) => `a:h${i}.example`).join(" ")} +all`;
    const out = ids(await checkSpf("example.com", [many], true, resolver));
    expect(out).toContain("spf.all-pass");
    expect(out).toContain("spf.too-many-lookups");
  });

  it("accepts a strict record", async () => {
    const out = await checkSpf("example.com", ["v=spf1 ip4:192.0.2.1 -all", "google-site-verification=x"], true, resolver);
    expect(out.every((f) => f.status === "ok")).toBe(true);
  });
});

describe("SPF rewriting", () => {
  it("replaces or adds the final all", () => {
    expect(withSoftfail("v=spf1 mx +all")).toBe("v=spf1 mx ~all");
    expect(withSoftfail("v=spf1 ip4:192.0.2.1")).toBe("v=spf1 ip4:192.0.2.1 ~all");
  });

  it("never keeps +all when merging", () => {
    expect(mergeSpf(["v=spf1 a +all", "v=spf1 mx"])).toBe("v=spf1 a mx ~all");
  });

  it("keeps the senders behind a redirect when merging", () => {
    // Next to an `all`, a redirect would be ignored (RFC 7208, section 6.1): it becomes an include.
    expect(mergeSpf(["v=spf1 redirect=_spf.example.com", "v=spf1 include:mail.zendesk.com ~all"])).toBe("v=spf1 include:_spf.example.com include:mail.zendesk.com ~all");
  });
});

describe("RFC 7208 section 4.6.4 extra limits", () => {
  it("flags more than two void lookups", async () => {
    const r = fakeResolver({ "ok.example A": ["192.0.2.1"] });
    const record = "v=spf1 a:gone1.example a:gone2.example exists:gone3.example a:ok.example -all";
    const out = await checkSpf("example.com", [record], true, r);
    const f = out.find((x) => x.id === "spf.void-lookups");
    expect(f).toMatchObject({ status: "warn", params: { count: 3, max: 2 } });
    expect(String(f?.params?.terms)).toContain("a:gone1.example");
  });

  it("does not count macros or two voids", async () => {
    const out = await checkSpf("example.com", ["v=spf1 exists:%{i}.bl.example a:gone.example -all"], true, fakeResolver({}));
    expect(out.map((x) => x.id)).not.toContain("spf.void-lookups");
  });

  it("fails an mx mechanism with more than 10 MX records", async () => {
    const mx = Array.from({ length: 11 }, (_, i) => `${i} mx${i}.example.com`);
    const out = await checkSpf("example.com", ["v=spf1 mx -all"], true, fakeResolver({ "example.com MX": mx }));
    expect(out.find((x) => x.id === "spf.mx-too-many")).toMatchObject({ status: "fail", params: { terms: "mx:example.com (11)", max: 10 } });
  });
});

describe("lookups that fail are not missing records", () => {
  it("does not propose removing an include that did not answer", async () => {
    const out = await checkSpf("example.com", ["v=spf1 include:_spf.provider.net -all"], true, fakeResolver({}, { servfail: ["_spf.provider.net"] }));
    expect(out.find((f) => f.id === "spf.include-error")).toMatchObject({ status: "info", params: { domains: "_spf.provider.net" } });
    expect(ids(out)).not.toContain("spf.include-missing");
    // The count is incomplete, so there is no "within the limit" verdict.
    expect(ids(out)).not.toContain("spf.lookups");
  });

  it("still removes an include whose domain really has no SPF", async () => {
    const out = await checkSpf("example.com", ["v=spf1 include:ghost.example -all"], true, fakeResolver({}, { nxdomain: ["ghost.example"] }));
    expect(out.find((f) => f.id === "spf.include-missing")?.suggest?.[0]?.value).toBe("v=spf1 -all");
  });
});

describe("cases found in the live validation", () => {
  it("does not resolve macros as if they were domains (rtve.es)", async () => {
    const ids = (await checkSpf("example.com", ["v=spf1 include:%{ir}.%{v}.%{d}.spf.has.pphosted.com -all"], true, fakeResolver({}))).map((f) => f.id);
    expect(ids).toContain("spf.macros");
    expect(ids).not.toContain("spf.include-missing");
  });

  it("flags an SPF that authorises nobody on a domain with mail servers (vulnweb.com)", async () => {
    const out = await checkSpf("example.com", ["v=spf1 ~all"], true, fakeResolver({}), { name: "Google", spf: "_spf.google.com" } as never);
    const ids = out.map((f) => f.id);
    expect(ids).toContain("spf.no-senders");
    expect(ids).not.toContain("spf.all-softfail");
    expect(out.find((f) => f.id === "spf.no-senders")?.suggest?.[0]?.value).toBe("v=spf1 include:_spf.google.com ~all");
  });

  it("keeps `v=spf1 -all` as correct when the domain has no mail servers", async () => {
    const ids = (await checkSpf("example.com", ["v=spf1 -all"], false, fakeResolver({}))).map((f) => f.id);
    expect(ids).not.toContain("spf.no-senders");
    expect(ids).toContain("spf.all-fail");
  });
});
