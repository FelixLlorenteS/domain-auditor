import { describe, expect, it } from "vitest";
import { checkDmarc, editDmarc, isDmarc, parseTags, treeWalkTargets } from "../src/core/dmarc";
import { fakeResolver } from "./helpers";

const ids = (r: { findings: { id: string }[] }) => r.findings.map((f) => f.id);

describe("parseTags", () => {
  it("parses tag=value pairs and keeps the first one", () => {
    const tags = parseTags("v=DMARC1; p=reject ; rua=mailto:a@example.com; p=none");
    expect(tags.get("p")).toBe("reject");
    expect(tags.get("rua")).toBe("mailto:a@example.com");
  });
});

describe("treeWalkTargets (RFC 9989, section 4.10)", () => {
  it("walks up from the parent", () => {
    expect(treeWalkTargets("a.mail.example.com")).toEqual(["mail.example.com", "example.com", "com"]);
  });

  it("shortens long names to seven labels first", () => {
    const targets = treeWalkTargets("a.b.c.d.e.f.g.h.i.j.mail.example.com");
    expect(targets[0]).toBe("g.h.i.j.mail.example.com");
    expect(targets).toHaveLength(7);
  });
});

describe("checkDmarc", () => {
  it("fails when missing", async () => {
    expect(ids(await checkDmarc("example.com", fakeResolver({})))).toEqual(["dmarc.missing"]);
  });

  it("recognises a strict policy", async () => {
    const r = fakeResolver({ "_dmarc.example.com TXT": ["v=DMARC1; p=reject; rua=mailto:d@example.com"] });
    const out = await checkDmarc("example.com", r);
    expect(ids(out)).toEqual(["dmarc.found", "dmarc.p-reject", "dmarc.rua"]);
    expect(out.records).toHaveLength(1);
  });

  it("warns on p=none and sp=none, and on test mode", async () => {
    const none = await checkDmarc("example.com", fakeResolver({ "_dmarc.example.com TXT": ["v=DMARC1; p=none"] }));
    expect(ids(none)).toEqual(["dmarc.found", "dmarc.p-none", "dmarc.no-rua"]);
    const partial = await checkDmarc(
      "example.com",
      fakeResolver({ "_dmarc.example.com TXT": ["v=DMARC1; p=quarantine; sp=none; t=y; pct=20; rua=mailto:d@example.com"] }),
    );
    expect(ids(partial)).toEqual(["dmarc.found", "dmarc.p-quarantine", "dmarc.sp-none", "dmarc.testing", "dmarc.removed-tags", "dmarc.rua"]);
  });

  it("treats a missing p as none", async () => {
    const r = fakeResolver({ "_dmarc.example.com TXT": ["v=DMARC1; rua=mailto:d@example.com"] });
    expect(ids(await checkDmarc("example.com", r))).toEqual(["dmarc.found", "dmarc.p-missing", "dmarc.rua"]);
  });

  it("inherits through the tree walk and applies sp", async () => {
    const r = fakeResolver({ "_dmarc.example.com TXT": ["v=DMARC1; p=reject; sp=none; rua=mailto:d@example.com"] });
    const out = ids(await checkDmarc("a.mail.example.com", r));
    expect(out).toEqual(["dmarc.found", "dmarc.inherited", "dmarc.p-none", "dmarc.rua"]);
  });

  it("rejects an invalid policy", async () => {
    const r = fakeResolver({ "_dmarc.example.com TXT": ["v=DMARC1; p=block"] });
    expect(ids(await checkDmarc("example.com", r))).toEqual(["dmarc.found", "dmarc.invalid-policy"]);
  });
});

describe("RFC 9989 strictness", () => {
  it("only accepts the version DMARC1 in upper case (sections 4.7 and 4.8)", () => {
    expect(isDmarc("v=DMARC1; p=reject")).toBe(true);
    expect(isDmarc("V = DMARC1;p=reject")).toBe(true);
    expect(isDmarc("v=DMARC1")).toBe(true);
    expect(isDmarc("v=dmarc1; p=reject")).toBe(false);
    expect(isDmarc(" v=DMARC1; p=reject")).toBe(false);
    expect(isDmarc("p=reject; v=DMARC1")).toBe(false);
  });

  it("reports a record receivers ignore instead of taking it as reject", async () => {
    const out = await checkDmarc("example.com", fakeResolver({ "_dmarc.example.com TXT": ["v=dmarc1; p=reject; rua=mailto:d@example.com"] }));
    expect(ids(out)).toEqual(["dmarc.bad-version"]);
    expect(out.findings[0]).toMatchObject({ status: "fail" });
    expect(out.findings[0]?.suggest?.[0]).toMatchObject({ name: "_dmarc.example.com", value: "v=DMARC1; p=reject; rua=mailto:d@example.com", action: "replace" });
    expect(out.records).toHaveLength(1);
  });

  it("walks up past an ignored record, as receivers do", async () => {
    const r = fakeResolver({
      "_dmarc.mail.example.com TXT": ["v=dmarc1; p=none"],
      "_dmarc.example.com TXT": ["v=DMARC1; p=reject; rua=mailto:d@example.com"],
    });
    expect(ids(await checkDmarc("mail.example.com", r))).toEqual(["dmarc.bad-version", "dmarc.found", "dmarc.inherited", "dmarc.p-reject", "dmarc.rua"]);
  });

  it("does not report reject when sp or np is invalid: receivers apply none (section 4.10.1)", async () => {
    const out = await checkDmarc("example.com", fakeResolver({ "_dmarc.example.com TXT": ["v=DMARC1; p=reject; sp=rejectt; rua=mailto:d@example.com"] }));
    expect(ids(out)).toEqual(["dmarc.found", "dmarc.invalid-policy"]);
    const f = out.findings[1];
    expect(f?.params).toEqual({ tag: "sp", value: "sp=rejectt" });
    // Without the broken sp, p=reject applies to subdomains too.
    expect(f?.suggest?.[0]?.value).toBe("v=DMARC1; p=reject; rua=mailto:d@example.com;");
    const np = await checkDmarc("example.com", fakeResolver({ "_dmarc.example.com TXT": ["v=DMARC1; p=reject; np=block"] }));
    expect(ids(np)).toEqual(["dmarc.found", "dmarc.invalid-policy"]);
  });

  it("does not guess a broken p", async () => {
    const out = await checkDmarc("example.com", fakeResolver({ "_dmarc.example.com TXT": ["v=DMARC1; p=rejct; rua=mailto:d@example.com"] }));
    expect(out.findings.find((f) => f.id === "dmarc.invalid-policy")?.suggest).toBeUndefined();
  });

  it("does not call a record missing when the lookup failed", async () => {
    const own = await checkDmarc("example.com", fakeResolver({}, { servfail: ["_dmarc.example.com"] }));
    expect(own.findings).toEqual([{ id: "dmarc.lookup-error", status: "info", params: { name: "_dmarc.example.com" } }]);
    const parent = await checkDmarc("mail.example.com", fakeResolver({}, { servfail: ["_dmarc.example.com"] }));
    expect(ids(parent)).toEqual(["dmarc.lookup-error"]);
  });
});

describe("DMARC fixes", () => {
  it("rebuilds records keeping v and p first", () => {
    expect(editDmarc("v=DMARC1; rua=mailto:a@example.com; p=none; pct=50", { p: "quarantine", pct: null })).toBe(
      "v=DMARC1; p=quarantine; rua=mailto:a@example.com;",
    );
  });

  it("proposes a starter record when missing", async () => {
    const [f] = (await checkDmarc("example.com", fakeResolver({}))).findings;
    // The report mailbox is left for the user to type: no invented address.
    expect(f?.suggest).toEqual([{ type: "TXT", name: "_dmarc.example.com", value: "v=DMARC1; p=none; rua=mailto:{mailbox};", input: "mailbox" }]);
  });

  it("proposes the next policy step on the record that applies", async () => {
    const r = fakeResolver({ "_dmarc.example.com TXT": ["v=DMARC1; p=none; rua=mailto:d@example.com"] });
    const none = (await checkDmarc("example.com", r)).findings.find((f) => f.id === "dmarc.p-none");
    expect(none?.suggest?.[0]).toMatchObject({ name: "_dmarc.example.com", value: "v=DMARC1; p=quarantine; rua=mailto:d@example.com;", action: "replace" });
    const r2 = fakeResolver({ "_dmarc.example.com TXT": ["v=DMARC1; p=quarantine; rua=mailto:d@example.com"] });
    const q = (await checkDmarc("example.com", r2)).findings.find((f) => f.id === "dmarc.p-quarantine");
    expect(q?.suggest?.[0]?.value).toBe("v=DMARC1; p=reject; rua=mailto:d@example.com;");
  });
});
