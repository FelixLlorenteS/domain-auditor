import { describe, expect, it } from "vitest";
import type { Section } from "../src/core/types";
import { observedFor } from "../src/ui/observed";

const mail: Section = {
  id: "mail",
  findings: [],
  records: [
    { name: "example.com", type: "MX", ttl: 300, data: "10 mx.example.net" },
    { name: "example.com", type: "TXT", ttl: 300, data: "v=spf1 -all" },
    { name: "_dmarc.example.com", type: "TXT", ttl: 300, data: "v=DMARC1; p=none" },
  ],
};

describe("observedFor", () => {
  it("shows only the records the finding is about", () => {
    const o = observedFor({ id: "dmarc.p-none", status: "warn" }, mail, "example.com", "es")!;
    expect(o.rows.map((r) => r.data)).toEqual(["v=DMARC1; p=none"]);
    expect(o.expected).toContain("_dmarc.example.com");
  });

  it("uses the suggested records as what should be there", () => {
    const o = observedFor(
      { id: "tls-rpt.missing", status: "info", suggest: [{ type: "TXT", name: "_smtp._tls.example.com", value: "v=TLSRPTv1; rua=mailto:{mailbox}" }] },
      mail,
      "example.com",
      "en",
    )!;
    expect(o.rows).toEqual([]);
    expect(o.where).toBe("_smtp._tls.example.com TXT");
    expect(o.suggest[0]).toEqual({ verb: "Add", line: "_smtp._tls.example.com TXT v=TLSRPTv1; rua=mailto:{mailbox}" });
    expect(o.expected).toBeUndefined();
  });

  it("says a passing check complies and skips findings with no DNS record", () => {
    expect(observedFor({ id: "spf.found", status: "ok" }, mail, "example.com", "es")!.expected).toMatch(/cumple/);
    expect(observedFor({ id: "reg.expires", status: "ok" }, mail, "example.com", "es")).toBeNull();
  });

  it("does not assess findings that only identify a provider", () => {
    expect(observedFor({ id: "mx.provider", status: "info" }, mail, "example.com", "es")!.identifyOnly).toBe(true);
  });
});
