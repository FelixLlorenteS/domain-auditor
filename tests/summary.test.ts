import { describe, expect, it } from "vitest";
import { verdicts } from "../src/core/summary";
import type { Report, Status } from "../src/core/types";

function report(mail: string[], dns: Array<[string, Status]> = [], reg: string[] = ["reg.transfer-lock"]): Report {
  return {
    query: "example.com",
    kind: "domain",
    generatedAt: "2026-09-25T00:00:00Z",
    sections: [
      { id: "mail", findings: mail.map((id) => ({ id, status: "ok" as Status })), records: [] },
      { id: "dns", findings: dns.map(([id, status]) => ({ id, status })), records: [] },
      { id: "registration", findings: reg.map((id) => ({ id, status: "ok" as Status })), records: [] },
    ],
  };
}

describe("verdicts", () => {
  it("rates e-mail spoofing protection", () => {
    const level = (mail: string[]) => verdicts(report(mail))[0]?.level;
    expect(level(["mx.found", "spf.found", "dmarc.p-reject", "dkim.found"])).toBe("good");
    expect(level(["mx.found", "spf.found", "dmarc.p-quarantine", "dkim.found"])).toBe("partial");
    expect(level(["mx.found", "spf.found", "dmarc.p-none"])).toBe("bad");
    expect(level(["mx.found", "spf.found", "dmarc.missing"])).toBe("bad");
    expect(level(["mx.none", "dmarc.missing"])).toBe("bad");
  });

  it("does not rate spoofing when DMARC could not be queried, and treats an ignored record as none", () => {
    const level = (mail: string[]) => verdicts(report(mail))[0];
    expect(level(["mx.found", "spf.found", "dmarc.lookup-error"])).toMatchObject({ level: "unknown", reason: "unverified" });
    expect(level(["mx.found", "spf.found", "dmarc.bad-version"])).toMatchObject({ level: "bad", reason: "no-dmarc" });
    // An ignored record on a subdomain whose parent's policy applies: the parent decides.
    expect(level(["mx.found", "spf.found", "dmarc.bad-version", "dmarc.found", "dmarc.p-reject", "dkim.found"])?.level).toBe("good");
  });

  it("rates DNS by its worst finding", () => {
    expect(verdicts(report(["dmarc.p-reject"], [["dns.caa-missing", "warn"]]))[1]).toMatchObject({ area: "dns", level: "partial" });
    expect(verdicts(report(["dmarc.p-reject"], [["dns.ns", "ok"]]))[1]?.level).toBe("good");
  });

  it("marks registration as unknown when RDAP is missing", () => {
    expect(verdicts(report(["dmarc.p-reject"], [], ["reg.unavailable"]))[2]?.level).toBe("unknown");
  });
});
