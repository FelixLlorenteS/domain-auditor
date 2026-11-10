import { describe, expect, it } from "vitest";
import { riskOf, techniqueUrl } from "../src/ui/attack";

describe("riskOf", () => {
  it("tells the risk of a gap and what the control prevents, with ATT&CK techniques", () => {
    const gap = riskOf("dmarc", false, "es")!;
    expect(gap.text).toMatch(/remitente visible/);
    expect(gap.techniques.map((t) => t.id)).toEqual(["T1566", "T1684.001"]);
    expect(riskOf("dmarc", true, "en")!.text).toMatch(/reject/);
    expect(riskOf("address", false, "es")).toBeNull();
  });

  it("links sub-techniques with a slash", () => {
    expect(techniqueUrl("T1684.001")).toBe("https://attack.mitre.org/techniques/T1684/001/");
  });
});
