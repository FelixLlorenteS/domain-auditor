import { describe, expect, it } from "vitest";
import type { Report } from "../src/core/types";
import { clientReportHtml } from "../src/ui/client-report";

const report: Report = {
  query: "example.com",
  kind: "domain",
  generatedAt: "2026-11-10T00:00:00.000Z",
  sections: [
    {
      id: "mail",
      findings: [
        { id: "spf.found", status: "ok", params: { record: "v=spf1 -all" } },
        { id: "dmarc.missing", status: "fail", params: { domain: "example.com" }, suggest: [{ type: "TXT", name: "_dmarc.example.com", value: "v=DMARC1; p=none; rua=mailto:{mailbox};", input: "mailbox" }] },
      ],
      records: [],
    },
    { id: "dns", findings: [{ id: "dns.caa-missing", status: "warn", params: { domain: "example.com" } }], records: [] },
  ],
};

describe("client report", () => {
  const html = clientReportHtml(report, "es", [["Registrador", "Example Registrar"]], {});

  it("always has the same four sections, in order", () => {
    const sections = [...html.matchAll(/<h2>([^<]+)<\/h2>/g)].map((m) => m[1]);
    expect(sections).toEqual(["1. Resumen ejecutivo", "2. Estado de los controles", "3. Plan de acción", "4. Anexo"]);
  });

  it("puts the most severe action first, with the exact record and no invented mailbox", () => {
    const plan = html.slice(html.indexOf("3. Plan de acción"));
    expect(plan.indexOf("DMARC")).toBeLessThan(plan.indexOf("CAA"));
    expect(plan).toContain("_dmarc.example.com");
    expect(plan).toContain("mailto:&#60;buzón&#62;");
    expect(plan).not.toContain("{mailbox}");
  });

  it("lists what is fine in the annex and escapes what comes from outside", () => {
    expect(html.slice(html.indexOf("4. Anexo"))).toContain("SPF");
    const hostile = clientReportHtml({ ...report, query: "<script>x</script>" }, "en", [], {});
    expect(hostile).not.toContain("<script>x");
  });
});
