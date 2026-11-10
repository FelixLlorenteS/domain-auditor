import { describe, expect, it } from "vitest";
import type { Report } from "../src/core/types";
import { reportMarkdown } from "../src/ui/markdown";

const report: Report = {
  query: "example.com",
  kind: "domain",
  generatedAt: "2026-09-27T10:00:00.000Z",
  sections: [
    {
      id: "mail",
      findings: [
        { id: "spf.found", status: "ok", params: { record: "v=spf1 -all" } },
        { id: "dmarc.p-none", status: "warn", suggest: [{ type: "TXT", name: "_dmarc.example.com", value: "v=DMARC1; p=quarantine;", action: "replace" }] },
      ],
      records: [
        { name: "example.com", type: "TXT", ttl: 300, data: "v=spf1 -all" },
        { name: "_dmarc.example.com", type: "TXT", ttl: 300, data: "v=DMARC1; p=none" },
      ],
    },
  ],
};

describe("reportMarkdown", () => {
  const md = reportMarkdown(report, "es", [["Titular", "Example Inc."]], {}, "https://audit.example/?q=example.com");

  it("starts with the action plan", () => {
    const plan = md.slice(md.indexOf("## Plan de acción"), md.indexOf("## Correo · autenticación"));
    expect(plan).toContain("1. **DMARC** (Aviso, severidad alta)");
  });

  it("gives each control its evidence, checks and action", () => {
    const dmarc = md.slice(md.indexOf("### DMARC"));
    expect(dmarc).toContain("_dmarc.example.com  300  TXT  v=DMARC1; p=none");
    expect(dmarc).toContain("- [Aviso]");
    expect(dmarc).toContain("_dmarc.example.com TXT v=DMARC1; p=quarantine;");
    expect(md).toMatch(/### SPF: Bien[\s\S]*- \[Bien\] .+ — `v=spf1 -all`/);
    expect(md).toContain("- **Titular:** Example Inc.");
  });
});
