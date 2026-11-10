import { describe, expect, it } from "vitest";
import { filterItems, normalize, type PaletteItem } from "../src/ui/palette";

const item = (label: string, keywords = ""): PaletteItem => ({ label, keywords, group: "g", run: () => {} });

describe("palette search", () => {
  it("ignores accents and case", () => {
    expect(normalize("Configuración DNS")).toBe("configuracion dns");
  });

  it("matches every word, including keywords that are not in the title", () => {
    const items = [item("Cualquier autoridad puede emitir certificados", "dns caa missing"), item("Tienes SPF", "spf found")];
    expect(filterItems(items, "caa").map((i) => i.label)).toEqual(["Cualquier autoridad puede emitir certificados"]);
    expect(filterItems(items, "CERTIFICADOS autoridad")).toHaveLength(1);
    expect(filterItems(items, "spf caa")).toHaveLength(0);
    expect(filterItems(items, "  ")).toHaveLength(2);
  });
});
