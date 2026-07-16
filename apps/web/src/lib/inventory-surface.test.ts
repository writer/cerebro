import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { inventoryAssetSurface, inventoryDefaultSurface, inventoryRequestSurface } from "@/lib/inventory-surface";

const readProjectFile = (...parts: string[]) => readFileSync(join(process.cwd(), ...parts), "utf8");

describe("inventory surface defaults", () => {
  it("keeps Assets requests explicit", () => {
    expect(inventoryDefaultSurface).toBe("asset");
    expect(inventoryRequestSurface("")).toBe("asset");
    expect(inventoryRequestSurface("  ")).toBe("asset");
    expect(inventoryRequestSurface("all")).toBe("all");
    expect(inventoryRequestSurface("component")).toBe("component");
  });

  it("treats records without a surface as assets", () => {
    expect(inventoryAssetSurface()).toBe("asset");
    expect(inventoryAssetSurface({})).toBe("asset");
    expect(inventoryAssetSurface({ surface: "component" })).toBe("component");
  });

  it("keeps inventory pages on the shared surface helpers", () => {
    const listSource = readProjectFile("src/app/inventory/page.tsx");
    const detailSource = readProjectFile("src/app/inventory/[urn]/page.tsx");

    expect(listSource).toContain("inventoryRequestSurface(debouncedSurfaceFilter)");
    expect(listSource).not.toMatch(/debouncedSurfaceFilter\s*\|\|\s*["']asset["']/);

    for (const source of [listSource, detailSource]) {
      expect(source).toContain("inventoryAssetSurface");
      expect(source).not.toMatch(/\.surface\s*\|\|\s*["']asset["']/);
    }
  });
});
