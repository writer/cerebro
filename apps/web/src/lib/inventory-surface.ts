import type { GRCInventoryAsset, GRCInventorySurface } from "@/lib/grc";

export const inventoryDefaultSurface: GRCInventorySurface = "asset";

export const inventoryRequestSurface = (surfaceFilter: string): GRCInventorySurface => {
  const trimmed = surfaceFilter.trim();
  return trimmed ? trimmed : inventoryDefaultSurface;
};

export const inventoryAssetSurface = (asset?: Pick<GRCInventoryAsset, "surface"> | null): GRCInventorySurface =>
  asset?.surface || inventoryDefaultSurface;
