import type { GRCInventoryAsset, GRCInventorySurface } from "@/lib/grc";

export const inventoryDefaultSurface: GRCInventorySurface = "asset";

export const inventoryRequestSurface = (surfaceFilter: string): GRCInventorySurface => {
  const trimmed = surfaceFilter.trim();
  return trimmed ? trimmed : inventoryDefaultSurface;
};

export const inventoryAssetSurface = (asset?: Pick<GRCInventoryAsset, "surface"> | null): GRCInventorySurface =>
  asset?.surface || inventoryDefaultSurface;

type InventoryNarrowingFilters = {
  surface: string;
  tenant: string;
  category: string;
  query: string;
  framework: string;
  owner: string;
  review: string;
  accountability: string;
  source: string;
  scope: string;
};

export const inventoryNarrowingFilterCount = (filters: InventoryNarrowingFilters): number => [
  inventoryRequestSurface(filters.surface) === inventoryDefaultSurface ? "" : filters.surface,
  filters.category,
  filters.query,
  filters.framework,
  filters.owner,
  filters.review,
  filters.accountability,
  filters.source,
  filters.scope,
  // Tenant selects the operating context; it is not an operator-applied result filter.
].filter((value) => value.trim()).length;
