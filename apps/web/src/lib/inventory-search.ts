import type { GRCInventoryAsset, GRCInventoryCategory } from "@/lib/grc";

export type InventoryMetadataMatch = {
  key: string;
  value: string;
};

const normalize = (value: string) => value.trim().toLowerCase();

/**
 * Explains a search hit the row does not already show.
 *
 * The entity catalog matches the URN, the label and every collected attribute
 * value, so an asset can match on metadata that no column renders.
 */
export const inventoryMetadataMatch = (
  asset: GRCInventoryAsset,
  query: string,
): InventoryMetadataMatch | null => {
  const needle = normalize(query);
  if (!needle) return null;
  if (normalize(`${asset.urn} ${asset.label}`).includes(needle)) return null;
  for (const [key, value] of Object.entries(asset.attributes ?? {})) {
    const text = String(value ?? "");
    if (normalize(text).includes(needle)) return { key, value: text };
  }
  return null;
};

/**
 * Lists every entity type the catalog reports, for the server-side type filter.
 *
 * Categories cover the whole corpus, so these options do not drift with the
 * rows that happen to be loaded.
 */
export const inventoryTypeOptions = (categories: GRCInventoryCategory[]): string[] =>
  [...new Set(categories.flatMap((category) => category.entity_types ?? []))]
    .filter((value) => value.trim().length > 0)
    .sort((left, right) => left.localeCompare(right));

/** Suggests source IDs seen in the loaded rows. These are hints, not a complete list. */
export const inventorySourceOptions = (assets: GRCInventoryAsset[]): string[] =>
  [...new Set(assets.map((asset) => asset.source_id ?? ""))]
    .filter((value) => value.trim().length > 0)
    .sort((left, right) => left.localeCompare(right));
