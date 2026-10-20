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
 * Names the person a device belongs to, from whichever user attribute its source collected.
 *
 * Device sources disagree on where the user lives: EDR agents report the last
 * logged-in account, MDMs report the assigned user's email.
 */
export const inventoryDeviceUser = (asset: GRCInventoryAsset): { name: string; email: string } => {
  const attributes = asset.attributes ?? {};
  const value = (key: "user_name" | "username" | "user_email" | "owner_email") => String(attributes[key] ?? "").trim();
  const email = value("user_email") || value("owner_email");
  const name = value("user_name") || value("username");
  return { name: name && name !== email ? name : "", email };
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
