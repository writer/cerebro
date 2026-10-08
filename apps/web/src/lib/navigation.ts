export type { NavigationEntry } from "@/lib/routes";
export { adminNavLinks, navigationEntries, operatorNavLinks, utilityLinks } from "@/lib/routes";

// Menu and page labels are title case; these words stay lowercase unless they
// lead the label.
export const MINOR_TITLE_WORDS = new Set([
  "a", "an", "and", "as", "at", "but", "by", "for", "in", "nor", "of", "on", "or", "per", "the", "to", "vs", "via", "with",
]);

const legacyControlHref = /^\/grc\/controls(?=[?#]|$)/;

export const normalizeLegacyControlHref = (href: string) =>
  href.replace(legacyControlHref, "/controls");
