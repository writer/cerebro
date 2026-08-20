export type { NavigationEntry } from "@/lib/routes";
export { navigationEntries, operatorNavLinks, utilityLinks } from "@/lib/routes";

const legacyControlHref = /^\/grc\/controls(?=[?#]|$)/;

export const normalizeLegacyControlHref = (href: string) =>
  href.replace(legacyControlHref, "/controls");
