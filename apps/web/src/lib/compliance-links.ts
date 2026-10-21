import { frameworkRouteSegment } from "@/lib/grc-frameworks";

// Server-safe: the /controls redirect imports this, so it must not pull in client-only modules.

export const frameworkDetailHref = (framework: { id?: string; name: string }, tenantID = "", controlID = "") => {
  const query = new URLSearchParams();
  if (tenantID.trim()) query.set("tenant_id", tenantID.trim());
  if (controlID.trim()) query.set("control", controlID.trim());
  const queryString = query.toString();
  return `/frameworks/${frameworkRouteSegment(framework)}${queryString ? `?${queryString}` : ""}`;
};

/** Carries tenant and workspace scope from legacy compliance URLs onto their replacement route. */
export const withComplianceScope = (href: string, scope: { tenantID?: string; workspaceID?: string }) => {
  const url = new URL(href, "http://scope.invalid");
  if (scope.tenantID?.trim()) url.searchParams.set("tenant_id", scope.tenantID.trim());
  if (scope.workspaceID?.trim()) url.searchParams.set("workspace_id", scope.workspaceID.trim());
  return `${url.pathname}${url.search}`;
};

/** Where a finding's control ref links: the framework page focused on that control. */
export const complianceControlHref = (frameworkName: string | undefined, controlID: string | undefined, tenantID = "") =>
  frameworkName?.trim() ? frameworkDetailHref({ name: frameworkName.trim() }, tenantID, controlID ?? "") : "/grc";
