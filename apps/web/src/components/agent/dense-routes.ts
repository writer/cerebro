export const denseAgentRouteLabels = new Set([
  "Audit packages",
  "Compliance",
  "Controls",
  "Evidence",
  "Frameworks",
  "Issues",
  "Work",
  "Audit packets",
  "Audit workspace",
  "Policies",
  "Reports",
  "Shared snapshot",
]);

export const isDenseAgentRouteLabel = (routeLabel?: string | null) =>
  Boolean(routeLabel && denseAgentRouteLabels.has(routeLabel));
