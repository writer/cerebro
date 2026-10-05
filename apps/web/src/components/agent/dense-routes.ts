// Matched against routeLabelForPath output, so every value here has to be a
// label some route actually resolves to.
export const denseAgentRouteLabels = new Set([
  "Audit workspace",
  "Compliance",
  "Controls",
  "Evidence",
  "Frameworks",
  "Policy documents",
  "Reports",
  "Shared snapshot",
]);

export const isDenseAgentRouteLabel = (routeLabel?: string | null) =>
  Boolean(routeLabel && denseAgentRouteLabels.has(routeLabel));
