// Matched against routeLabelForPath output, so every value here has to be a
// label some route actually resolves to.
export const denseAgentRouteLabels = new Set([
  "Audit Workspace",
  "Compliance",
  "Controls",
  "Evidence",
  "Frameworks",
  "Policy Documents",
  "Reports",
  "Shared Snapshot",
]);

export const isDenseAgentRouteLabel = (routeLabel?: string | null) =>
  Boolean(routeLabel && denseAgentRouteLabels.has(routeLabel));
