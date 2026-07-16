export const denseAgentRouteLabels = new Set([
  "Audit packages",
  "Compliance",
  "Controls",
  "Evidence",
  "Frameworks",
  "Issues",
  "Packet review",
  "Reports",
  "Shared snapshot",
]);

export const isDenseAgentRouteLabel = (routeLabel?: string | null) =>
  Boolean(routeLabel && denseAgentRouteLabels.has(routeLabel));
