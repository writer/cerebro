export function grcBrowserRouteContracts({ adminURN }) {
  return [
    { route: "/", pageId: "overview", heading: "Security Posture" },
    { route: "/risks", pageId: "risks", heading: "Risks" },
    { route: "/grc", pageId: "grc", heading: "Compliance" },
    { route: "/integrations", pageId: "connectors", heading: "Integrations" },
    { route: `/explore?root_urn=${encodeURIComponent(adminURN)}`, pageId: "graph-explorer", heading: "Attack Graphs" },
    { route: "/reports", pageId: "reports", heading: "Reports" },
  ];
}
