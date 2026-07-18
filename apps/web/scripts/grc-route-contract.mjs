export function grcBrowserRouteContracts({ adminURN }) {
  return [
    { route: "/", pageId: "overview", heading: "Home" },
    { route: "/risk-inbox", pageId: "risk-inbox", heading: "Risks" },
    { route: "/controls", pageId: "controls", heading: "Controls" },
    { route: "/frameworks", pageId: "frameworks", heading: "Frameworks" },
    { route: "/controls/builder", pageId: "control-builder", heading: "Control Builder" },
    { route: "/evidence", pageId: "evidence", heading: "Evidence" },
    { route: "/vendors", pageId: "vendors", heading: "Vendors" },
    { route: "/connectors", pageId: "connectors", heading: "Sources" },
    { route: `/impact?root_urn=${encodeURIComponent(adminURN)}`, pageId: "impact-map", heading: "Affected assets" },
    { route: "/reports", pageId: "reports", heading: "Reports" },
  ];
}
