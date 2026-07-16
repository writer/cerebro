export function grcBrowserRouteContracts({ adminURN }) {
  return [
    { route: "/", pageId: "overview", heading: "Overview" },
    { route: "/risk-inbox", pageId: "risk-inbox", heading: "Risk Inbox" },
    { route: "/controls", pageId: "controls", heading: "Controls" },
    { route: "/frameworks", pageId: "frameworks", heading: "Frameworks" },
    { route: "/controls/builder", pageId: "control-builder", heading: "Control Builder" },
    { route: "/evidence", pageId: "evidence", heading: "Evidence" },
    { route: "/vendors", pageId: "vendors", heading: "Vendors" },
    { route: "/connectors", pageId: "connectors", heading: "Connectors" },
    { route: `/impact?root_urn=${encodeURIComponent(adminURN)}`, pageId: "impact-map", heading: "Impact Map" },
    { route: "/reports", pageId: "reports", heading: "Reports" },
  ];
}
