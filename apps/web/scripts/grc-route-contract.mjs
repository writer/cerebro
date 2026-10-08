export function grcBrowserRouteContracts({ adminURN }) {
  return [
    { route: "/", pageId: "overview", heading: "Security Overview" },
    { route: "/risks", pageId: "risks", heading: "Risks" },
    { route: "/controls", pageId: "controls", heading: "Controls" },
    { route: "/policies", pageId: "policies", heading: "Policy Documents" },
    { route: "/frameworks", pageId: "frameworks", heading: "Frameworks" },
    { route: "/controls/builder", pageId: "control-builder", heading: "Control Builder" },
    { route: "/evidence", pageId: "evidence", heading: "Evidence" },
    { route: "/questionnaires", pageId: "questionnaires", heading: "Questionnaires" },
    { route: "/vendors", pageId: "vendors", heading: "Vendors" },
    { route: "/connectors", pageId: "connectors", heading: "Integrations" },
    { route: `/explore?root_urn=${encodeURIComponent(adminURN)}`, pageId: "graph-explorer", heading: "Graph" },
    { route: "/reports", pageId: "reports", heading: "Reports" },
    { route: "/reports/packages", pageId: "audit-packages", heading: "Audit Workspace" },
  ];
}
