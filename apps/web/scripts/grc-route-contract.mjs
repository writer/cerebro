export function grcBrowserRouteContracts({ adminURN }) {
  return [
    { route: "/", pageId: "overview", heading: "Compliance overview" },
    { route: "/risk-inbox", pageId: "risk-inbox", heading: "Risks" },
    { route: "/controls", pageId: "controls", heading: "Controls" },
    { route: "/policies", pageId: "policies", heading: "Policies" },
    { route: "/frameworks", pageId: "frameworks", heading: "Frameworks" },
    { route: "/controls/builder", pageId: "control-builder", heading: "Control Builder" },
    { route: "/evidence", pageId: "evidence", heading: "Evidence" },
    { route: "/questionnaires", pageId: "questionnaires", heading: "Questionnaires" },
    { route: "/vendors", pageId: "vendors", heading: "Vendors" },
    { route: "/connectors", pageId: "connectors", heading: "Integrations" },
    { route: `/impact?root_urn=${encodeURIComponent(adminURN)}`, pageId: "impact-map", heading: "Affected assets" },
    { route: "/reports", pageId: "reports", heading: "Reports" },
    { route: "/reports/audit-packages", pageId: "audit-packages", heading: "Audit workspace" },
  ];
}
