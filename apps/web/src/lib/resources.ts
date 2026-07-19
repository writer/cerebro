export type ManualOperation = {
  tag: string;
  path: string;
  summary: string;
  description?: string;
  params?: string[];
  response?: "json" | "text";
};

export const manualTags: Record<string, string> = {
  System: "Health and API metadata.",
  Sources: "Registered source integrations and preview helpers.",
  Connectors: "Connector library, runtime status, and credential transport metadata.",
  "Source Runtimes": "Persisted runtime configs, sync state, claims, evidence, and findings.",
  Findings: "Finding rules, finding detail, evidence, and evaluation runs.",
  GRC: "Dashboard, controls, audit packets, evidence, and GRC finding views.",
  Reports: "Report definitions and durable report runs.",
  Platform: "Platform knowledge and automation APIs.",
  Graph: "Graph neighborhoods, impact queries, ingest health, and ingest run status.",
};

export const manualOperations: ManualOperation[] = [
  { tag: "System", path: "/health", summary: "Health check" },
  { tag: "System", path: "/healthz", summary: "Health check alias" },
  { tag: "System", path: "/openapi.yaml", summary: "OpenAPI YAML", response: "text" },
  { tag: "Sources", path: "/sources", summary: "List registered sources" },
  {
    tag: "Sources",
    path: "/sources/:sourceID/check",
    summary: "Check source configuration",
    params: ["sourceID"],
  },
  {
    tag: "Sources",
    path: "/sources/:sourceID/discover",
    summary: "Discover source URNs",
    params: ["sourceID"],
  },
  {
    tag: "Sources",
    path: "/sources/:sourceID/read",
    summary: "Read one source preview page",
    params: ["sourceID"],
  },
  {
    tag: "Connectors",
    path: "/connectors",
    summary: "List available connectors and connection health",
  },
  {
    tag: "Connectors",
    path: "/connectors/credential-key",
    summary: "Get the public credential transport key",
  },
  {
    tag: "Source Runtimes",
    path: "/source-runtimes",
    summary: "List source runtime configurations",
  },
  {
    tag: "Source Runtimes",
    path: "/source-runtimes/health",
    summary: "List source runtime health, sync, watermark, graph, and finding-evaluation state",
  },
  {
    tag: "Source Runtimes",
    path: "/source-runtimes/:runtimeID",
    summary: "Get source runtime configuration",
    params: ["runtimeID"],
  },
  {
    tag: "Source Runtimes",
    path: "/source-runtimes/:runtimeID/claims",
    summary: "List runtime claims",
    params: ["runtimeID"],
  },
  {
    tag: "Source Runtimes",
    path: "/source-runtimes/:runtimeID/findings",
    summary: "List runtime findings",
    params: ["runtimeID"],
  },
  {
    tag: "Source Runtimes",
    path: "/source-runtimes/:runtimeID/finding-evidence",
    summary: "List runtime finding evidence",
    params: ["runtimeID"],
  },
  {
    tag: "Source Runtimes",
    path: "/source-runtimes/:runtimeID/finding-evaluation-runs",
    summary: "List runtime finding evaluation runs",
    params: ["runtimeID"],
  },
  { tag: "Findings", path: "/finding-rules", summary: "List finding rules" },
  {
    tag: "Findings",
    path: "/findings/:findingID",
    summary: "Get finding",
    params: ["findingID"],
  },
  {
    tag: "Findings",
    path: "/finding-evaluation-runs/:runID",
    summary: "Get finding evaluation run",
    params: ["runID"],
  },
  {
    tag: "Findings",
    path: "/finding-evidence/:evidenceID",
    summary: "Get finding evidence",
    params: ["evidenceID"],
  },
  { tag: "Reports", path: "/reports", summary: "List report definitions" },
  {
    tag: "Reports",
    path: "/report-runs/:runID",
    summary: "Get report run",
    params: ["runID"],
  },
  {
    tag: "Graph",
    path: "/platform/graph/neighborhood",
    summary: "Query graph neighborhood",
  },
  {
    tag: "Graph",
    path: "/platform/graph/impact/vulnerability/:id",
    summary: "Query vulnerability impact graph",
    params: ["id"],
  },
  {
    tag: "Graph",
    path: "/platform/graph/impact/package",
    summary: "Query package exposure graph",
  },
  {
    tag: "Graph",
    path: "/platform/graph/impact/asset",
    summary: "Query asset vulnerability graph",
  },
  { tag: "Graph", path: "/platform/graph/ingest-health", summary: "Check graph ingest health" },
  { tag: "Graph", path: "/platform/graph/ingest-runs", summary: "List graph ingest runs" },
  {
    tag: "Graph",
    path: "/platform/graph/ingest-runs/:runID",
    summary: "Get graph ingest run",
    params: ["runID"],
  },
];
