export const AGENT_PLATFORM_CONTRACT_VERSION = "2026-06-16.cerebro-agent-platform";

export type AgentPlatformDomainId =
  | "runtime"
  | "evals"
  | "capabilities"
  | "execution"
  | "streaming-replay"
  | "connectors"
  | "knowledge";

export type AgentPlatformDomain = {
  id: AgentPlatformDomainId;
  name: string;
  principle: string;
  consoleSurface: string;
  owns: readonly string[];
  mustExpose: readonly string[];
};

export type AgentPlatformInvariant = {
  id: string;
  domainId: AgentPlatformDomainId;
  statement: string;
};

export type AgentPlatformConnectorDependency = {
  sourceId: string;
  purpose: string;
  authModels: readonly string[];
  requiredScopes: readonly string[];
  tokenOwner: string;
  credentialStore: string;
  oauthSurface: string;
  mcpSurface: string;
  tenantScoped: boolean;
  readiness: string;
};

export type AgentPlatformEvalStatus = {
  required: boolean;
  status: string;
  localCommands: readonly string[];
  scenarioSets: readonly string[];
  rubrics: readonly string[];
};

export type AgentPlatformReviewStatus = {
  state: string;
  cadence: string;
  requiredApprovers: readonly string[];
};

export type AgentPlatformCapability = {
  id: string;
  name: string;
  domainId: AgentPlatformDomainId;
  kind: string;
  version: string;
  owner: string;
  risk: "low" | "medium" | "high" | string;
  defaultOn: boolean;
  summary: string;
  consoleSurfaces: readonly string[];
  requiredScopes: readonly string[];
  connectorDependencies: readonly AgentPlatformConnectorDependency[];
  eval: AgentPlatformEvalStatus;
  runtimeEvents: readonly string[];
  provenance: readonly string[];
  review: AgentPlatformReviewStatus;
};

export type AgentPlatformRuntimeEvent = {
  name: string;
  domainId: AgentPlatformDomainId;
  stage: string;
  sequenceRequired: boolean;
  terminal: boolean;
  replayable: boolean;
  payloadFields: readonly string[];
  provenanceFields: readonly string[];
};

export type AgentPlatformProvenanceRequirement = {
  surface: string;
  domainId: AgentPlatformDomainId;
  requiredFields: readonly string[];
  citationRequired: boolean;
  budgetRequired: boolean;
  fallbackRequired: boolean;
};

export type AgentPlatformConnectorInfrastructure = {
  authModels: readonly string[];
  oauthSurfaces: readonly string[];
  credentialStores: readonly string[];
  tokenBoundaries: readonly string[];
  mcpSurfaces: readonly string[];
  requiredControls: readonly string[];
};

export type AgentPlatformContract = {
  version: string;
  domains: readonly AgentPlatformDomain[];
  invariants: readonly AgentPlatformInvariant[];
  capabilities: readonly AgentPlatformCapability[];
  runtimeEvents: readonly AgentPlatformRuntimeEvent[];
  provenanceRequirements: readonly AgentPlatformProvenanceRequirement[];
  connectorInfrastructure: AgentPlatformConnectorInfrastructure;
};

export const AGENT_PLATFORM_FALLBACK_CONTRACT: AgentPlatformContract = {
  version: AGENT_PLATFORM_CONTRACT_VERSION,
  domains: [
    {
      id: "runtime",
      name: "Contract-first runtime",
      principle: "Agent execution is typed, replayable, and isolated from product-specific orchestration.",
      consoleSurface: "Ask console, trace drawer, runtime status",
      owns: ["closed event schemas", "append-only conversation or trajectory records", "ports for LLM, graph query, persistence, and telemetry"],
      mustExpose: ["trace id", "event order", "terminal outcome", "model route"],
    },
    {
      id: "evals",
      name: "Evals as product infrastructure",
      principle: "Every agent capability has a measurable regression surface before it becomes a default workflow.",
      consoleSurface: "Developer evals",
      owns: ["golden and adversarial scenarios", "rubric outcomes", "trace-linked diagnostics", "model comparison metadata"],
      mustExpose: ["scenario id", "score", "rubric failures", "trace link"],
    },
    {
      id: "capabilities",
      name: "Capabilities as governed artifacts",
      principle: "Reusable agent behavior is packaged, versioned, and reviewed instead of hidden in prompts.",
      consoleSurface: "Security producers, policies, connector builder",
      owns: ["capability metadata", "selection rules", "review and sharing state", "safe invocation contracts"],
      mustExpose: ["capability id", "version", "owner", "selection reason"],
    },
    {
      id: "execution",
      name: "Execution behind ports",
      principle: "Stateful or risky work happens through explicit adapters with limits, cancellation, and audit.",
      consoleSurface: "Runtime response and workflow views",
      owns: ["workspace access", "shell or runtime response dispatch", "side-effect fencing", "result capture and truncation markers"],
      mustExpose: ["adapter kind", "scope", "limits", "cancel state", "truncation state"],
    },
    {
      id: "streaming-replay",
      name: "Streaming and replay discipline",
      principle: "Live execution, durable records, and replay/debug views use one ordered event vocabulary.",
      consoleSurface: "Ask trace drawer and eval artifacts",
      owns: ["monotonic event sequencing", "trajectory persistence", "runtime debugger inputs", "replay fixtures"],
      mustExpose: ["sequence", "stage", "redaction status", "replay source"],
    },
    {
      id: "connectors",
      name: "Connector identity and OAuth boundaries",
      principle: "Integrations are authenticated channels with clear public/private surfaces and token ownership.",
      consoleSurface: "Connectors, identity contract, MCP status",
      owns: ["connector catalog contracts", "OAuth/token lifecycle", "MCP access", "credential store boundaries"],
      mustExpose: ["principal", "tenant", "scopes", "token owner", "surface"],
    },
    {
      id: "knowledge",
      name: "Knowledge with provenance and budgets",
      principle: "Retrieved context is bounded, cited, instruction-safe, and non-blocking when unavailable.",
      consoleSurface: "Graph answers, evidence, inventory, findings",
      owns: ["graph and knowledge retrieval", "citation validation", "context budgets", "best-effort ingestion"],
      mustExpose: ["source urn", "scope", "budget", "citation status", "fallback reason"],
    },
  ],
  invariants: [
    { id: "CAP-01", domainId: "capabilities", statement: "A capability used by an agent run must be identifiable by id and version." },
    { id: "CONN-01", domainId: "connectors", statement: "A connector token must not be consumed outside its declared owner surface." },
    { id: "EVAL-01", domainId: "evals", statement: "A default-on agent capability must have at least one local regression path." },
    { id: "EXEC-01", domainId: "execution", statement: "Adapters report cancellation and truncation explicitly instead of hiding partial results." },
    { id: "KNOW-01", domainId: "knowledge", statement: "Retrieved context must carry source scope and citation status when shown to a user or model." },
    { id: "RUN-01", domainId: "runtime", statement: "Consumer-visible events use stable names and a single terminal outcome per logical run." },
    { id: "STREAM-01", domainId: "streaming-replay", statement: "Replay records preserve event order even when payloads are redacted or truncated." },
  ],
  capabilities: [
    {
      id: "grc-ask",
      name: "GRC ask workflow",
      domainId: "runtime",
      kind: "agent-workflow",
      version: "1.0.0",
      owner: "cerebro-platform",
      risk: "medium",
      defaultOn: true,
      summary: "Answers security and compliance questions from graph, findings, evidence, and runtime context.",
      consoleSurfaces: ["Ask console", "GRC dashboard", "trace drawer"],
      requiredScopes: ["cosmo.security.read"],
      connectorDependencies: [],
      eval: {
        required: true,
        status: "required",
        localCommands: ["npm run eval:ask:local", "npm run eval:ask:adversarial"],
        scenarioSets: ["ask-golden", "ask-adversarial"],
        rubrics: ["groundedness", "source use", "safe refusal", "answer completeness"],
      },
      runtimeEvents: ["agent.run.started", "capability.selected", "knowledge.retrieval.completed", "agent.run.completed", "agent.run.failed"],
      provenance: ["ask-answer"],
      review: { state: "required", cadence: "before default workflow changes", requiredApprovers: ["platform", "security"] },
    },
    {
      id: "security-eval-harness",
      name: "Security eval harness",
      domainId: "evals",
      kind: "eval-suite",
      version: "1.0.0",
      owner: "cerebro-platform",
      risk: "low",
      defaultOn: true,
      summary: "Runs golden and adversarial scenarios with trace-linked rubric outcomes for agent-facing workflows.",
      consoleSurfaces: ["Developer evals", "pull request checks"],
      requiredScopes: ["cosmo.security.read"],
      connectorDependencies: [],
      eval: {
        required: true,
        status: "self-covered",
        localCommands: ["npm run eval:security-agent:local"],
        scenarioSets: ["security-agent-golden"],
        rubrics: ["triage accuracy", "evidence quality", "risk calibration"],
      },
      runtimeEvents: ["eval.scenario.started", "eval.scenario.completed"],
      provenance: ["eval-result"],
      review: { state: "required", cadence: "with rubric or fixture changes", requiredApprovers: ["platform"] },
    },
    {
      id: "trace-streaming-replay",
      name: "Trace streaming and replay",
      domainId: "streaming-replay",
      kind: "event-contract",
      version: "1.0.0",
      owner: "cerebro-platform",
      risk: "medium",
      defaultOn: true,
      summary: "Keeps live execution, persisted traces, eval artifacts, and replay fixtures on one ordered event vocabulary.",
      consoleSurfaces: ["trace drawer", "Developer evals", "workflow replay"],
      requiredScopes: ["cosmo.security.read"],
      connectorDependencies: [],
      eval: {
        required: true,
        status: "required",
        localCommands: ["go test ./internal/workflowevents ./internal/bootstrap -run Test.*Replay"],
        scenarioSets: ["trace-replay", "redacted-event-replay"],
        rubrics: ["event ordering", "terminal outcome", "redaction status", "replay source"],
      },
      runtimeEvents: ["agent.run.started", "capability.selected", "agent.run.completed", "agent.run.failed", "eval.scenario.completed"],
      provenance: ["replay-record"],
      review: { state: "required", cadence: "with event schema or replay fixture changes", requiredApprovers: ["platform"] },
    },
    {
      id: "connector-oauth-mcp",
      name: "Connector OAuth and MCP boundary",
      domainId: "connectors",
      kind: "integration-infrastructure",
      version: "1.0.0",
      owner: "cerebro-platform",
      risk: "high",
      defaultOn: true,
      summary: "Makes connector identity, OAuth token ownership, credential storage, and MCP exposure explicit platform contracts.",
      consoleSurfaces: ["Connectors", "connector builder", "MCP status"],
      requiredScopes: ["cosmo.security.read", "connector.credentials.read", "connector.credentials.write"],
      connectorDependencies: [
        {
          sourceId: "catalog-managed",
          purpose: "Connector setup, credential lifecycle, runtime sync, and MCP tool exposure.",
          authModels: ["oauth_authorization_code", "oauth_client_credentials", "api_key", "environment_reference", "external_secret_reference"],
          requiredScopes: ["connector.credentials.read", "connector.credentials.write"],
          tokenOwner: "declared connector surface",
          credentialStore: "tenant-scoped credential broker or declared external reference",
          oauthSurface: "/oauth/* and /.well-known/oauth-*",
          mcpSurface: "/api/v1/mcp",
          tenantScoped: true,
          readiness: "required",
        },
      ],
      eval: {
        required: true,
        status: "required",
        localCommands: ["go test ./internal/bootstrap -run 'Test.*OAuth|Test.*MCP|TestConnector'"],
        scenarioSets: ["connector-auth-boundaries", "mcp-protected-resource"],
        rubrics: ["token owner isolation", "scope enforcement", "tenant isolation", "credential redaction"],
      },
      runtimeEvents: ["connector.auth.boundary.checked", "adapter.execution.started", "adapter.execution.completed"],
      provenance: ["connector-call", "mcp-tool-result"],
      review: { state: "required", cadence: "before auth surface or connector catalog changes", requiredApprovers: ["platform", "security"] },
    },
    {
      id: "source-runtime-sync",
      name: "Source runtime sync",
      domainId: "execution",
      kind: "runtime-adapter",
      version: "1.0.0",
      owner: "cerebro-platform",
      risk: "medium",
      defaultOn: true,
      summary: "Runs source sync, graph ingest, claim writes, and finding evaluation through explicit runtime adapters.",
      consoleSurfaces: ["Source runtimes", "runtime freshness", "ingest health"],
      requiredScopes: ["cosmo.security.read"],
      connectorDependencies: [],
      eval: {
        required: true,
        status: "required",
        localCommands: ["go test ./internal/bootstrap -run Test.*SourceRuntime"],
        scenarioSets: ["runtime-sync-health", "finding-evaluation"],
        rubrics: ["adapter status", "cancellation state", "truncation state", "tenant scope"],
      },
      runtimeEvents: ["adapter.execution.started", "adapter.execution.completed", "adapter.execution.failed"],
      provenance: ["source-runtime-event"],
      review: { state: "required", cadence: "with runtime adapter changes", requiredApprovers: ["platform"] },
    },
    {
      id: "finding-rule-evaluation",
      name: "Finding rule evaluation",
      domainId: "capabilities",
      kind: "governed-capability",
      version: "1.0.0",
      owner: "cerebro-platform",
      risk: "medium",
      defaultOn: true,
      summary: "Packages finding candidate promotion, rejection, and rule evaluation as reviewable capability behavior.",
      consoleSurfaces: ["Finding rules", "source runtime finding evaluations", "GRC findings"],
      requiredScopes: ["cosmo.security.read", "finding.candidate.promote"],
      connectorDependencies: [],
      eval: {
        required: true,
        status: "required",
        localCommands: ["go test ./internal/findings"],
        scenarioSets: ["finding-rule-fixtures"],
        rubrics: ["precision", "recall", "evidence sufficiency", "risk reason quality"],
      },
      runtimeEvents: ["capability.selected", "eval.scenario.completed"],
      provenance: ["finding-evidence", "finding-evaluation-run"],
      review: { state: "required", cadence: "before promotion or rule behavior changes", requiredApprovers: ["security"] },
    },
    {
      id: "runtime-response-actions",
      name: "Runtime response actions",
      domainId: "execution",
      kind: "side-effect-adapter",
      version: "1.0.0",
      owner: "cerebro-platform",
      risk: "high",
      defaultOn: false,
      summary: "Executes explicit containment actions through scoped adapters with audit, cancellation, and result capture.",
      consoleSurfaces: ["Runtime response", "workflow actions", "blocklist"],
      requiredScopes: ["runtime.response.write"],
      connectorDependencies: [],
      eval: {
        required: true,
        status: "required",
        localCommands: ["go test ./internal/bootstrap -run TestRecordRuntimeResponseWorkflowAppendsActionEvent"],
        scenarioSets: ["runtime-response-actions"],
        rubrics: ["trusted-scope enforcement", "audit completeness", "result status"],
      },
      runtimeEvents: ["adapter.execution.started", "adapter.execution.completed", "adapter.execution.failed"],
      provenance: ["runtime-response-action"],
      review: { state: "required", cadence: "before adding or changing mutating actions", requiredApprovers: ["platform", "security"] },
    },
    {
      id: "knowledge-provenance",
      name: "Knowledge provenance",
      domainId: "knowledge",
      kind: "retrieval-contract",
      version: "1.0.0",
      owner: "cerebro-platform",
      risk: "medium",
      defaultOn: true,
      summary: "Requires cited, scoped, budgeted context with explicit fallback when graph or evidence is unavailable.",
      consoleSurfaces: ["Graph answers", "evidence", "inventory", "findings"],
      requiredScopes: ["cosmo.security.read"],
      connectorDependencies: [],
      eval: {
        required: true,
        status: "required",
        localCommands: ["go test ./internal/bootstrap -run 'Test.*GRC|Test.*Evidence|Test.*Inventory'"],
        scenarioSets: ["knowledge-provenance", "citation-status"],
        rubrics: ["citation coverage", "scope preservation", "fallback clarity", "context budget"],
      },
      runtimeEvents: ["knowledge.retrieval.completed", "agent.run.completed", "agent.run.failed"],
      provenance: ["knowledge-context", "graph-neighborhood", "evidence-record"],
      review: { state: "required", cadence: "with retrieval or user-visible answer changes", requiredApprovers: ["platform", "security"] },
    },
  ],
  runtimeEvents: [
    { name: "agent.run.started", domainId: "runtime", stage: "start", sequenceRequired: true, terminal: false, replayable: true, payloadFields: ["trace_id", "tenant_id", "capability_hint", "model_route"], provenanceFields: ["trace_id", "scope"] },
    { name: "capability.selected", domainId: "capabilities", stage: "selection", sequenceRequired: true, terminal: false, replayable: true, payloadFields: ["capability_id", "version", "selection_reason", "owner"], provenanceFields: ["capability_id", "version", "selection_reason"] },
    { name: "connector.auth.boundary.checked", domainId: "connectors", stage: "authorization", sequenceRequired: true, terminal: false, replayable: true, payloadFields: ["source_id", "principal", "tenant", "scopes", "token_owner", "surface"], provenanceFields: ["source_urn", "scope", "token_owner"] },
    { name: "knowledge.retrieval.completed", domainId: "knowledge", stage: "retrieval", sequenceRequired: true, terminal: false, replayable: true, payloadFields: ["source_urn", "scope", "budget", "citation_status", "fallback_reason"], provenanceFields: ["source_urn", "scope", "citation_status", "fallback_reason"] },
    { name: "adapter.execution.started", domainId: "execution", stage: "execution", sequenceRequired: true, terminal: false, replayable: true, payloadFields: ["adapter_kind", "scope", "limits"], provenanceFields: ["scope", "adapter_kind"] },
    { name: "adapter.execution.completed", domainId: "execution", stage: "terminal", sequenceRequired: true, terminal: false, replayable: true, payloadFields: ["adapter_kind", "cancel_state", "truncation_state", "result_ref"], provenanceFields: ["scope", "adapter_kind", "truncation_state"] },
    { name: "adapter.execution.failed", domainId: "execution", stage: "terminal", sequenceRequired: true, terminal: true, replayable: true, payloadFields: ["adapter_kind", "cancel_state", "truncation_state", "error_class"], provenanceFields: ["scope", "adapter_kind", "truncation_state"] },
    { name: "eval.scenario.started", domainId: "evals", stage: "start", sequenceRequired: true, terminal: false, replayable: true, payloadFields: ["scenario_id", "capability_id", "model_route"], provenanceFields: ["scenario_id", "capability_id"] },
    { name: "eval.scenario.completed", domainId: "evals", stage: "terminal", sequenceRequired: true, terminal: true, replayable: true, payloadFields: ["scenario_id", "score", "rubric_failures", "trace_link"], provenanceFields: ["scenario_id", "score", "trace_link"] },
    { name: "agent.run.completed", domainId: "runtime", stage: "terminal", sequenceRequired: true, terminal: true, replayable: true, payloadFields: ["trace_id", "terminal_outcome", "model_route", "redaction_status"], provenanceFields: ["trace_id", "terminal_outcome"] },
    { name: "agent.run.failed", domainId: "runtime", stage: "terminal", sequenceRequired: true, terminal: true, replayable: true, payloadFields: ["trace_id", "terminal_outcome", "error_class", "redaction_status"], provenanceFields: ["trace_id", "terminal_outcome"] },
  ],
  provenanceRequirements: [
    { surface: "ask-answer", domainId: "knowledge", requiredFields: ["source_urn", "scope", "budget", "citation_status", "fallback_reason"], citationRequired: true, budgetRequired: true, fallbackRequired: true },
    { surface: "connector-call", domainId: "connectors", requiredFields: ["source_urn", "principal", "tenant", "scopes", "token_owner", "surface"], citationRequired: false, budgetRequired: false, fallbackRequired: true },
    { surface: "mcp-tool-result", domainId: "connectors", requiredFields: ["source_urn", "principal", "tenant", "scopes", "token_owner", "surface", "tool_name"], citationRequired: false, budgetRequired: false, fallbackRequired: true },
    { surface: "source-runtime-event", domainId: "execution", requiredFields: ["runtime_id", "source_urn", "tenant", "adapter_kind", "scope", "truncation_state"], citationRequired: false, budgetRequired: false, fallbackRequired: false },
    { surface: "runtime-response-action", domainId: "execution", requiredFields: ["adapter_kind", "scope", "limits", "cancel_state", "truncation_state"], citationRequired: false, budgetRequired: false, fallbackRequired: false },
    { surface: "eval-result", domainId: "evals", requiredFields: ["scenario_id", "score", "rubric_failures", "trace_link"], citationRequired: false, budgetRequired: false, fallbackRequired: false },
    { surface: "replay-record", domainId: "streaming-replay", requiredFields: ["trace_id", "sequence", "stage", "redaction_status", "replay_source", "terminal_outcome"], citationRequired: false, budgetRequired: false, fallbackRequired: false },
    { surface: "finding-evaluation-run", domainId: "capabilities", requiredFields: ["run_id", "runtime_id", "source_urn", "score", "rubric_failures", "trace_link"], citationRequired: false, budgetRequired: false, fallbackRequired: false },
    { surface: "finding-evidence", domainId: "capabilities", requiredFields: ["source_urn", "scope", "citation_status", "evidence_id"], citationRequired: true, budgetRequired: false, fallbackRequired: false },
    { surface: "knowledge-context", domainId: "knowledge", requiredFields: ["source_urn", "scope", "budget", "citation_status", "fallback_reason"], citationRequired: true, budgetRequired: true, fallbackRequired: true },
    { surface: "graph-neighborhood", domainId: "knowledge", requiredFields: ["source_urn", "scope", "entity_urn", "budget", "citation_status", "fallback_reason"], citationRequired: true, budgetRequired: true, fallbackRequired: true },
    { surface: "evidence-record", domainId: "knowledge", requiredFields: ["source_urn", "scope", "evidence_id", "citation_status"], citationRequired: true, budgetRequired: false, fallbackRequired: false },
  ],
  connectorInfrastructure: {
    authModels: ["oauth_authorization_code", "oauth_client_credentials", "api_key", "environment_reference", "external_secret_reference"],
    oauthSurfaces: [
      "/.well-known/oauth-protected-resource",
      "/.well-known/oauth-protected-resource/api/v1/mcp",
      "/.well-known/oauth-authorization-server",
      "/oauth/authorize",
      "/oauth/callback",
      "/oauth/token",
      "/oauth/revoke",
      "/oauth/register",
    ],
    credentialStores: ["tenant-scoped credential broker", "environment", "external-reference"],
    tokenBoundaries: ["principal", "tenant", "scopes", "token owner", "surface", "resource"],
    mcpSurfaces: ["/api/v1/mcp"],
    requiredControls: [
      "protected-resource metadata for MCP",
      "read/write credential scopes",
      "tenant-scoped token exchange",
      "credential rotation and revocation",
      "connector preflight before connection creation",
      "secret redaction in UI, API, logs, traces, and eval artifacts",
    ],
  },
};

export const AGENT_PLATFORM_DOMAINS = AGENT_PLATFORM_FALLBACK_CONTRACT.domains;
export const AGENT_PLATFORM_INVARIANTS = AGENT_PLATFORM_FALLBACK_CONTRACT.invariants;

type UnknownRecord = Record<string, unknown>;

export function normalizeAgentPlatformContract(input: unknown): AgentPlatformContract {
  if (!isRecord(input)) return AGENT_PLATFORM_FALLBACK_CONTRACT;
  const version = readString(input, "version") || AGENT_PLATFORM_CONTRACT_VERSION;
  const domains = readArray(input, "domains").map(normalizeDomain).filter(isAgentPlatformDomain);
  const invariants = readArray(input, "invariants").map(normalizeInvariant).filter(isAgentPlatformInvariant);
  const capabilities = readArray(input, "capabilities").map(normalizeCapability).filter(isAgentPlatformCapability);
  const runtimeEvents = readArray(input, "runtimeEvents", "runtime_events").map(normalizeRuntimeEvent).filter(isAgentPlatformRuntimeEvent);
  const provenanceRequirements = readArray(input, "provenanceRequirements", "provenance_requirements")
    .map(normalizeProvenanceRequirement)
    .filter(isAgentPlatformProvenanceRequirement);
  const connectorInfrastructure = normalizeConnectorInfrastructure(readRecord(input, "connectorInfrastructure", "connector_infrastructure"));

  if (domains.length === 0 || invariants.length === 0) {
    return AGENT_PLATFORM_FALLBACK_CONTRACT;
  }
  return {
    version,
    domains,
    invariants,
    capabilities,
    runtimeEvents,
    provenanceRequirements,
    connectorInfrastructure,
  };
}

export function agentPlatformDomainById(id: AgentPlatformDomainId | string, contract: AgentPlatformContract = AGENT_PLATFORM_FALLBACK_CONTRACT) {
  return contract.domains.find((domain) => domain.id === id);
}

export function agentPlatformCapabilitiesByDomain(contract: AgentPlatformContract = AGENT_PLATFORM_FALLBACK_CONTRACT) {
  const grouped = new Map<AgentPlatformDomainId, AgentPlatformCapability[]>();
  for (const domain of contract.domains) {
    grouped.set(domain.id, []);
  }
  for (const capability of contract.capabilities) {
    const existing = grouped.get(capability.domainId) ?? [];
    existing.push(capability);
    grouped.set(capability.domainId, existing);
  }
  return grouped;
}

function normalizeDomain(value: unknown): AgentPlatformDomain | null {
  if (!isRecord(value)) return null;
  return {
    id: readDomainId(value, "id"),
    name: readString(value, "name"),
    principle: readString(value, "principle"),
    consoleSurface: readString(value, "consoleSurface", "console_surface"),
    owns: readStringArray(value, "owns"),
    mustExpose: readStringArray(value, "mustExpose", "must_expose", "diagnostics"),
  };
}

function normalizeInvariant(value: unknown): AgentPlatformInvariant | null {
  if (!isRecord(value)) return null;
  return {
    id: readString(value, "id"),
    domainId: readDomainId(value, "domainId", "domain_id"),
    statement: readString(value, "statement"),
  };
}

function normalizeCapability(value: unknown): AgentPlatformCapability | null {
  if (!isRecord(value)) return null;
  return {
    id: readString(value, "id"),
    name: readString(value, "name"),
    domainId: readDomainId(value, "domainId", "domain_id"),
    kind: readString(value, "kind"),
    version: readString(value, "version"),
    owner: readString(value, "owner"),
    risk: readString(value, "risk"),
    defaultOn: readBoolean(value, "defaultOn", "default_on"),
    summary: readString(value, "summary"),
    consoleSurfaces: readStringArray(value, "consoleSurfaces", "console_surfaces"),
    requiredScopes: readStringArray(value, "requiredScopes", "required_scopes"),
    connectorDependencies: readArray(value, "connectorDependencies", "connector_dependencies").map(normalizeConnectorDependency).filter(isAgentPlatformConnectorDependency),
    eval: normalizeEvalStatus(readRecord(value, "eval")),
    runtimeEvents: readStringArray(value, "runtimeEvents", "runtime_events"),
    provenance: readStringArray(value, "provenance"),
    review: normalizeReviewStatus(readRecord(value, "review")),
  };
}

function normalizeConnectorDependency(value: unknown): AgentPlatformConnectorDependency | null {
  if (!isRecord(value)) return null;
  return {
    sourceId: readString(value, "sourceId", "source_id"),
    purpose: readString(value, "purpose"),
    authModels: readStringArray(value, "authModels", "auth_models"),
    requiredScopes: readStringArray(value, "requiredScopes", "required_scopes"),
    tokenOwner: readString(value, "tokenOwner", "token_owner"),
    credentialStore: readString(value, "credentialStore", "credential_store"),
    oauthSurface: readString(value, "oauthSurface", "oauth_surface"),
    mcpSurface: readString(value, "mcpSurface", "mcp_surface"),
    tenantScoped: readBoolean(value, "tenantScoped", "tenant_scoped"),
    readiness: readString(value, "readiness"),
  };
}

function normalizeEvalStatus(value: UnknownRecord | null): AgentPlatformEvalStatus {
  if (!value) return { required: false, status: "", localCommands: [], scenarioSets: [], rubrics: [] };
  return {
    required: readBoolean(value, "required"),
    status: readString(value, "status"),
    localCommands: readStringArray(value, "localCommands", "local_commands"),
    scenarioSets: readStringArray(value, "scenarioSets", "scenario_sets"),
    rubrics: readStringArray(value, "rubrics"),
  };
}

function normalizeReviewStatus(value: UnknownRecord | null): AgentPlatformReviewStatus {
  if (!value) return { state: "", cadence: "", requiredApprovers: [] };
  return {
    state: readString(value, "state"),
    cadence: readString(value, "cadence"),
    requiredApprovers: readStringArray(value, "requiredApprovers", "required_approvers"),
  };
}

function normalizeRuntimeEvent(value: unknown): AgentPlatformRuntimeEvent | null {
  if (!isRecord(value)) return null;
  return {
    name: readString(value, "name"),
    domainId: readDomainId(value, "domainId", "domain_id"),
    stage: readString(value, "stage"),
    sequenceRequired: readBoolean(value, "sequenceRequired", "sequence_required"),
    terminal: readBoolean(value, "terminal"),
    replayable: readBoolean(value, "replayable"),
    payloadFields: readStringArray(value, "payloadFields", "payload_fields"),
    provenanceFields: readStringArray(value, "provenanceFields", "provenance_fields"),
  };
}

function normalizeProvenanceRequirement(value: unknown): AgentPlatformProvenanceRequirement | null {
  if (!isRecord(value)) return null;
  return {
    surface: readString(value, "surface"),
    domainId: readDomainId(value, "domainId", "domain_id"),
    requiredFields: readStringArray(value, "requiredFields", "required_fields"),
    citationRequired: readBoolean(value, "citationRequired", "citation_required"),
    budgetRequired: readBoolean(value, "budgetRequired", "budget_required"),
    fallbackRequired: readBoolean(value, "fallbackRequired", "fallback_required"),
  };
}

function normalizeConnectorInfrastructure(value: UnknownRecord | null): AgentPlatformConnectorInfrastructure {
  if (!value) return AGENT_PLATFORM_FALLBACK_CONTRACT.connectorInfrastructure;
  return {
    authModels: readStringArray(value, "authModels", "auth_models"),
    oauthSurfaces: readStringArray(value, "oauthSurfaces", "oauth_surfaces"),
    credentialStores: readStringArray(value, "credentialStores", "credential_stores"),
    tokenBoundaries: readStringArray(value, "tokenBoundaries", "token_boundaries"),
    mcpSurfaces: readStringArray(value, "mcpSurfaces", "mcp_surfaces"),
    requiredControls: readStringArray(value, "requiredControls", "required_controls"),
  };
}

function isAgentPlatformDomain(value: AgentPlatformDomain | null): value is AgentPlatformDomain {
  return Boolean(value?.id && value.name && value.principle && value.consoleSurface);
}

function isAgentPlatformInvariant(value: AgentPlatformInvariant | null): value is AgentPlatformInvariant {
  return Boolean(value?.id && value.domainId && value.statement);
}

function isAgentPlatformCapability(value: AgentPlatformCapability | null): value is AgentPlatformCapability {
  return Boolean(value?.id && value.name && value.domainId && value.version);
}

function isAgentPlatformConnectorDependency(value: AgentPlatformConnectorDependency | null): value is AgentPlatformConnectorDependency {
  return Boolean(value?.sourceId && value.authModels.length > 0);
}

function isAgentPlatformRuntimeEvent(value: AgentPlatformRuntimeEvent | null): value is AgentPlatformRuntimeEvent {
  return Boolean(value?.name && value.domainId && value.payloadFields.length > 0);
}

function isAgentPlatformProvenanceRequirement(value: AgentPlatformProvenanceRequirement | null): value is AgentPlatformProvenanceRequirement {
  return Boolean(value?.surface && value.domainId && value.requiredFields.length > 0);
}

function readDomainId(record: UnknownRecord, ...keys: string[]): AgentPlatformDomainId {
  const value = readString(record, ...keys);
  if (isAgentPlatformDomainId(value)) return value;
  return "runtime";
}

function isAgentPlatformDomainId(value: string): value is AgentPlatformDomainId {
  return AGENT_PLATFORM_FALLBACK_CONTRACT.domains.some((domain) => domain.id === value);
}

function readRecord(record: UnknownRecord, ...keys: string[]) {
  for (const key of keys) {
    const value = record[key];
    if (isRecord(value)) return value;
  }
  return null;
}

function readArray(record: UnknownRecord, ...keys: string[]) {
  for (const key of keys) {
    const value = record[key];
    if (Array.isArray(value)) return value;
  }
  return [];
}

function readStringArray(record: UnknownRecord, ...keys: string[]) {
  return readArray(record, ...keys).filter((value): value is string => typeof value === "string");
}

function readString(record: UnknownRecord, ...keys: string[]) {
  for (const key of keys) {
    const value = record[key];
    if (typeof value === "string") return value;
  }
  return "";
}

function readBoolean(record: UnknownRecord, ...keys: string[]) {
  for (const key of keys) {
    const value = record[key];
    if (typeof value === "boolean") return value;
  }
  return false;
}

function isRecord(value: unknown): value is UnknownRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
