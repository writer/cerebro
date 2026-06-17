// Package agentplatform names the Cerebro-native agent platform contract.
//
// The package is intentionally small and dependency-free. It gives docs,
// tests, API handlers, and UI clients one stable vocabulary for the pieces
// Cerebro expects every agent-facing capability to preserve.
package agentplatform

const ContractVersion = "2026-06-16.cerebro-agent-platform"

type Contract struct {
	Version                 string                  `json:"version"`
	Domains                 []Domain                `json:"domains"`
	Invariants              []Invariant             `json:"invariants"`
	Capabilities            []Capability            `json:"capabilities"`
	RuntimeEvents           []RuntimeEvent          `json:"runtime_events"`
	ProvenanceRequirements  []ProvenanceRequirement `json:"provenance_requirements"`
	ConnectorInfrastructure ConnectorInfrastructure `json:"connector_infrastructure"`
	SecurityControlPlane    SecurityControlPlane    `json:"security_control_plane"`
}

type Domain struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Principle      string   `json:"principle"`
	ConsoleSurface string   `json:"console_surface"`
	Owns           []string `json:"owns"`
	MustExpose     []string `json:"must_expose"`
}

type Invariant struct {
	ID        string `json:"id"`
	DomainID  string `json:"domain_id"`
	Statement string `json:"statement"`
}

type Capability struct {
	ID                    string                `json:"id"`
	Name                  string                `json:"name"`
	DomainID              string                `json:"domain_id"`
	Kind                  string                `json:"kind"`
	Version               string                `json:"version"`
	Owner                 string                `json:"owner"`
	Risk                  string                `json:"risk"`
	DefaultOn             bool                  `json:"default_on"`
	Summary               string                `json:"summary"`
	ConsoleSurfaces       []string              `json:"console_surfaces"`
	RequiredScopes        []string              `json:"required_scopes"`
	ConnectorDependencies []ConnectorDependency `json:"connector_dependencies,omitempty"`
	Eval                  EvalStatus            `json:"eval"`
	RuntimeEvents         []string              `json:"runtime_events"`
	Provenance            []string              `json:"provenance"`
	Review                ReviewStatus          `json:"review"`
}

type ConnectorDependency struct {
	SourceID        string   `json:"source_id"`
	Purpose         string   `json:"purpose"`
	AuthModels      []string `json:"auth_models"`
	RequiredScopes  []string `json:"required_scopes"`
	TokenOwner      string   `json:"token_owner"`
	CredentialStore string   `json:"credential_store"`
	OAuthSurface    string   `json:"oauth_surface"`
	MCPSurface      string   `json:"mcp_surface"`
	TenantScoped    bool     `json:"tenant_scoped"`
	Readiness       string   `json:"readiness"`
}

type EvalStatus struct {
	Required      bool     `json:"required"`
	Status        string   `json:"status"`
	LocalCommands []string `json:"local_commands"`
	ScenarioSets  []string `json:"scenario_sets"`
	Rubrics       []string `json:"rubrics"`
}

type ReviewStatus struct {
	State             string   `json:"state"`
	Cadence           string   `json:"cadence"`
	RequiredApprovers []string `json:"required_approvers"`
}

type RuntimeEvent struct {
	Name             string   `json:"name"`
	DomainID         string   `json:"domain_id"`
	Stage            string   `json:"stage"`
	SequenceRequired bool     `json:"sequence_required"`
	Terminal         bool     `json:"terminal"`
	Replayable       bool     `json:"replayable"`
	PayloadFields    []string `json:"payload_fields"`
	ProvenanceFields []string `json:"provenance_fields"`
}

type ProvenanceRequirement struct {
	Surface          string   `json:"surface"`
	DomainID         string   `json:"domain_id"`
	RequiredFields   []string `json:"required_fields"`
	CitationRequired bool     `json:"citation_required"`
	BudgetRequired   bool     `json:"budget_required"`
	FallbackRequired bool     `json:"fallback_required"`
}

type ConnectorInfrastructure struct {
	AuthModels       []string `json:"auth_models"`
	OAuthSurfaces    []string `json:"oauth_surfaces"`
	CredentialStores []string `json:"credential_stores"`
	TokenBoundaries  []string `json:"token_boundaries"`
	MCPSurfaces      []string `json:"mcp_surfaces"`
	RequiredControls []string `json:"required_controls"`
}

var Domains = []Domain{
	{
		ID:             "runtime",
		Name:           "Contract-first runtime",
		Principle:      "Agent execution is typed, replayable, and isolated from product-specific orchestration.",
		ConsoleSurface: "Ask console, trace drawer, runtime status",
		Owns: []string{
			"closed event schemas",
			"append-only conversation or trajectory records",
			"ports for LLM, graph query, persistence, and telemetry",
		},
		MustExpose: []string{"trace id", "event order", "terminal outcome", "model route"},
	},
	{
		ID:             "evals",
		Name:           "Evals as product infrastructure",
		Principle:      "Every agent capability has a measurable regression surface before it becomes a default workflow.",
		ConsoleSurface: "Developer evals",
		Owns: []string{
			"golden and adversarial scenarios",
			"rubric outcomes",
			"trace-linked diagnostics",
			"model comparison metadata",
		},
		MustExpose: []string{"scenario id", "score", "rubric failures", "trace link"},
	},
	{
		ID:             "capabilities",
		Name:           "Capabilities as governed artifacts",
		Principle:      "Reusable agent behavior is packaged, versioned, and reviewed instead of hidden in prompts.",
		ConsoleSurface: "Security producers, policies, connector builder",
		Owns: []string{
			"capability metadata",
			"selection rules",
			"review and sharing state",
			"safe invocation contracts",
		},
		MustExpose: []string{"capability id", "version", "owner", "selection reason"},
	},
	{
		ID:             "execution",
		Name:           "Execution behind ports",
		Principle:      "Stateful or risky work happens through explicit adapters with limits, cancellation, and audit.",
		ConsoleSurface: "Runtime response and workflow views",
		Owns: []string{
			"workspace access",
			"shell or runtime response dispatch",
			"side-effect fencing",
			"result capture and truncation markers",
		},
		MustExpose: []string{"adapter kind", "scope", "limits", "cancel state", "truncation state"},
	},
	{
		ID:             "streaming-replay",
		Name:           "Streaming and replay discipline",
		Principle:      "Live execution, durable records, and replay/debug views use one ordered event vocabulary.",
		ConsoleSurface: "Ask trace drawer and eval artifacts",
		Owns: []string{
			"monotonic event sequencing",
			"trajectory persistence",
			"runtime debugger inputs",
			"replay fixtures",
		},
		MustExpose: []string{"sequence", "stage", "redaction status", "replay source"},
	},
	{
		ID:             "connectors",
		Name:           "Connector identity and OAuth boundaries",
		Principle:      "Integrations are authenticated channels with clear public/private surfaces and token ownership.",
		ConsoleSurface: "Connectors, identity contract, MCP status",
		Owns: []string{
			"connector catalog contracts",
			"OAuth/token lifecycle",
			"MCP access",
			"credential store boundaries",
		},
		MustExpose: []string{"principal", "tenant", "scopes", "token owner", "surface"},
	},
	{
		ID:             "knowledge",
		Name:           "Knowledge with provenance and budgets",
		Principle:      "Retrieved context is bounded, cited, instruction-safe, and non-blocking when unavailable.",
		ConsoleSurface: "Graph answers, evidence, inventory, findings",
		Owns: []string{
			"graph and knowledge retrieval",
			"citation validation",
			"context budgets",
			"best-effort ingestion",
		},
		MustExpose: []string{"source urn", "scope", "budget", "citation status", "fallback reason"},
	},
}

var Invariants = []Invariant{
	{ID: "CAP-01", DomainID: "capabilities", Statement: "A capability used by an agent run must be identifiable by id and version."},
	{ID: "CONN-01", DomainID: "connectors", Statement: "A connector token must not be consumed outside its declared owner surface."},
	{ID: "EVAL-01", DomainID: "evals", Statement: "A default-on agent capability must have at least one local regression path."},
	{ID: "EXEC-01", DomainID: "execution", Statement: "Adapters report cancellation and truncation explicitly instead of hiding partial results."},
	{ID: "KNOW-01", DomainID: "knowledge", Statement: "Retrieved context must carry source scope and citation status when shown to a user or model."},
	{ID: "PLAN-01", DomainID: "runtime", Statement: "Agent runs resolve tenant, scope, capability, connector, and write-back preconditions before planning."},
	{ID: "RUN-01", DomainID: "runtime", Statement: "Consumer-visible events use stable names and a single terminal outcome per logical run."},
	{ID: "STREAM-01", DomainID: "streaming-replay", Statement: "Replay records preserve event order even when payloads are redacted or truncated."},
}

var Capabilities = []Capability{
	{
		ID:              "grc-ask",
		Name:            "GRC ask workflow",
		DomainID:        "runtime",
		Kind:            "agent-workflow",
		Version:         "1.0.0",
		Owner:           "cerebro-platform",
		Risk:            "medium",
		DefaultOn:       true,
		Summary:         "Answers security and compliance questions from graph, findings, evidence, and runtime context.",
		ConsoleSurfaces: []string{"Ask console", "GRC dashboard", "trace drawer"},
		RequiredScopes:  []string{"cosmo.security.read"},
		Eval: EvalStatus{
			Required:      true,
			Status:        "required",
			LocalCommands: []string{"npm run eval:ask:local", "npm run eval:ask:adversarial"},
			ScenarioSets:  []string{"ask-golden", "ask-adversarial"},
			Rubrics:       []string{"groundedness", "source use", "safe refusal", "answer completeness"},
		},
		RuntimeEvents: []string{"agent.run.started", "capability.selected", "knowledge.retrieval.completed", "agent.run.completed", "agent.run.failed"},
		Provenance:    []string{"ask-answer"},
		Review: ReviewStatus{
			State:             "required",
			Cadence:           "before default workflow changes",
			RequiredApprovers: []string{"platform", "security"},
		},
	},
	{
		ID:              "security-eval-harness",
		Name:            "Security eval harness",
		DomainID:        "evals",
		Kind:            "eval-suite",
		Version:         "1.0.0",
		Owner:           "cerebro-platform",
		Risk:            "low",
		DefaultOn:       true,
		Summary:         "Runs golden and adversarial scenarios with trace-linked rubric outcomes for agent-facing workflows.",
		ConsoleSurfaces: []string{"Developer evals", "pull request checks"},
		RequiredScopes:  []string{"cosmo.security.read"},
		Eval: EvalStatus{
			Required:      true,
			Status:        "self-covered",
			LocalCommands: []string{"npm run eval:security-agent:local"},
			ScenarioSets:  []string{"security-agent-golden"},
			Rubrics:       []string{"triage accuracy", "evidence quality", "risk calibration"},
		},
		RuntimeEvents: []string{"eval.scenario.started", "eval.scenario.completed"},
		Provenance:    []string{"eval-result"},
		Review: ReviewStatus{
			State:             "required",
			Cadence:           "with rubric or fixture changes",
			RequiredApprovers: []string{"platform"},
		},
	},
	{
		ID:              "trace-streaming-replay",
		Name:            "Trace streaming and replay",
		DomainID:        "streaming-replay",
		Kind:            "event-contract",
		Version:         "1.0.0",
		Owner:           "cerebro-platform",
		Risk:            "medium",
		DefaultOn:       true,
		Summary:         "Keeps live execution, persisted traces, eval artifacts, and replay fixtures on one ordered event vocabulary.",
		ConsoleSurfaces: []string{"trace drawer", "Developer evals", "workflow replay"},
		RequiredScopes:  []string{"cosmo.security.read"},
		Eval: EvalStatus{
			Required:      true,
			Status:        "required",
			LocalCommands: []string{"go test ./internal/workflowevents ./internal/bootstrap -run Test.*Replay"},
			ScenarioSets:  []string{"trace-replay", "redacted-event-replay"},
			Rubrics:       []string{"event ordering", "terminal outcome", "redaction status", "replay source"},
		},
		RuntimeEvents: []string{"agent.run.started", "capability.selected", "agent.run.completed", "agent.run.failed", "eval.scenario.completed"},
		Provenance:    []string{"replay-record"},
		Review: ReviewStatus{
			State:             "required",
			Cadence:           "with event schema or replay fixture changes",
			RequiredApprovers: []string{"platform"},
		},
	},
	{
		ID:              "connector-oauth-mcp",
		Name:            "Connector OAuth and MCP boundary",
		DomainID:        "connectors",
		Kind:            "integration-infrastructure",
		Version:         "1.0.0",
		Owner:           "cerebro-platform",
		Risk:            "high",
		DefaultOn:       true,
		Summary:         "Makes connector identity, OAuth token ownership, credential storage, and MCP exposure explicit platform contracts.",
		ConsoleSurfaces: []string{"Connectors", "connector builder", "MCP status"},
		RequiredScopes:  []string{"cosmo.security.read", "connector.credentials.read", "connector.credentials.write"},
		ConnectorDependencies: []ConnectorDependency{
			// #nosec G101 -- static platform metadata only; no secret values.
			{
				SourceID:        "catalog-managed",
				Purpose:         "Connector setup, credential lifecycle, runtime sync, and MCP tool exposure.",
				AuthModels:      []string{"oauth_authorization_code", "oauth_client_credentials", "api_key", "environment_reference", "external_secret_reference"},
				RequiredScopes:  []string{"connector.credentials.read", "connector.credentials.write"},
				TokenOwner:      "declared connector surface",
				CredentialStore: "tenant-scoped credential broker or declared external reference",
				OAuthSurface:    "/oauth/* and /.well-known/oauth-*",
				MCPSurface:      "/api/v1/mcp",
				TenantScoped:    true,
				Readiness:       "required",
			},
		},
		Eval: EvalStatus{
			Required:      true,
			Status:        "required",
			LocalCommands: []string{"go test ./internal/bootstrap -run 'Test.*OAuth|Test.*MCP|TestConnector'"},
			ScenarioSets:  []string{"connector-auth-boundaries", "mcp-protected-resource"},
			Rubrics:       []string{"token owner isolation", "scope enforcement", "tenant isolation", "credential redaction"},
		},
		RuntimeEvents: []string{"connector.auth.boundary.checked", "adapter.execution.started", "adapter.execution.completed"},
		Provenance:    []string{"connector-call", "mcp-tool-result"},
		Review: ReviewStatus{
			State:             "required",
			Cadence:           "before auth surface or connector catalog changes",
			RequiredApprovers: []string{"platform", "security"},
		},
	},
	{
		ID:              "source-runtime-sync",
		Name:            "Source runtime sync",
		DomainID:        "execution",
		Kind:            "runtime-adapter",
		Version:         "1.0.0",
		Owner:           "cerebro-platform",
		Risk:            "medium",
		DefaultOn:       true,
		Summary:         "Runs source sync, graph ingest, claim writes, and finding evaluation through explicit runtime adapters.",
		ConsoleSurfaces: []string{"Source runtimes", "runtime freshness", "ingest health"},
		RequiredScopes:  []string{"cosmo.security.read"},
		Eval: EvalStatus{
			Required:      true,
			Status:        "required",
			LocalCommands: []string{"go test ./internal/bootstrap -run Test.*SourceRuntime"},
			ScenarioSets:  []string{"runtime-sync-health", "finding-evaluation"},
			Rubrics:       []string{"adapter status", "cancellation state", "truncation state", "tenant scope"},
		},
		RuntimeEvents: []string{"adapter.execution.started", "adapter.execution.completed", "adapter.execution.failed"},
		Provenance:    []string{"source-runtime-event"},
		Review: ReviewStatus{
			State:             "required",
			Cadence:           "with runtime adapter changes",
			RequiredApprovers: []string{"platform"},
		},
	},
	{
		ID:              "finding-rule-evaluation",
		Name:            "Finding rule evaluation",
		DomainID:        "capabilities",
		Kind:            "governed-capability",
		Version:         "1.0.0",
		Owner:           "cerebro-platform",
		Risk:            "medium",
		DefaultOn:       true,
		Summary:         "Packages finding candidate promotion, rejection, and rule evaluation as reviewable capability behavior.",
		ConsoleSurfaces: []string{"Finding rules", "source runtime finding evaluations", "GRC findings"},
		RequiredScopes:  []string{"cosmo.security.read", "finding.candidate.promote"},
		Eval: EvalStatus{
			Required:      true,
			Status:        "required",
			LocalCommands: []string{"go test ./internal/findings"},
			ScenarioSets:  []string{"finding-rule-fixtures"},
			Rubrics:       []string{"precision", "recall", "evidence sufficiency", "risk reason quality"},
		},
		RuntimeEvents: []string{"capability.selected", "eval.scenario.completed"},
		Provenance:    []string{"finding-evidence", "finding-evaluation-run"},
		Review: ReviewStatus{
			State:             "required",
			Cadence:           "before promotion or rule behavior changes",
			RequiredApprovers: []string{"security"},
		},
	},
	{
		ID:              "runtime-response-actions",
		Name:            "Runtime response actions",
		DomainID:        "execution",
		Kind:            "side-effect-adapter",
		Version:         "1.0.0",
		Owner:           "cerebro-platform",
		Risk:            "high",
		DefaultOn:       false,
		Summary:         "Executes explicit containment actions through scoped adapters with audit, cancellation, and result capture.",
		ConsoleSurfaces: []string{"Runtime response", "workflow actions", "blocklist"},
		RequiredScopes:  []string{"runtime.response.write"},
		Eval: EvalStatus{
			Required:      true,
			Status:        "required",
			LocalCommands: []string{"go test ./internal/bootstrap -run TestRecordRuntimeResponseWorkflowAppendsActionEvent"},
			ScenarioSets:  []string{"runtime-response-actions"},
			Rubrics:       []string{"trusted-scope enforcement", "audit completeness", "result status"},
		},
		RuntimeEvents: []string{"adapter.execution.started", "adapter.execution.completed", "adapter.execution.failed"},
		Provenance:    []string{"runtime-response-action"},
		Review: ReviewStatus{
			State:             "required",
			Cadence:           "before adding or changing mutating actions",
			RequiredApprovers: []string{"platform", "security"},
		},
	},
	{
		ID:              "knowledge-provenance",
		Name:            "Knowledge provenance",
		DomainID:        "knowledge",
		Kind:            "retrieval-contract",
		Version:         "1.0.0",
		Owner:           "cerebro-platform",
		Risk:            "medium",
		DefaultOn:       true,
		Summary:         "Requires cited, scoped, budgeted context with explicit fallback when graph or evidence is unavailable.",
		ConsoleSurfaces: []string{"Graph answers", "evidence", "inventory", "findings"},
		RequiredScopes:  []string{"cosmo.security.read"},
		Eval: EvalStatus{
			Required:      true,
			Status:        "required",
			LocalCommands: []string{"go test ./internal/bootstrap -run 'Test.*GRC|Test.*Evidence|Test.*Inventory'"},
			ScenarioSets:  []string{"knowledge-provenance", "citation-status"},
			Rubrics:       []string{"citation coverage", "scope preservation", "fallback clarity", "context budget"},
		},
		RuntimeEvents: []string{"knowledge.retrieval.completed", "agent.run.completed", "agent.run.failed"},
		Provenance:    []string{"knowledge-context", "graph-neighborhood", "evidence-record"},
		Review: ReviewStatus{
			State:             "required",
			Cadence:           "with retrieval or user-visible answer changes",
			RequiredApprovers: []string{"platform", "security"},
		},
	},
	{
		ID:              "agent-evidence-packet",
		Name:            "Agent evidence packet",
		DomainID:        "knowledge",
		Kind:            "agent-context-contract",
		Version:         "1.0.0",
		Owner:           "cerebro-platform",
		Risk:            "medium",
		DefaultOn:       true,
		Summary:         "Bundles tenant scope, graph context, source coverage, evidence references, verifier results, action gates, memory, and simulation planning before agent reasoning.",
		ConsoleSurfaces: []string{"Agent platform API", "Ask console", "trace drawer"},
		RequiredScopes:  []string{"cosmo.security.read"},
		Eval: EvalStatus{
			Required:      true,
			Status:        "required",
			LocalCommands: []string{"go test ./internal/agentplatform -run TestBuildEvidencePacket"},
			ScenarioSets:  []string{"agent-evidence-packet"},
			Rubrics:       []string{"tenant scope", "coverage caveats", "verifier completeness", "action gate clarity"},
		},
		RuntimeEvents: []string{"agent.preflight.completed", "knowledge.retrieval.completed", "verifier.completed"},
		Provenance:    []string{"agent-run-preflight", "knowledge-context", "source-coverage", "verifier-result"},
		Review: ReviewStatus{
			State:             "required",
			Cadence:           "before evidence packet schema or verifier changes",
			RequiredApprovers: []string{"platform", "security"},
		},
	},
	{
		ID:              "security-verifier-layer",
		Name:            "Security verifier layer",
		DomainID:        "capabilities",
		Kind:            "verification-contract",
		Version:         "1.0.0",
		Owner:           "cerebro-platform",
		Risk:            "high",
		DefaultOn:       true,
		Summary:         "Requires independent verifier statuses for tenant scope, provenance, freshness, blind spots, connector tool use, action stage, remediation safety, eval readiness, and memory provenance.",
		ConsoleSurfaces: []string{"Agent platform API", "finding rules", "runtime response", "trace drawer"},
		RequiredScopes:  []string{"cosmo.security.read"},
		Eval: EvalStatus{
			Required:      true,
			Status:        "required",
			LocalCommands: []string{"go test ./internal/agentplatform -run TestSecurityControlPlaneSnapshot"},
			ScenarioSets:  []string{"security-verifier-layer"},
			Rubrics:       []string{"blocking gates", "warning gates", "evidence pointers", "safe downgrade"},
		},
		RuntimeEvents: []string{"verifier.completed", "agent.run.completed", "agent.run.failed"},
		Provenance:    []string{"verifier-result", "evidence-record"},
		Review: ReviewStatus{
			State:             "required",
			Cadence:           "before verifier or promotion behavior changes",
			RequiredApprovers: []string{"platform", "security"},
		},
	},
	{
		ID:              "specialized-security-agents",
		Name:            "Specialized security agents",
		DomainID:        "capabilities",
		Kind:            "agent-profile-registry",
		Version:         "1.0.0",
		Owner:           "cerebro-platform",
		Risk:            "medium",
		DefaultOn:       true,
		Summary:         "Defines narrow security-agent profiles with explicit semantic views, required verifiers, capability ids, and maximum action stages.",
		ConsoleSurfaces: []string{"Agent platform API", "Ask console", "Developer evals"},
		RequiredScopes:  []string{"cosmo.security.read"},
		Eval: EvalStatus{
			Required:      true,
			Status:        "required",
			LocalCommands: []string{"go test ./internal/agentplatform -run TestSecurityControlPlaneSnapshot"},
			ScenarioSets:  []string{"specialized-security-agents"},
			Rubrics:       []string{"profile selection", "least privilege", "max action stage", "required verifiers"},
		},
		RuntimeEvents: []string{"capability.selected", "agent.preflight.completed"},
		Provenance:    []string{"agent-run-preflight", "capability-selection"},
		Review: ReviewStatus{
			State:             "required",
			Cadence:           "before adding default-on agent profiles",
			RequiredApprovers: []string{"platform", "security"},
		},
	},
	{
		ID:              "security-memory",
		Name:            "Security memory",
		DomainID:        "knowledge",
		Kind:            "memory-contract",
		Version:         "1.0.0",
		Owner:           "cerebro-platform",
		Risk:            "medium",
		DefaultOn:       true,
		Summary:         "Promotes accepted risks, false positives, prior investigations, remediation outcomes, and detector learnings into typed, tenant-scoped, provenance-bearing memory.",
		ConsoleSurfaces: []string{"Knowledge actions", "findings", "workflow outcomes", "trace drawer"},
		RequiredScopes:  []string{"cosmo.security.read"},
		Eval: EvalStatus{
			Required:      true,
			Status:        "required",
			LocalCommands: []string{"go test ./internal/agentplatform -run TestBuildEvidencePacket"},
			ScenarioSets:  []string{"security-memory"},
			Rubrics:       []string{"typed memory", "tenant scope", "TTL", "no raw transcripts"},
		},
		RuntimeEvents: []string{"knowledge.retrieval.completed", "agent.run.completed"},
		Provenance:    []string{"security-memory", "knowledge-context", "evidence-record"},
		Review: ReviewStatus{
			State:             "required",
			Cadence:           "before memory type or retention changes",
			RequiredApprovers: []string{"platform", "security"},
		},
	},
	{
		ID:              "defensive-graph-simulation",
		Name:            "Defensive graph simulation",
		DomainID:        "knowledge",
		Kind:            "simulation-harness",
		Version:         "1.0.0",
		Owner:           "cerebro-platform",
		Risk:            "medium",
		DefaultOn:       true,
		Summary:         "Lets agents simulate attack paths, blast radius, and remediation effects from graph facts and fixtures without live exploitation.",
		ConsoleSurfaces: []string{"Agent platform API", "Graph operations", "Developer evals"},
		RequiredScopes:  []string{"cosmo.security.read"},
		Eval: EvalStatus{
			Required:      true,
			Status:        "required",
			LocalCommands: []string{"go test ./internal/agentplatform -run TestBuildEvidencePacket"},
			ScenarioSets:  []string{"defensive-graph-simulation"},
			Rubrics:       []string{"graph-only inputs", "bounded path output", "blocked assumptions", "verification plan"},
		},
		RuntimeEvents: []string{"knowledge.retrieval.completed", "agent.run.completed"},
		Provenance:    []string{"defensive-simulation", "graph-neighborhood", "source-coverage"},
		Review: ReviewStatus{
			State:             "required",
			Cadence:           "before simulation mode or output changes",
			RequiredApprovers: []string{"platform", "security"},
		},
	},
	{
		ID:              "graph-reasoning",
		Name:            "Agent graph reasoning",
		DomainID:        "knowledge",
		Kind:            "agent-graph-reasoning",
		Version:         "1.0.0",
		Owner:           "cerebro-platform",
		Risk:            "medium",
		DefaultOn:       true,
		Summary:         "Lets agents ask bounded graph questions and receive a structured reasoning envelope with query plan, validation, rows, graph context, citations, and provenance.",
		ConsoleSurfaces: []string{"Agent platform graph API", "Ask console", "trace drawer"},
		RequiredScopes:  []string{"cosmo.security.read"},
		Eval: EvalStatus{
			Required:      true,
			Status:        "required",
			LocalCommands: []string{"go test ./internal/graphagent ./internal/bootstrap -run Test.*Reason"},
			ScenarioSets:  []string{"graph-reasoning-envelope", "graph-reasoning-unsupported-query"},
			Rubrics:       []string{"read-only validation", "query plan transparency", "citation grounding", "provenance completeness"},
		},
		RuntimeEvents: []string{"agent.preflight.completed", "agent.run.started", "capability.selected", "knowledge.retrieval.completed", "agent.run.completed", "agent.run.failed"},
		Provenance:    []string{"agent-run-preflight", "graph-reasoning", "knowledge-context", "graph-neighborhood", "graph-provenance", "source-coverage"},
		Review: ReviewStatus{
			State:             "required",
			Cadence:           "before graph reasoning API or query contract changes",
			RequiredApprovers: []string{"platform", "security"},
		},
	},
}

var RuntimeEvents = []RuntimeEvent{
	{
		Name:             "agent.preflight.completed",
		DomainID:         "runtime",
		Stage:            "preflight",
		SequenceRequired: true,
		Replayable:       true,
		PayloadFields:    []string{"tenant_id", "actor_id", "capability_ids", "scope_urn", "policy_checks", "connector_gates", "write_back_contract"},
		ProvenanceFields: []string{"tenant_id", "scope", "capability_id", "policy_check", "connector_node_urn"},
	},
	{
		Name:             "agent.run.started",
		DomainID:         "runtime",
		Stage:            "start",
		SequenceRequired: true,
		Replayable:       true,
		PayloadFields:    []string{"trace_id", "tenant_id", "capability_hint", "model_route"},
		ProvenanceFields: []string{"trace_id", "scope"},
	},
	{
		Name:             "capability.selected",
		DomainID:         "capabilities",
		Stage:            "selection",
		SequenceRequired: true,
		Replayable:       true,
		PayloadFields:    []string{"capability_id", "version", "selection_reason", "owner"},
		ProvenanceFields: []string{"capability_id", "version", "selection_reason"},
	},
	{
		Name:             "connector.auth.boundary.checked",
		DomainID:         "connectors",
		Stage:            "authorization",
		SequenceRequired: true,
		Replayable:       true,
		PayloadFields:    []string{"source_id", "principal", "tenant", "scopes", "token_owner", "surface"},
		ProvenanceFields: []string{"source_urn", "scope", "token_owner"},
	},
	{
		Name:             "knowledge.retrieval.completed",
		DomainID:         "knowledge",
		Stage:            "retrieval",
		SequenceRequired: true,
		Replayable:       true,
		PayloadFields:    []string{"source_urn", "scope", "budget", "citation_status", "fallback_reason"},
		ProvenanceFields: []string{"source_urn", "scope", "citation_status", "fallback_reason"},
	},
	{
		Name:             "verifier.completed",
		DomainID:         "capabilities",
		Stage:            "verification",
		SequenceRequired: true,
		Replayable:       true,
		PayloadFields:    []string{"verifier_id", "status", "message", "evidence"},
		ProvenanceFields: []string{"verifier_id", "status", "evidence"},
	},
	{
		Name:             "adapter.execution.started",
		DomainID:         "execution",
		Stage:            "execution",
		SequenceRequired: true,
		Replayable:       true,
		PayloadFields:    []string{"adapter_kind", "scope", "limits"},
		ProvenanceFields: []string{"scope", "adapter_kind"},
	},
	{
		Name:             "adapter.execution.completed",
		DomainID:         "execution",
		Stage:            "terminal",
		SequenceRequired: true,
		Replayable:       true,
		PayloadFields:    []string{"adapter_kind", "cancel_state", "truncation_state", "result_ref"},
		ProvenanceFields: []string{"scope", "adapter_kind", "truncation_state"},
	},
	{
		Name:             "adapter.execution.failed",
		DomainID:         "execution",
		Stage:            "terminal",
		SequenceRequired: true,
		Terminal:         true,
		Replayable:       true,
		PayloadFields:    []string{"adapter_kind", "cancel_state", "truncation_state", "error_class"},
		ProvenanceFields: []string{"scope", "adapter_kind", "truncation_state"},
	},
	{
		Name:             "eval.scenario.started",
		DomainID:         "evals",
		Stage:            "start",
		SequenceRequired: true,
		Replayable:       true,
		PayloadFields:    []string{"scenario_id", "capability_id", "model_route"},
		ProvenanceFields: []string{"scenario_id", "capability_id"},
	},
	{
		Name:             "eval.scenario.completed",
		DomainID:         "evals",
		Stage:            "terminal",
		SequenceRequired: true,
		Terminal:         true,
		Replayable:       true,
		PayloadFields:    []string{"scenario_id", "score", "rubric_failures", "trace_link"},
		ProvenanceFields: []string{"scenario_id", "score", "trace_link"},
	},
	{
		Name:             "agent.run.completed",
		DomainID:         "runtime",
		Stage:            "terminal",
		SequenceRequired: true,
		Terminal:         true,
		Replayable:       true,
		PayloadFields:    []string{"trace_id", "terminal_outcome", "model_route", "redaction_status"},
		ProvenanceFields: []string{"trace_id", "terminal_outcome"},
	},
	{
		Name:             "agent.run.failed",
		DomainID:         "runtime",
		Stage:            "terminal",
		SequenceRequired: true,
		Terminal:         true,
		Replayable:       true,
		PayloadFields:    []string{"trace_id", "terminal_outcome", "error_class", "redaction_status"},
		ProvenanceFields: []string{"trace_id", "terminal_outcome"},
	},
}

var ProvenanceRequirements = []ProvenanceRequirement{
	{
		Surface:          "agent-run-preflight",
		DomainID:         "runtime",
		RequiredFields:   []string{"tenant_id", "scope", "capability_id", "policy_check", "connector_node_urn", "write_back_event"},
		CitationRequired: false,
		BudgetRequired:   true,
		FallbackRequired: true,
	},
	{
		Surface:          "ask-answer",
		DomainID:         "knowledge",
		RequiredFields:   []string{"source_urn", "scope", "budget", "citation_status", "fallback_reason"},
		CitationRequired: true,
		BudgetRequired:   true,
		FallbackRequired: true,
	},
	{
		Surface:          "connector-call",
		DomainID:         "connectors",
		RequiredFields:   []string{"source_urn", "principal", "tenant", "scopes", "token_owner", "surface"},
		CitationRequired: false,
		BudgetRequired:   false,
		FallbackRequired: true,
	},
	{
		Surface:          "mcp-tool-result",
		DomainID:         "connectors",
		RequiredFields:   []string{"source_urn", "principal", "tenant", "scopes", "token_owner", "surface", "tool_name"},
		CitationRequired: false,
		BudgetRequired:   false,
		FallbackRequired: true,
	},
	{
		Surface:          "source-runtime-event",
		DomainID:         "execution",
		RequiredFields:   []string{"runtime_id", "source_urn", "tenant", "adapter_kind", "scope", "truncation_state"},
		CitationRequired: false,
		BudgetRequired:   false,
		FallbackRequired: false,
	},
	{
		Surface:          "runtime-response-action",
		DomainID:         "execution",
		RequiredFields:   []string{"adapter_kind", "scope", "limits", "cancel_state", "truncation_state"},
		CitationRequired: false,
		BudgetRequired:   false,
		FallbackRequired: false,
	},
	{
		Surface:          "eval-result",
		DomainID:         "evals",
		RequiredFields:   []string{"scenario_id", "score", "rubric_failures", "trace_link"},
		CitationRequired: false,
		BudgetRequired:   false,
		FallbackRequired: false,
	},
	{
		Surface:          "replay-record",
		DomainID:         "streaming-replay",
		RequiredFields:   []string{"trace_id", "sequence", "stage", "redaction_status", "replay_source", "terminal_outcome"},
		CitationRequired: false,
		BudgetRequired:   false,
		FallbackRequired: false,
	},
	{
		Surface:          "finding-evaluation-run",
		DomainID:         "capabilities",
		RequiredFields:   []string{"run_id", "runtime_id", "source_urn", "score", "rubric_failures", "trace_link"},
		CitationRequired: false,
		BudgetRequired:   false,
		FallbackRequired: false,
	},
	{
		Surface:          "finding-evidence",
		DomainID:         "capabilities",
		RequiredFields:   []string{"source_urn", "scope", "citation_status", "evidence_id"},
		CitationRequired: true,
		BudgetRequired:   false,
		FallbackRequired: false,
	},
	{
		Surface:          "knowledge-context",
		DomainID:         "knowledge",
		RequiredFields:   []string{"source_urn", "scope", "budget", "citation_status", "fallback_reason"},
		CitationRequired: true,
		BudgetRequired:   true,
		FallbackRequired: true,
	},
	{
		Surface:          "graph-neighborhood",
		DomainID:         "knowledge",
		RequiredFields:   []string{"source_urn", "scope", "entity_urn", "budget", "citation_status", "fallback_reason"},
		CitationRequired: true,
		BudgetRequired:   true,
		FallbackRequired: true,
	},
	{
		Surface:          "graph-reasoning",
		DomainID:         "knowledge",
		RequiredFields:   []string{"trace_id", "source_urns", "scope", "citation_status", "fallback_reason"},
		CitationRequired: true,
		BudgetRequired:   true,
		FallbackRequired: true,
	},
	{
		Surface:          "graph-provenance",
		DomainID:         "knowledge",
		RequiredFields:   []string{"source_urn", "scope", "projection_class", "source_id", "runtime_id"},
		CitationRequired: true,
		BudgetRequired:   true,
		FallbackRequired: true,
	},
	{
		Surface:          "source-coverage",
		DomainID:         "connectors",
		RequiredFields:   []string{"tenant_id", "source_id", "dimension_id", "state", "support_level", "blind_spot"},
		CitationRequired: false,
		BudgetRequired:   true,
		FallbackRequired: true,
	},
	{
		Surface:          "verifier-result",
		DomainID:         "capabilities",
		RequiredFields:   []string{"verifier_id", "status", "message", "evidence"},
		CitationRequired: false,
		BudgetRequired:   false,
		FallbackRequired: true,
	},
	{
		Surface:          "security-memory",
		DomainID:         "knowledge",
		RequiredFields:   []string{"tenant_id", "type", "source_urn", "citation_status", "created_at", "owner"},
		CitationRequired: true,
		BudgetRequired:   false,
		FallbackRequired: true,
	},
	{
		Surface:          "defensive-simulation",
		DomainID:         "knowledge",
		RequiredFields:   []string{"mode", "scope", "path_summary", "affected_assets", "blocked_assumptions", "recommended_verification"},
		CitationRequired: true,
		BudgetRequired:   true,
		FallbackRequired: true,
	},
	{
		Surface:          "capability-selection",
		DomainID:         "capabilities",
		RequiredFields:   []string{"capability_id", "version", "selection_reason"},
		CitationRequired: false,
		BudgetRequired:   false,
		FallbackRequired: true,
	},
	{
		Surface:          "evidence-record",
		DomainID:         "knowledge",
		RequiredFields:   []string{"source_urn", "scope", "evidence_id", "citation_status"},
		CitationRequired: true,
		BudgetRequired:   false,
		FallbackRequired: false,
	},
}

var ConnectorInfrastructureProfile = ConnectorInfrastructure{
	AuthModels: []string{
		"oauth_authorization_code",
		"oauth_client_credentials",
		"api_key",
		"environment_reference",
		"external_secret_reference",
	},
	OAuthSurfaces: []string{
		"/.well-known/oauth-protected-resource",
		"/.well-known/oauth-protected-resource/api/v1/mcp",
		"/.well-known/oauth-authorization-server",
		"/oauth/authorize",
		"/oauth/callback",
		"/oauth/token",
		"/oauth/revoke",
		"/oauth/register",
	},
	CredentialStores: []string{
		"tenant-scoped credential broker",
		"environment",
		"external-reference",
	},
	TokenBoundaries: []string{
		"principal",
		"tenant",
		"scopes",
		"token owner",
		"surface",
		"resource",
	},
	MCPSurfaces: []string{
		"/api/v1/mcp",
	},
	RequiredControls: []string{
		"protected-resource metadata for MCP",
		"read/write credential scopes",
		"tenant-scoped token exchange",
		"credential rotation and revocation",
		"connector preflight before connection creation",
		"secret redaction in UI, API, logs, traces, and eval artifacts",
	},
}

func Snapshot() Contract {
	return Contract{
		Version:                 ContractVersion,
		Domains:                 cloneDomains(Domains),
		Invariants:              cloneInvariants(Invariants),
		Capabilities:            cloneCapabilities(Capabilities),
		RuntimeEvents:           cloneRuntimeEvents(RuntimeEvents),
		ProvenanceRequirements:  cloneProvenanceRequirements(ProvenanceRequirements),
		ConnectorInfrastructure: cloneConnectorInfrastructure(ConnectorInfrastructureProfile),
		SecurityControlPlane:    SecurityControlPlaneSnapshot(),
	}
}

func DomainByID(id string) (Domain, bool) {
	for _, domain := range Domains {
		if domain.ID == id {
			return domain, true
		}
	}
	return Domain{}, false
}

func cloneDomains(domains []Domain) []Domain {
	out := make([]Domain, 0, len(domains))
	for _, domain := range domains {
		domain.Owns = cloneStrings(domain.Owns)
		domain.MustExpose = cloneStrings(domain.MustExpose)
		out = append(out, domain)
	}
	return out
}

func cloneInvariants(invariants []Invariant) []Invariant {
	return append([]Invariant(nil), invariants...)
}

func cloneCapabilities(capabilities []Capability) []Capability {
	out := make([]Capability, 0, len(capabilities))
	for _, capability := range capabilities {
		capability.ConsoleSurfaces = cloneStrings(capability.ConsoleSurfaces)
		capability.RequiredScopes = cloneStrings(capability.RequiredScopes)
		capability.ConnectorDependencies = cloneConnectorDependencies(capability.ConnectorDependencies)
		capability.Eval.LocalCommands = cloneStrings(capability.Eval.LocalCommands)
		capability.Eval.ScenarioSets = cloneStrings(capability.Eval.ScenarioSets)
		capability.Eval.Rubrics = cloneStrings(capability.Eval.Rubrics)
		capability.RuntimeEvents = cloneStrings(capability.RuntimeEvents)
		capability.Provenance = cloneStrings(capability.Provenance)
		capability.Review.RequiredApprovers = cloneStrings(capability.Review.RequiredApprovers)
		out = append(out, capability)
	}
	return out
}

func cloneConnectorDependencies(dependencies []ConnectorDependency) []ConnectorDependency {
	out := make([]ConnectorDependency, 0, len(dependencies))
	for _, dependency := range dependencies {
		dependency.AuthModels = cloneStrings(dependency.AuthModels)
		dependency.RequiredScopes = cloneStrings(dependency.RequiredScopes)
		out = append(out, dependency)
	}
	return out
}

func cloneRuntimeEvents(events []RuntimeEvent) []RuntimeEvent {
	out := make([]RuntimeEvent, 0, len(events))
	for _, event := range events {
		event.PayloadFields = cloneStrings(event.PayloadFields)
		event.ProvenanceFields = cloneStrings(event.ProvenanceFields)
		out = append(out, event)
	}
	return out
}

func cloneProvenanceRequirements(requirements []ProvenanceRequirement) []ProvenanceRequirement {
	out := make([]ProvenanceRequirement, 0, len(requirements))
	for _, requirement := range requirements {
		requirement.RequiredFields = cloneStrings(requirement.RequiredFields)
		out = append(out, requirement)
	}
	return out
}

func cloneConnectorInfrastructure(infrastructure ConnectorInfrastructure) ConnectorInfrastructure {
	infrastructure.AuthModels = cloneStrings(infrastructure.AuthModels)
	infrastructure.OAuthSurfaces = cloneStrings(infrastructure.OAuthSurfaces)
	infrastructure.CredentialStores = cloneStrings(infrastructure.CredentialStores)
	infrastructure.TokenBoundaries = cloneStrings(infrastructure.TokenBoundaries)
	infrastructure.MCPSurfaces = cloneStrings(infrastructure.MCPSurfaces)
	infrastructure.RequiredControls = cloneStrings(infrastructure.RequiredControls)
	return infrastructure
}

func cloneStrings(values []string) []string {
	return append([]string(nil), values...)
}
