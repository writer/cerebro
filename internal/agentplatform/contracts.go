// Package agentplatform names the Cerebro-native agent platform contract.
//
// The package is intentionally small and dependency-free. It gives docs,
// tests, API handlers, and UI clients one stable vocabulary for the pieces
// Cerebro expects every agent-facing capability to preserve.
package agentplatform

const ContractVersion = "2026-06-16.cerebro-agent-platform"

type Domain struct {
	ID         string
	Name       string
	Principle  string
	Owns       []string
	MustExpose []string
}

type Invariant struct {
	ID        string
	DomainID  string
	Statement string
}

var Domains = []Domain{
	{
		ID:        "runtime",
		Name:      "Contract-first runtime",
		Principle: "Agent execution is typed, replayable, and isolated from product-specific orchestration.",
		Owns: []string{
			"closed event schemas",
			"append-only conversation or trajectory records",
			"ports for LLM, graph query, persistence, and telemetry",
		},
		MustExpose: []string{"trace id", "event order", "terminal outcome", "model route"},
	},
	{
		ID:        "evals",
		Name:      "Evals as product infrastructure",
		Principle: "Every agent capability has a measurable regression surface before it becomes a default workflow.",
		Owns: []string{
			"golden and adversarial scenarios",
			"rubric outcomes",
			"trace-linked diagnostics",
			"model comparison metadata",
		},
		MustExpose: []string{"scenario id", "score", "rubric failures", "trace link"},
	},
	{
		ID:        "capabilities",
		Name:      "Capabilities as governed artifacts",
		Principle: "Reusable agent behavior is packaged, versioned, and reviewed instead of hidden in prompts.",
		Owns: []string{
			"capability metadata",
			"selection rules",
			"review and sharing state",
			"safe invocation contracts",
		},
		MustExpose: []string{"capability id", "version", "owner", "selection reason"},
	},
	{
		ID:        "execution",
		Name:      "Execution behind ports",
		Principle: "Stateful or risky work happens through explicit adapters with limits, cancellation, and audit.",
		Owns: []string{
			"workspace access",
			"shell or runtime response dispatch",
			"side-effect fencing",
			"result capture and truncation markers",
		},
		MustExpose: []string{"adapter kind", "scope", "limits", "cancel state", "truncation state"},
	},
	{
		ID:        "streaming-replay",
		Name:      "Streaming and replay discipline",
		Principle: "Live execution, durable records, and replay/debug views use one ordered event vocabulary.",
		Owns: []string{
			"monotonic event sequencing",
			"trajectory persistence",
			"runtime debugger inputs",
			"replay fixtures",
		},
		MustExpose: []string{"sequence", "stage", "redaction status", "replay source"},
	},
	{
		ID:        "connectors",
		Name:      "Connector identity and OAuth boundaries",
		Principle: "Integrations are authenticated channels with clear public/private surfaces and token ownership.",
		Owns: []string{
			"connector catalog contracts",
			"OAuth/token lifecycle",
			"MCP access",
			"credential store boundaries",
		},
		MustExpose: []string{"principal", "tenant", "scopes", "token owner", "surface"},
	},
	{
		ID:        "knowledge",
		Name:      "Knowledge with provenance and budgets",
		Principle: "Retrieved context is bounded, cited, instruction-safe, and non-blocking when unavailable.",
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
	{ID: "RUN-01", DomainID: "runtime", Statement: "Consumer-visible events use stable names and a single terminal outcome per logical run."},
	{ID: "STREAM-01", DomainID: "streaming-replay", Statement: "Replay records preserve event order even when payloads are redacted or truncated."},
}

func DomainByID(id string) (Domain, bool) {
	for _, domain := range Domains {
		if domain.ID == id {
			return domain, true
		}
	}
	return Domain{}, false
}
