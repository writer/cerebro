package complianceimprovement

// DefaultAgentRoles returns the fixed responsibility and action boundaries for
// the compliance program improvement loop.
func DefaultAgentRoles() []AgentRole {
	return []AgentRole{
		{
			ID: "compliance-refiner", Purpose: "Find a verified program gap and define the current measure, target, and guardrails.",
			Reads:    []string{"program revisions", "verified assessments", "readiness blockers", "monitored changes", "remediation outcomes"},
			Produces: []string{"detected gap", "measurable target", "guardrails"}, MaxAction: "propose",
			RequiredChecks: []string{"exact input revisions", "current-state evidence"},
		},
		{
			ID: "compliance-researcher", Purpose: "Build the source-backed case for and against a program change.",
			Reads:    []string{"source snapshots", "program policy", "control evidence", "assessment results"},
			Produces: []string{"cited claims", "counterevidence", "unknowns"}, MaxAction: "propose",
			RequiredChecks: []string{"citation coverage", "evidence freshness"},
		},
		{
			ID: "compliance-verifier", Purpose: "Block stale, unsupported, unsafe, or score-gaming proposals.",
			Reads:    []string{"improvement proposal", "exact input revisions", "repository patch"},
			Produces: []string{"blocking, warning, and passing verifier results"}, MaxAction: "validate",
			RequiredChecks: []string{"tenant scope", "revision identity", "program integrity", "repository data policy"},
		},
		{
			ID: "compliance-author", Purpose: "Prepare a bounded repository change with checks and rollback steps.",
			Reads:    []string{"validated proposal", "repository base revision"},
			Produces: []string{"bounded file changes", "validation steps", "rollback steps"}, MaxAction: "draft",
			RequiredChecks: []string{"file and byte limits", "exact repository base"},
		},
		{
			ID: "compliance-draft-publisher", Purpose: "Open an idempotent draft pull request for human review.",
			Reads:    []string{"validated proposal digest", "bounded repository patch"},
			Produces: []string{"draft pull-request receipt"}, MaxAction: "open_draft_pull_request",
			RequiredChecks: []string{"draft state", "exact base commit", "allowed repository and branch"},
		},
		{
			ID: "compliance-team-notifier", Purpose: "Queue the decision record for approved team channels.",
			Reads:    []string{"validated proposal", "draft pull-request receipt"},
			Produces: []string{"team update outbox record"}, MaxAction: "enqueue_update",
			RequiredChecks: []string{"destination policy", "idempotency", "private-data boundary"},
		},
	}
}
