package mcpoperations

type AssessmentToolDefinition struct {
	Name         string
	Title        string
	Description  string
	InputSchema  InputSchema
	OutputSchema OutputSchema
	Idempotent   bool
}

func AssessmentToolDefinitions() []AssessmentToolDefinition {
	tenant := map[string]any{"type": "string", "description": "Tenant scope. Omit only when the authenticated principal is bound to one tenant."}
	identifier := func(description string) map[string]any {
		return map[string]any{"type": "string", "description": description}
	}
	output := func(properties map[string]any) OutputSchema { return ResponseSchema(Properties(properties)) }
	return []AssessmentToolDefinition{
		{
			Name: "cerebro.assessments.plan.create", Title: "Create Assessment Plan",
			Description:  "Create one tenant-scoped assessment plan draft. Requires cerebro.cosmo.security.read and cerebro.grc.inventory.write.",
			InputSchema:  objectSchema(map[string]any{"plan": map[string]any{"type": "object", "description": "Typed AssessmentPlanRevision content. Server-owned identity, revision, status, digest, actor, and timestamp fields are ignored.", "additionalProperties": true}}, []string{"plan"}),
			OutputSchema: output(map[string]any{"plan": map[string]any{"type": "object"}, "created": map[string]any{"type": "boolean"}}),
		},
		{
			Name: "cerebro.assessments.plan.publish", Title: "Publish Assessment Plan",
			Description:  "Publish one validated assessment plan revision using optimistic concurrency. Requires cerebro.cosmo.security.read and cerebro.grc.inventory.write.",
			InputSchema:  objectSchema(map[string]any{"tenant_id": tenant, "plan_id": identifier("Assessment plan ID."), "expected_version": map[string]any{"type": "integer", "minimum": 1}}, []string{"plan_id", "expected_version"}),
			OutputSchema: output(map[string]any{"plan": map[string]any{"type": "object"}, "published": map[string]any{"type": "boolean"}}),
		},
		{
			Name: "cerebro.assessments.plan.get", Title: "Get Assessment Plan", Description: "Read one tenant-scoped assessment plan revision by ID.",
			InputSchema:  objectSchema(map[string]any{"tenant_id": tenant, "plan_id": identifier("Assessment plan ID or revision ID.")}, []string{"plan_id"}),
			OutputSchema: output(map[string]any{"plan": map[string]any{"type": "object"}}), Idempotent: true,
		},
		{
			Name: "cerebro.assessments.run.request", Title: "Request Assessment Run",
			Description: "Request a recoverable assessment run for a published plan. Reusing the same idempotency key and body returns the existing run. Requires cerebro.cosmo.security.read and cerebro.grc.inventory.write.",
			InputSchema: objectSchema(map[string]any{
				"tenant_id": tenant, "plan_revision_id": identifier("Published assessment plan revision ID."),
				"period_start": map[string]any{"type": "string", "format": "date-time"}, "period_end": map[string]any{"type": "string", "format": "date-time"},
				"baseline_run_id": identifier("Optional completed run to compare after execution."), "idempotency_key": identifier("Caller-owned retry key."),
			}, []string{"plan_revision_id", "period_start", "period_end", "idempotency_key"}),
			OutputSchema: output(map[string]any{"run": map[string]any{"type": "object"}, "created": map[string]any{"type": "boolean"}}), Idempotent: true,
		},
		{
			Name: "cerebro.assessments.run.get", Title: "Get Assessment Run", Description: "Read one assessment run, including its state, pinned input manifest, hashes, and terminal-result availability.",
			InputSchema:  objectSchema(map[string]any{"tenant_id": tenant, "run_id": identifier("Assessment run ID.")}, []string{"run_id"}),
			OutputSchema: output(map[string]any{"run": map[string]any{"type": "object"}, "terminal": map[string]any{"type": "boolean"}, "results_available": map[string]any{"type": "boolean"}}), Idempotent: true,
		},
		{
			Name: "cerebro.assessments.results.list", Title: "List Verified Assessment Results",
			Description: "Read one bounded result page and independently verify its sequence, boundaries, payload digests, and predecessor chain. Pass verification.next_previous_digest into expected_previous_digest for the next page.",
			InputSchema: objectSchema(map[string]any{
				"tenant_id": tenant, "run_id": identifier("Completed assessment run ID."),
				"after_sequence": map[string]any{"type": "integer", "minimum": 0}, "expected_previous_digest": identifier("Verified digest from the preceding page."),
				"limit": limitSchema(100, "result chunks"),
			}, []string{"run_id"}),
			OutputSchema: output(map[string]any{"chunks": map[string]any{"type": "array"}, "verification": map[string]any{"type": "object"}, "has_more": map[string]any{"type": "boolean"}}), Idempotent: true,
		},
		{
			Name: "cerebro.assessments.run.diff", Title: "Compare Assessment Runs", Description: "Verify and compare one completed run with its explicit or pinned baseline. Fails closed when the bounded comparison cannot cover every result.",
			InputSchema:  objectSchema(map[string]any{"tenant_id": tenant, "run_id": identifier("Completed current assessment run ID."), "baseline_run_id": identifier("Optional completed baseline run ID; defaults to the run's pinned baseline.")}, []string{"run_id"}),
			OutputSchema: output(map[string]any{"diff": map[string]any{"type": "object"}, "current_verification": map[string]any{"type": "object"}, "baseline_verification": map[string]any{"type": "object"}}), Idempotent: true,
		},
		{
			Name: "cerebro.assessments.result.explain", Title: "Explain Assessment Result", Description: "Verify one completed run, return the selected objective result and pinned manifest, resolve bounded evidence and finding records, and provide exact provenance follow-up tool calls.",
			InputSchema:  objectSchema(map[string]any{"tenant_id": tenant, "run_id": identifier("Completed assessment run ID."), "result_id": identifier("Objective result ID.")}, []string{"run_id", "result_id"}),
			OutputSchema: output(map[string]any{"run": map[string]any{"type": "object"}, "result": map[string]any{"type": "object"}, "verification": map[string]any{"type": "object"}, "evidence": map[string]any{"type": "array"}, "findings": map[string]any{"type": "array"}, "provenance_handoffs": map[string]any{"type": "array"}}), Idempotent: true,
		},
		{
			Name: "cerebro.assessments.remediation.propose", Title: "Propose Assessment Remediation", Description: "Build a non-mutating, approval-gated work request from one verified non-passing assessment result. The tool never creates work or executes remediation.",
			InputSchema: objectSchema(map[string]any{
				"dry_run":   map[string]any{"type": "boolean", "const": true},
				"tenant_id": tenant, "run_id": identifier("Completed assessment run ID."), "result_id": identifier("Non-passing objective result ID."),
				"subject_id": identifier("Stable affected subject ID."), "source_id": identifier("Optional source owner ID."), "owner_id": identifier("Work owner ID."),
				"due_at": map[string]any{"type": "string", "format": "date-time"}, "priority": map[string]any{"type": "string"},
			}, []string{"dry_run", "run_id", "result_id"}),
			OutputSchema: output(map[string]any{"dry_run": map[string]any{"type": "boolean"}, "ready": map[string]any{"type": "boolean"}, "request": map[string]any{"type": "object"}, "verification": map[string]any{"type": "object"}}), Idempotent: true,
		},
	}
}
