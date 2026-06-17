package compliance

import "testing"

func TestEvaluateControlReadinessClassifiesAuditorReadyControl(t *testing.T) {
	catalog := loadTestCatalog(t, `
version: "2026-06-17"
frameworks:
  - id: custom
    name: Custom Framework
    tags: [custom]
    families:
      - id: IAM
        name: Identity Controls
        tags: [identity]
        controls:
          - id: IAM-1
            title: Privileged access requires MFA
            objective: Privileged production access requires strong authentication evidence.
            intent: Reduce account takeover risk for privileged production identities.
            owner_domain: identity
            freshness_sla: 30d
            applicability: [production, privileged_access]
            assessment_methods: [examine, test]
            implementation_guidance:
              - Enforce MFA before privileged production access is granted.
            audit_procedure:
              - Compare privileged account inventory against MFA enrollment evidence.
            failure_modes:
              - Privileged account has production access without MFA evidence.
            remediation_guidance:
              - Remove privileged access until MFA is enrolled.
            exception_guidance: Exceptions require compensating monitoring and approval.
            automatable: true
            manual_evidence_allowed: true
            evidence_expectations:
              - id: privileged-mfa-state
                title: Privileged MFA state
                type: identity_configuration
                description: Current MFA enrollment state for privileged accounts.
                required: true
                assessment_methods: [examine, test]
                freshness_sla: 30d
                accepted_from: [identity_provider, source_snapshot]
`)
	index, issues := BuildCatalogIndex(catalog)
	if len(issues) != 0 {
		t.Fatalf("BuildCatalogIndex() issues = %#v, want none", issues)
	}
	control, ok := index.Control(ControlRef{FrameworkID: "custom", ControlID: "IAM-1"})
	if !ok {
		t.Fatal("Control(custom IAM-1) not found")
	}

	readiness := EvaluateControlReadiness(control)
	if readiness.Status != ControlReadinessAuditorReady || readiness.Score != 100 || len(readiness.MissingFields) != 0 {
		t.Fatalf("readiness = %#v, want auditor-ready 100 score", readiness)
	}
}

func TestEvaluateControlReadinessClassifiesPlaceholderControl(t *testing.T) {
	readiness := EvaluateControlReadiness(ResolvedControl{Control: Control{ID: "CC6.1"}})
	if readiness.Status != ControlReadinessPlaceholder {
		t.Fatalf("Status = %q, want placeholder", readiness.Status)
	}
	if readiness.Score >= 50 {
		t.Fatalf("Score = %d, want below placeholder threshold", readiness.Score)
	}
	if !stringSliceContains(readiness.MissingFields, "objective") || !stringSliceContains(readiness.MissingFields, "evidence_expectations") {
		t.Fatalf("MissingFields = %#v, want core audit fields", readiness.MissingFields)
	}
}
