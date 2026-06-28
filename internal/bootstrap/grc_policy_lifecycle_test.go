package bootstrap

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/fabriccontract"
	"github.com/writer/cerebro/internal/ports"
)

func TestGRCPolicyLifecycleEndpointReturnsOperationalObjects(t *testing.T) {
	policy := grcPolicyLifecycleTestNode("urn:cerebro:writer:policy:policyops:policy:access", "policy", "Access Control Policy", map[string]string{
		"policy_id":      "access",
		"policy_type":    "policy",
		"status":         "approved",
		"review_cadence": "annual",
	})
	template := grcPolicyLifecycleTestNode("urn:cerebro:writer:policy_template:policyops:access", "policy.template", "Access Control Template", map[string]string{
		"template_id": "tpl-access",
		"frameworks":  "SOC 2",
		"status":      "published",
	})
	version := grcPolicyLifecycleTestNode("urn:cerebro:writer:policy_version:policyops:v2", "policy.version", "Access Control Policy v2", map[string]string{
		"policy_id":         "access",
		"policy_version_id": "v2",
		"version":           "2",
		"status":            "draft",
		"change_summary":    "Updated privileged access review scope.",
	})
	approval := grcPolicyLifecycleTestNode("urn:cerebro:writer:policy_approval:policyops:approval-1", "policy.approval", "Access Control approval", map[string]string{
		"approval_id":       "approval-1",
		"policy_id":         "access",
		"policy_version_id": "v2",
		"status":            "pending",
		"due_at":            "2026-01-04",
	})
	acceptance := grcPolicyLifecycleTestNode("urn:cerebro:writer:policy_acceptance:policyops:acceptance-1", "policy.acceptance", "Access Control attestation", map[string]string{
		"acceptance_id":     "acceptance-1",
		"policy_id":         "access",
		"policy_version_id": "v2",
		"status":            "pending",
		"due_at":            "2026-01-03",
	})
	review := grcPolicyLifecycleTestNode("urn:cerebro:writer:policy_review:policyops:review-1", "policy.review", "Access Control owner review", map[string]string{
		"review_id":      "review-1",
		"policy_id":      "access",
		"status":         "pending",
		"review_due_at":  "2026-01-02",
		"review_cadence": "annual",
	})
	exception := grcPolicyLifecycleTestNode("urn:cerebro:writer:policy_exception:policyops:exception-1", "policy.exception", "Temporary laptop waiver", map[string]string{
		"exception_id": "exception-1",
		"policy_id":    "access",
		"status":       "active",
		"expires_at":   "2026-07-15",
	})
	reminder := grcPolicyLifecycleTestNode("urn:cerebro:writer:policy_reminder:policyops:reminder-1", "policy.reminder", "Access Control reminder", map[string]string{
		"reminder_id": "reminder-1",
		"policy_id":   "access",
		"status":      "sent",
		"sent_at":     "2026-01-05T12:00:00Z",
	})
	control := grcPolicyLifecycleTestNode("urn:cerebro:writer:policy:policyops:control:CC6.1", "policy", "CC6.1", map[string]string{
		"policy_id":   "CC6.1",
		"policy_type": "control",
		"control_id":  "CC6.1",
		"framework":   "SOC 2",
	})
	document := grcPolicyLifecycleTestNode("urn:cerebro:writer:document:policyops:doc-1", "document", "Access Control PDF", map[string]string{
		"document_id":   "doc-1",
		"document_type": "policy_pdf",
		"status":        "draft",
		"review_due_at": "2026-01-01",
	})
	risk := grcPolicyLifecycleTestNode("urn:cerebro:writer:claim:policyops:risk_scenario:risk-1", "claim", "Access review risk", map[string]string{
		"claim_type":          "risk_scenario",
		"risk_id":             "risk-1",
		"status":              "open",
		"residual_risk_level": "high",
		"review_due_at":       "2026-01-01",
	})
	group := grcPolicyLifecycleTestNode("urn:cerebro:writer:grc_group:policyops:employees", "grc.group", "All employees", map[string]string{"group_id": "employees"})
	owner := grcPolicyLifecycleTestNode("urn:cerebro:writer:user:policyops:owner-1", "user", "owner@example.com", map[string]string{"user_id": "owner-1"})
	reviewer := grcPolicyLifecycleTestNode("urn:cerebro:writer:user:policyops:reviewer-1", "user", "reviewer@example.com", map[string]string{"user_id": "reviewer-1"})
	approver := grcPolicyLifecycleTestNode("urn:cerebro:writer:user:policyops:approver-1", "user", "approver@example.com", map[string]string{"user_id": "approver-1"})
	person := grcPolicyLifecycleTestNode("urn:cerebro:writer:person:policyops:person-1", "person", "employee@example.com", map[string]string{"person_id": "person-1"})
	asset := grcPolicyLifecycleTestNode("urn:cerebro:writer:device:device-1", "device", "laptop-1", map[string]string{"device_id": "device-1"})

	graph := &stubGraphStore{cypherRows: [][]ports.CypherRow{
		{policy, template, version, approval, acceptance, review, exception, reminder, document, risk},
		{
			grcPolicyLifecycleTestRelation(policy, fabriccontract.RelationOwnedBy, nil, owner),
			grcPolicyLifecycleTestRelation(policy, fabriccontract.RelationSupports, nil, control),
			grcPolicyLifecycleTestRelation(policy, fabriccontract.RelationHasEvidence, nil, document),
			grcPolicyLifecycleTestRelation(document, fabriccontract.RelationAssociatedWith, nil, policy),
			grcPolicyLifecycleTestRelation(document, fabriccontract.RelationAssociatedWith, nil, risk),
			grcPolicyLifecycleTestRelation(template, fabriccontract.RelationSupports, nil, control),
			grcPolicyLifecycleTestRelation(version, fabriccontract.RelationBelongsTo, nil, policy),
			grcPolicyLifecycleTestRelation(version, fabriccontract.RelationSupports, nil, control),
			grcPolicyLifecycleTestRelation(version, fabriccontract.RelationAssignedTo, nil, group),
			grcPolicyLifecycleTestRelation(approval, fabriccontract.RelationAssociatedWith, nil, policy),
			grcPolicyLifecycleTestRelation(approver, fabriccontract.RelationActedOn, map[string]string{"action": "approved"}, approval),
			grcPolicyLifecycleTestRelation(acceptance, fabriccontract.RelationAssociatedWith, nil, policy),
			grcPolicyLifecycleTestRelation(acceptance, fabriccontract.RelationAssignedTo, nil, group),
			grcPolicyLifecycleTestRelation(person, fabriccontract.RelationHasEvidence, nil, acceptance),
			grcPolicyLifecycleTestRelation(review, fabriccontract.RelationAssociatedWith, nil, policy),
			grcPolicyLifecycleTestRelation(review, fabriccontract.RelationOwnedBy, nil, owner),
			grcPolicyLifecycleTestRelation(reviewer, fabriccontract.RelationActedOn, map[string]string{"action": "reviewed"}, review),
			grcPolicyLifecycleTestRelation(exception, fabriccontract.RelationAssociatedWith, nil, policy),
			grcPolicyLifecycleTestRelation(exception, fabriccontract.RelationAssociatedWith, nil, control),
			grcPolicyLifecycleTestRelation(exception, fabriccontract.RelationTargeted, nil, asset),
			grcPolicyLifecycleTestRelation(risk, fabriccontract.RelationHasEvidence, nil, document),
			grcPolicyLifecycleTestRelation(risk, fabriccontract.RelationAssociatedWith, nil, policy),
			grcPolicyLifecycleTestRelation(risk, fabriccontract.RelationAssociatedWith, nil, control),
			grcPolicyLifecycleTestRelation(risk, fabriccontract.RelationAssignedTo, nil, owner),
			grcPolicyLifecycleTestRelation(reminder, fabriccontract.RelationAssociatedWith, nil, policy),
			grcPolicyLifecycleTestRelation(reminder, fabriccontract.RelationAssignedTo, nil, group),
		},
	}}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{GraphStore: graph}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	resp, err := server.Client().Get(server.URL + "/grc/policy-lifecycle?tenant_id=writer&source_id=grc&runtime_id=writer-grc")
	if err != nil {
		t.Fatalf("GET /grc/policy-lifecycle error = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /grc/policy-lifecycle status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var payload struct {
		Summary struct {
			Policies               int `json:"policies"`
			Templates              int `json:"templates"`
			PolicyDocuments        int `json:"policy_documents"`
			RiskRegisterItems      int `json:"risk_register_items"`
			DraftVersions          int `json:"draft_versions"`
			DraftDocuments         int `json:"draft_documents"`
			PendingApprovals       int `json:"pending_approvals"`
			OverdueReviews         int `json:"overdue_reviews"`
			DocumentsDueForReview  int `json:"documents_due_for_review"`
			OpenRisks              int `json:"open_risks"`
			HighRisks              int `json:"high_risks"`
			AttestationCoveragePct int `json:"attestation_coverage_pct"`
			OverdueAttestations    int `json:"overdue_attestations"`
			MappedControls         int `json:"mapped_controls"`
			EvidenceItems          int `json:"evidence_items"`
		} `json:"summary"`
		Policies []struct {
			ID            string `json:"id"`
			Owner         string `json:"owner"`
			LatestVersion string `json:"latest_version"`
			VersionStatus string `json:"version_status"`
			Approvals     []any  `json:"approvals"`
			Attestations  []any  `json:"attestations"`
			Exceptions    []any  `json:"exceptions"`
			Reviews       []any  `json:"reviews"`
		} `json:"policies"`
		Documents []struct {
			ID       string `json:"id"`
			Status   string `json:"status"`
			Policies []any  `json:"policies"`
			Risks    []any  `json:"risks"`
		} `json:"documents"`
		RiskRegister []struct {
			ID               string `json:"id"`
			ResidualRisk     string `json:"residual_risk"`
			SourceDocumentID string `json:"source_document_id"`
		} `json:"risk_register"`
		WorkQueue         []any `json:"work_queue"`
		DocumentWorkQueue []any `json:"document_work_queue"`
		Templates         []struct {
			Controls []any `json:"controls"`
		} `json:"templates"`
		Reminders []struct {
			Recipients []string `json:"recipients"`
		} `json:"reminders"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode policy lifecycle: %v", err)
	}
	if payload.Summary.Policies != 1 || payload.Summary.Templates != 1 {
		t.Fatalf("summary = %+v, want one policy and one template", payload.Summary)
	}
	if payload.Summary.PolicyDocuments != 1 || payload.Summary.RiskRegisterItems != 1 || payload.Summary.DraftDocuments != 1 || payload.Summary.DocumentsDueForReview != 0 || payload.Summary.OpenRisks != 1 || payload.Summary.HighRisks != 1 {
		t.Fatalf("summary document/risk rollups = %+v, want document and risk counts", payload.Summary)
	}
	if payload.Summary.DraftVersions != 1 || payload.Summary.PendingApprovals != 1 || payload.Summary.OverdueReviews != 1 || payload.Summary.OverdueAttestations != 1 {
		t.Fatalf("summary queues = %+v, want draft, approval, review, and attestation work", payload.Summary)
	}
	if payload.Summary.MappedControls != 1 || payload.Summary.EvidenceItems != 1 {
		t.Fatalf("summary mappings = %+v, want one control and one evidence item", payload.Summary)
	}
	if len(payload.Policies) != 1 || payload.Policies[0].ID != "access" {
		t.Fatalf("policies = %+v, want access policy", payload.Policies)
	}
	policyItem := payload.Policies[0]
	if policyItem.Owner != "owner@example.com" || policyItem.LatestVersion != "2" || policyItem.VersionStatus != "draft" {
		t.Fatalf("policy = %+v, want owner and latest draft version", policyItem)
	}
	if len(policyItem.Approvals) != 1 || len(policyItem.Attestations) != 1 || len(policyItem.Exceptions) != 1 || len(policyItem.Reviews) != 1 {
		t.Fatalf("policy lifecycle children = %+v", policyItem)
	}
	if len(payload.WorkQueue) < 4 {
		t.Fatalf("work queue len = %d, want draft, approval, review, attestation, exception work", len(payload.WorkQueue))
	}
	if len(payload.Documents) != 1 || payload.Documents[0].ID != "doc-1" || len(payload.Documents[0].Policies) != 1 || len(payload.Documents[0].Risks) != 1 {
		t.Fatalf("documents = %+v, want linked policy document", payload.Documents)
	}
	if len(payload.RiskRegister) != 1 || payload.RiskRegister[0].ID != "risk-1" || payload.RiskRegister[0].ResidualRisk != "high" || payload.RiskRegister[0].SourceDocumentID != "doc-1" {
		t.Fatalf("risk register = %+v, want linked high risk", payload.RiskRegister)
	}
	if len(payload.DocumentWorkQueue) < 2 {
		t.Fatalf("document work queue len = %d, want draft document and risk work", len(payload.DocumentWorkQueue))
	}
	if len(payload.Templates) != 1 || len(payload.Templates[0].Controls) != 1 {
		t.Fatalf("templates = %+v, want template control mapping", payload.Templates)
	}
	if len(payload.Reminders) != 1 || payload.Reminders[0].Recipients[0] != "All employees" {
		t.Fatalf("reminders = %+v, want employee recipient", payload.Reminders)
	}
	if len(graph.cypherRequests) != 2 || graph.cypherRequests[0].Params["tenant_id"] != "writer" {
		t.Fatalf("cypher requests = %#v, want scoped entity and relation reads", graph.cypherRequests)
	}
	for _, request := range graph.cypherRequests {
		if request.Params["source_id"] != "grc" || request.Params["runtime_id"] != "writer-grc" {
			t.Fatalf("cypher request params = %#v, want source and runtime filters", request.Params)
		}
		if !strings.Contains(request.Query, "$source_id") || !strings.Contains(request.Query, "$runtime_id") {
			t.Fatalf("cypher query %q does not reference source and runtime filters", request.Query)
		}
	}
}

func grcPolicyLifecycleTestNode(urn string, entityType string, label string, attrs map[string]string) ports.CypherRow {
	rawAttrs, _ := json.Marshal(attrs)
	return ports.CypherRow{Values: map[string]any{
		"urn":             urn,
		"tenant_id":       "writer",
		"source_id":       "grc",
		"runtime_id":      "writer-grc",
		"entity_type":     entityType,
		"label":           label,
		"attributes_json": string(rawAttrs),
	}}
}

func grcPolicyLifecycleTestRelation(left ports.CypherRow, relation string, attrs map[string]string, right ports.CypherRow) ports.CypherRow {
	values := map[string]any{}
	for key, value := range left.Values {
		values["left_"+key] = value
	}
	for key, value := range right.Values {
		values["right_"+key] = value
	}
	rawAttrs, _ := json.Marshal(attrs)
	values["relation"] = relation
	values["relation_attributes_json"] = string(rawAttrs)
	return ports.CypherRow{Values: values}
}
