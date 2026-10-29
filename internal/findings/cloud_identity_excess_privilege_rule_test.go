package findings

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/cloudidentity"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestCloudIdentityExcessPrivilegeRuleRuntimeScope(t *testing.T) {
	rule := newCloudIdentityExcessPrivilegeRule()
	if !rule.SupportsRuntime(&cerebrov1.SourceRuntime{SourceId: cloudidentity.SourceID}) {
		t.Fatal("SupportsRuntime(cloud_identity) = false, want true")
	}
	if rule.SupportsRuntime(&cerebrov1.SourceRuntime{SourceId: "other_source"}) {
		t.Fatal("SupportsRuntime(other_source) = true, want false")
	}
}

func TestCloudIdentityExcessPrivilegeRuleAWSSupportedExcess(t *testing.T) {
	baseTime := time.Date(2026, time.March, 2, 9, 0, 0, 0, time.UTC)
	evidence := cloudIdentityAWSExcessEvidence(baseTime)
	assessment := cloudidentity.Assess(evidence, baseTime, cloudIdentityAssessmentMaxAge)
	if assessment.Status != cloudidentity.Supported {
		t.Fatalf("fixture assessment.Status = %q, want %q; keep this fixture in sync with cloudidentity.Assess", assessment.Status, cloudidentity.Supported)
	}

	rule := newCloudIdentityExcessPrivilegeRuleWithClock(func() time.Time { return baseTime })
	runtime := &cerebrov1.SourceRuntime{Id: "writer-cloud-identity", SourceId: cloudidentity.SourceID, TenantId: "writer"}
	event := cloudIdentityEvidenceEvent(t, "event-aws-1", evidence)

	records, err := rule.Evaluate(context.Background(), runtime, event)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("Evaluate() returned %d records, want 1", len(records))
	}
	finding := records[0]
	if finding.RuleID != cloudIdentityExcessPrivilegeRuleID {
		t.Fatalf("RuleID = %q, want %q", finding.RuleID, cloudIdentityExcessPrivilegeRuleID)
	}
	if finding.Status != findingStatusOpen {
		t.Fatalf("Status = %q, want %q", finding.Status, findingStatusOpen)
	}
	if finding.TenantID != "writer" {
		t.Fatalf("TenantID = %q, want writer", finding.TenantID)
	}
	if got := finding.Attributes["cloud_provider"]; got != "aws" {
		t.Fatalf("Attributes[cloud_provider] = %q, want aws", got)
	}
	if got := finding.Attributes["side"]; got != assessment.Side {
		t.Fatalf("Attributes[side] = %q, want %q", got, assessment.Side)
	}
	if finding.Attributes["declared_excess"] == "" || finding.Attributes["observed_excess"] == "" {
		t.Fatalf("expected non-empty declared_excess and observed_excess, got declared=%q observed=%q", finding.Attributes["declared_excess"], finding.Attributes["observed_excess"])
	}
	if !strings.Contains(finding.Attributes["declared_excess"], "s3:DeleteBucket") {
		t.Fatalf("declared_excess = %q, want to mention s3:DeleteBucket", finding.Attributes["declared_excess"])
	}
	if finding.Attributes["declared_citations"] == "" || finding.Attributes["observed_citations"] == "" {
		t.Fatal("expected both declared and observed citation attributes to be populated (source facts, not just a verdict)")
	}
	if !strings.Contains(finding.Attributes["declared_citations"], "example-org/infra") {
		t.Fatalf("declared_citations = %q, want the IaC repository citation", finding.Attributes["declared_citations"])
	}
	if !strings.Contains(finding.Attributes["observed_citations"], "iam:GetRolePolicy") {
		t.Fatalf("observed_citations = %q, want the live API citation", finding.Attributes["observed_citations"])
	}

	wantPrincipalURN := cloudIdentityPrincipalScopeURN("writer", cloudidentity.AWS, evidence.Principal.ID, evidence.Scope)
	if finding.Attributes["cloud_identity_principal_scope_urn"] != wantPrincipalURN {
		t.Fatalf("Attributes[cloud_identity_principal_scope_urn] = %q, want %q", finding.Attributes["cloud_identity_principal_scope_urn"], wantPrincipalURN)
	}
	wantEvidenceDigest, err := cloudIdentityDigest(evidence)
	if err != nil {
		t.Fatalf("cloudIdentityDigest(evidence) error = %v", err)
	}
	if got := finding.Attributes["cloud_identity_evidence_digest"]; got != wantEvidenceDigest {
		t.Fatalf("Attributes[cloud_identity_evidence_digest] = %q, want %q (actual evidence content digest, not an ID string)", got, wantEvidenceDigest)
	}
	wantAssessmentDigest, err := cloudIdentityDigest(assessment)
	if err != nil {
		t.Fatalf("cloudIdentityDigest(assessment) error = %v", err)
	}
	if got := finding.Attributes["cloud_identity_assessment_digest"]; got != wantAssessmentDigest {
		t.Fatalf("Attributes[cloud_identity_assessment_digest] = %q, want %q (actual machine assessment output digest, not an ID string)", got, wantAssessmentDigest)
	}
	if !containsTrimmed(finding.ResourceURNs, wantPrincipalURN) {
		t.Fatalf("ResourceURNs = %#v, want principal URN %q", finding.ResourceURNs, wantPrincipalURN)
	}
	if len(finding.GraphEvidenceRows) != 1 {
		t.Fatalf("GraphEvidenceRows = %d, want 1", len(finding.GraphEvidenceRows))
	}
	paths := finding.GraphEvidenceRows[0].GetPaths()
	if len(paths) == 0 {
		t.Fatal("GraphEvidenceRows[0].Paths is empty, want workload->service_account->principal graph-join citations")
	}
	var sawRunsAs, sawRepresentsIdentity bool
	for _, path := range paths {
		switch path.GetRelation() {
		case "runs_as":
			sawRunsAs = true
		case "represents_identity":
			sawRepresentsIdentity = true
		}
	}
	if !sawRunsAs || !sawRepresentsIdentity {
		t.Fatalf("expected runs_as and represents_identity citation paths, got %+v", paths)
	}
	if finding.Severity == "" {
		t.Fatal("Severity must not be empty")
	}
	if finding.Fingerprint == "" || finding.ID != finding.Fingerprint {
		t.Fatalf("ID/Fingerprint must be set and equal, got ID=%q Fingerprint=%q", finding.ID, finding.Fingerprint)
	}
}

func TestCloudIdentityExcessPrivilegeRuleGCPSupportedExcess(t *testing.T) {
	baseTime := time.Date(2026, time.March, 3, 9, 0, 0, 0, time.UTC)
	evidence := cloudIdentityGCPExcessEvidence(baseTime)
	assessment := cloudidentity.Assess(evidence, baseTime, cloudIdentityAssessmentMaxAge)
	if assessment.Status != cloudidentity.Supported {
		t.Fatalf("fixture assessment.Status = %q, want %q; keep this fixture in sync with cloudidentity.Assess", assessment.Status, cloudidentity.Supported)
	}

	rule := newCloudIdentityExcessPrivilegeRuleWithClock(func() time.Time { return baseTime })
	runtime := &cerebrov1.SourceRuntime{Id: "writer-cloud-identity", SourceId: cloudidentity.SourceID, TenantId: "writer"}
	event := cloudIdentityEvidenceEvent(t, "event-gcp-1", evidence)

	records, err := rule.Evaluate(context.Background(), runtime, event)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("Evaluate() returned %d records, want 1", len(records))
	}
	finding := records[0]
	if got := finding.Attributes["cloud_provider"]; got != "gcp" {
		t.Fatalf("Attributes[cloud_provider] = %q, want gcp", got)
	}
	if got := finding.Attributes["project_id"]; got != evidence.Principal.Project {
		t.Fatalf("Attributes[project_id] = %q, want %q", got, evidence.Principal.Project)
	}
	if !strings.Contains(finding.Attributes["declared_excess"], "storage.objects.delete") {
		t.Fatalf("declared_excess = %q, want to mention storage.objects.delete", finding.Attributes["declared_excess"])
	}
}

func TestCloudIdentityExcessPrivilegeRuleCandidateInvisibleInConfirmedFindings(t *testing.T) {
	baseTime := time.Date(2026, time.March, 2, 9, 0, 0, 0, time.UTC)
	evidence := cloudIdentityAWSIncompleteEvidence(baseTime)
	assessment := cloudidentity.Assess(evidence, baseTime, cloudIdentityAssessmentMaxAge)
	if assessment.Status == cloudidentity.Supported {
		t.Fatalf("fixture assessment.Status = %q, want anything but Supported for an incomplete/candidate cohort", assessment.Status)
	}

	rule := newCloudIdentityExcessPrivilegeRuleWithClock(func() time.Time { return baseTime })
	runtime := &cerebrov1.SourceRuntime{Id: "writer-cloud-identity", SourceId: cloudidentity.SourceID, TenantId: "writer"}
	event := cloudIdentityEvidenceEvent(t, "event-incomplete-1", evidence)

	records, err := rule.Evaluate(context.Background(), runtime, event)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("Evaluate() returned %d records for a non-Supported assessment, want 0 (no automatic promotion without Supported)", len(records))
	}
}

func TestCloudIdentityExcessPrivilegeRulePartialDoesNotCloseSupportedFinding(t *testing.T) {
	baseTime := time.Date(2026, time.March, 2, 9, 0, 0, 0, time.UTC)
	rule := newCloudIdentityExcessPrivilegeRuleWithClock(func() time.Time { return baseTime.Add(time.Hour) })
	counterRule, ok := durableStateCounterEventRule(rule)
	if !ok {
		t.Fatal("cloud-identity-excess-privilege does not implement durable CounterEventRule")
	}

	partial := cloudIdentityAWSIncompleteEvidence(baseTime.Add(time.Hour))
	partialAssessment := cloudidentity.Assess(partial, baseTime.Add(time.Hour), cloudIdentityAssessmentMaxAge)
	if partialAssessment.Status == cloudidentity.Clear {
		t.Fatalf("fixture assessment.Status = %q, want anything but Clear so it cannot close an open finding", partialAssessment.Status)
	}
	partialEvent := cloudIdentityEvidenceEvent(t, "event-partial-1", partial)
	if anchor, closes := counterRule.CloseOnEvent(partialEvent); closes || anchor != "" {
		t.Fatalf("CloseOnEvent(partial) = %q/%v, want empty/false; partial/incomplete reassessment must never close a supported finding", anchor, closes)
	}
}

func TestCloudIdentityExcessPrivilegeRuleCloseReopenStableFingerprint(t *testing.T) {
	baseTime := time.Date(2026, time.March, 2, 9, 0, 0, 0, time.UTC)
	clock := baseTime
	rule := newCloudIdentityExcessPrivilegeRuleWithClock(func() time.Time { return clock })
	runtime := &cerebrov1.SourceRuntime{Id: "writer-cloud-identity", SourceId: cloudidentity.SourceID, TenantId: "writer"}
	counterRule, ok := durableStateCounterEventRule(rule)
	if !ok {
		t.Fatal("cloud-identity-excess-privilege does not implement durable CounterEventRule")
	}

	excessEvidence := cloudIdentityAWSExcessEvidence(baseTime)
	openEvent := cloudIdentityEvidenceEvent(t, "event-open-1", excessEvidence)
	opened, err := rule.Evaluate(context.Background(), runtime, openEvent)
	if err != nil || len(opened) != 1 {
		t.Fatalf("Evaluate(open) = %v / err=%v, want 1 finding", opened, err)
	}
	firstFingerprint := opened[0].Fingerprint

	clock = baseTime.Add(time.Hour)
	clearEvidence := cloudIdentityAWSClearEvidence(baseTime.Add(time.Hour))
	clearAssessment := cloudidentity.Assess(clearEvidence, baseTime.Add(time.Hour), cloudIdentityAssessmentMaxAge)
	if clearAssessment.Status != cloudidentity.Clear {
		t.Fatalf("fixture assessment.Status = %q, want %q; keep this fixture in sync with cloudidentity.Assess", clearAssessment.Status, cloudidentity.Clear)
	}
	closeEvent := cloudIdentityEvidenceEvent(t, "event-close-1", clearEvidence)
	anchor, closes := counterRule.CloseOnEvent(closeEvent)
	if !closes || anchor == "" {
		t.Fatalf("CloseOnEvent(clear) = %q/%v, want non-empty/true", anchor, closes)
	}
	if wantAnchor := counterRule.OpenAnchor(opened[0].Attributes); anchor != wantAnchor {
		t.Fatalf("CloseOnEvent anchor = %q, want %q (must match the original OpenAnchor)", anchor, wantAnchor)
	}

	clock = baseTime.Add(2 * time.Hour)
	reopenEvidence := cloudIdentityAWSExcessEvidence(baseTime.Add(2 * time.Hour))
	reopenEvent := cloudIdentityEvidenceEvent(t, "event-reopen-1", reopenEvidence)
	reopened, err := rule.Evaluate(context.Background(), runtime, reopenEvent)
	if err != nil || len(reopened) != 1 {
		t.Fatalf("Evaluate(reopen) = %v / err=%v, want 1 finding", reopened, err)
	}
	if reopened[0].Fingerprint != firstFingerprint {
		t.Fatalf("reopened fingerprint = %q, want %q (remediation/recurrence must retain the stable fingerprint)", reopened[0].Fingerprint, firstFingerprint)
	}
}

// TestCloudIdentityExcessPrivilegeRuleStaleEvidenceNeitherOpensNorCloses pins
// VAL item 5: freshness is evaluated against the rule's injected trusted
// clock, never EventEnvelope.OccurredAt, so evidence collected 72h before the
// evaluation clock (beyond cloudIdentityAssessmentMaxAge=48h) is treated as
// unknown freshness: an otherwise-Supported excess cohort does not open a
// finding, and an otherwise-Clear cohort does not close one.
func TestCloudIdentityExcessPrivilegeRuleStaleEvidenceNeitherOpensNorCloses(t *testing.T) {
	evalTime := time.Date(2026, time.March, 10, 9, 0, 0, 0, time.UTC)
	staleCollectedAt := evalTime.Add(-72 * time.Hour)

	rule := newCloudIdentityExcessPrivilegeRuleWithClock(func() time.Time { return evalTime })
	runtime := &cerebrov1.SourceRuntime{Id: "writer-cloud-identity", SourceId: cloudidentity.SourceID, TenantId: "writer"}

	staleExcess := cloudIdentityAWSExcessEvidence(staleCollectedAt)
	openEvent := cloudIdentityEvidenceEvent(t, "event-stale-open-1", staleExcess)
	// The event's own OccurredAt is set to the stale CollectedAt too; if the
	// rule ever fell back to EventEnvelope.OccurredAt instead of the
	// injected clock, "now" would equal CollectedAt and look fresh.
	records, err := rule.Evaluate(context.Background(), runtime, openEvent)
	if err != nil {
		t.Fatalf("Evaluate(stale excess) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("Evaluate(stale excess) returned %d records, want 0 (stale evidence must not open a finding)", len(records))
	}

	counterRule, ok := durableStateCounterEventRule(rule)
	if !ok {
		t.Fatal("cloud-identity-excess-privilege does not implement durable CounterEventRule")
	}
	staleClear := cloudIdentityAWSClearEvidence(staleCollectedAt)
	closeEvent := cloudIdentityEvidenceEvent(t, "event-stale-close-1", staleClear)
	if anchor, closes := counterRule.CloseOnEvent(closeEvent); closes || anchor != "" {
		t.Fatalf("CloseOnEvent(stale clear) = %q/%v, want empty/false (stale evidence must not close a finding)", anchor, closes)
	}
}

// TestCloudIdentityExcessPrivilegeRuleFutureEvidenceNeitherOpensNorCloses
// covers the symmetric future-dated case from VAL item 5.
func TestCloudIdentityExcessPrivilegeRuleFutureEvidenceNeitherOpensNorCloses(t *testing.T) {
	evalTime := time.Date(2026, time.March, 10, 9, 0, 0, 0, time.UTC)
	futureCollectedAt := evalTime.Add(72 * time.Hour)

	rule := newCloudIdentityExcessPrivilegeRuleWithClock(func() time.Time { return evalTime })
	runtime := &cerebrov1.SourceRuntime{Id: "writer-cloud-identity", SourceId: cloudidentity.SourceID, TenantId: "writer"}

	futureExcess := cloudIdentityAWSExcessEvidence(futureCollectedAt)
	openEvent := cloudIdentityEvidenceEvent(t, "event-future-open-1", futureExcess)
	records, err := rule.Evaluate(context.Background(), runtime, openEvent)
	if err != nil {
		t.Fatalf("Evaluate(future excess) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("Evaluate(future excess) returned %d records, want 0 (future-dated evidence must not open a finding)", len(records))
	}
}

// TestCloudIdentityExcessPrivilegeRuleFreshEvidenceStillOpensAndCloses is the
// control case for VAL item 5: evidence within the freshness window still
// opens a Supported excess finding and closes it on a later Clear cohort.
func TestCloudIdentityExcessPrivilegeRuleFreshEvidenceStillOpensAndCloses(t *testing.T) {
	evalTime := time.Date(2026, time.March, 10, 9, 0, 0, 0, time.UTC)
	freshCollectedAt := evalTime.Add(-1 * time.Hour)

	rule := newCloudIdentityExcessPrivilegeRuleWithClock(func() time.Time { return evalTime })
	runtime := &cerebrov1.SourceRuntime{Id: "writer-cloud-identity", SourceId: cloudidentity.SourceID, TenantId: "writer"}

	freshExcess := cloudIdentityAWSExcessEvidence(freshCollectedAt)
	openEvent := cloudIdentityEvidenceEvent(t, "event-fresh-open-1", freshExcess)
	records, err := rule.Evaluate(context.Background(), runtime, openEvent)
	if err != nil {
		t.Fatalf("Evaluate(fresh excess) error = %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("Evaluate(fresh excess) returned %d records, want 1", len(records))
	}

	counterRule, ok := durableStateCounterEventRule(rule)
	if !ok {
		t.Fatal("cloud-identity-excess-privilege does not implement durable CounterEventRule")
	}
	freshClear := cloudIdentityAWSClearEvidence(freshCollectedAt)
	closeEvent := cloudIdentityEvidenceEvent(t, "event-fresh-close-1", freshClear)
	if anchor, closes := counterRule.CloseOnEvent(closeEvent); !closes || anchor == "" {
		t.Fatalf("CloseOnEvent(fresh clear) = %q/%v, want non-empty/true", anchor, closes)
	}
}

func TestCloudIdentityExcessPrivilegeRuleRejectsMismatchedAttributes(t *testing.T) {
	baseTime := time.Date(2026, time.March, 2, 9, 0, 0, 0, time.UTC)
	evidence := cloudIdentityAWSExcessEvidence(baseTime)
	event := cloudIdentityEvidenceEvent(t, "event-mismatch-1", evidence)
	event.Attributes["principal_id"] = "arn:aws:iam::999999999999:role/unrelated-role"

	rule := newCloudIdentityExcessPrivilegeRule()
	runtime := &cerebrov1.SourceRuntime{Id: "writer-cloud-identity", SourceId: cloudidentity.SourceID, TenantId: "writer"}
	records, err := rule.Evaluate(context.Background(), runtime, event)
	if err == nil {
		t.Fatal("Evaluate() error = nil, want a rejection error for mismatched payload/attributes")
	}
	if len(records) != 0 {
		t.Fatalf("Evaluate() returned %d records on mismatched attrs, want 0", len(records))
	}
}

// --- fixtures shared with cloud_identity_shared_principal_rule_test.go ---

func cloudIdentityAWSExcessEvidence(baseTime time.Time) cloudidentity.Evidence {
	principal := cloudidentity.Principal{
		ID:       "arn:aws:iam::111111111111:role/payments-processor",
		Provider: cloudidentity.AWS,
		Kind:     "role",
		Account:  "111111111111",
	}
	scope := principal.ID
	consumer := cloudidentity.Workload{
		ID:             "payments/payments-processor",
		Service:        "payments-processor",
		Environment:    "prod",
		Cluster:        "prod-use1",
		Namespace:      "payments",
		Name:           "payments-processor",
		Kind:           "Deployment",
		ServiceAccount: "payments-processor",
		Image:          "111111111111.dkr.ecr.us-east-1.amazonaws.com/payments-processor:1.2.3",
		Source: cloudidentity.SourcePin{
			Repository: "example-org/payments-processor",
			Revision:   "a1b2c3d4",
			Exact:      true,
			Digest:     "sha256:appdigest",
		},
		Principals: []cloudidentity.Principal{principal},
		References: []cloudidentity.Reference{{
			Repository: "example-org/payments-processor",
			Revision:   "a1b2c3d4",
			Path:       "deploy/deployment.yaml",
			Digest:     "sha256:manifestdigest",
		}},
	}
	declaredGrant := cloudidentity.Grant{
		ID:        "grant-s3-access",
		Effect:    "Allow",
		Actions:   []string{"s3:GetObject", "s3:DeleteBucket"},
		Resources: []string{"arn:aws:s3:::payments-bucket/*"},
		References: []cloudidentity.Reference{{
			Repository: "example-org/infra",
			Revision:   "d4e5f6a7",
			Path:       "modules/payments/iam.tf",
			StartLine:  10,
			EndLine:    24,
			Digest:     "sha256:iacdigest",
		}},
	}
	observedGrant := declaredGrant
	observedGrant.References = []cloudidentity.Reference{{
		API:        "iam:GetRolePolicy",
		Scope:      scope,
		ObservedAt: baseTime,
		Digest:     "sha256:livedigest",
	}}
	trust := []cloudidentity.Grant{{
		ID: "workload-trust", Effect: "Allow", Actions: []string{"sts:AssumeRoleWithWebIdentity"},
		Members:    []string{"Federated:arn:aws:iam::111111111111:oidc-provider/oidc.eks.example.com/id/EX"},
		Conditions: []cloudidentity.Condition{{Operator: "StringEquals", Key: "oidc.eks.example.com/id/EX:sub", Values: []string{"system:serviceaccount:payments:payments-processor"}}},
	}}
	return cloudidentity.Evidence{
		Schema:                    cloudidentity.SchemaVersion,
		Principal:                 principal,
		Scope:                     scope,
		Consumers:                 []cloudidentity.Workload{consumer},
		ConsumerInventoryComplete: true,
		ResolvedIdentifiers:       map[string]string{"aws_eks_oidc_provider_arn:prod-use1": "arn:aws:iam::111111111111:oidc-provider/oidc.eks.example.com/id/EX"},
		Declared: cloudidentity.PolicyState{
			Grants:     []cloudidentity.Grant{declaredGrant},
			Trust:      trust,
			Complete:   true,
			ObservedAt: baseTime,
			References: declaredGrant.References,
		},
		Observed: cloudidentity.PolicyState{
			Grants:     []cloudidentity.Grant{observedGrant},
			Trust:      trust,
			Complete:   true,
			ObservedAt: baseTime,
			References: observedGrant.References,
		},
		Definitions: cloudidentity.MergeDefinitions(cloudidentity.Definitions{
			Complete: true,
			Actions:  []cloudidentity.ActionDefinition{{Name: "s3:GetObject"}, {Name: "s3:DeleteBucket"}},
		}),
		Investigations: []cloudidentity.Investigation{{
			ConsumerID: consumer.ID,
			Source:     consumer.Source,
			Requirements: []cloudidentity.Requirement{{
				Provider:    cloudidentity.AWS,
				Service:     "s3",
				Operation:   "GetObject",
				Action:      "s3:GetObject",
				Resources:   []string{"arn:aws:s3:::payments-bucket/*"},
				ConsumerIDs: []string{consumer.ID},
				References: []cloudidentity.Reference{{
					Repository: consumer.Source.Repository,
					Revision:   consumer.Source.Revision,
					Path:       "internal/storage/client.go",
					StartLine:  40,
					EndLine:    44,
					Digest:     "sha256:appdigest",
				}},
			}},
			Validation: cloudidentity.Validation{
				Analyzer:           "go-ast",
				SourceDigest:       "sha256:appdigest",
				CitationsVerified:  true,
				OperationsVerified: true,
				ScopeComplete:      true,
				CoveredFiles:       []string{"internal/storage/client.go"},
			},
		}},
		CollectedAt: baseTime,
	}
}

func cloudIdentityAWSClearEvidence(baseTime time.Time) cloudidentity.Evidence {
	evidence := cloudIdentityAWSExcessEvidence(baseTime)
	evidence.Declared.Grants = []cloudidentity.Grant{{
		ID:         evidence.Declared.Grants[0].ID,
		Effect:     "Allow",
		Actions:    []string{"s3:GetObject"},
		Resources:  evidence.Declared.Grants[0].Resources,
		References: evidence.Declared.Grants[0].References,
	}}
	evidence.Observed.Grants = []cloudidentity.Grant{{
		ID:         evidence.Observed.Grants[0].ID,
		Effect:     "Allow",
		Actions:    []string{"s3:GetObject"},
		Resources:  evidence.Observed.Grants[0].Resources,
		References: evidence.Observed.Grants[0].References,
	}}
	evidence.CollectedAt = baseTime
	return evidence
}

func cloudIdentityAWSIncompleteEvidence(baseTime time.Time) cloudidentity.Evidence {
	evidence := cloudIdentityAWSExcessEvidence(baseTime)
	evidence.ConsumerInventoryComplete = false
	evidence.Investigations = nil
	evidence.Gaps = []cloudidentity.Gap{{
		Code:    "unresolved_consumer",
		Scope:   evidence.Scope,
		Message: "unable to enumerate all workloads referencing this principal before the collection budget was exhausted",
	}}
	evidence.CollectedAt = baseTime
	return evidence
}

func cloudIdentityGCPExcessEvidence(baseTime time.Time) cloudidentity.Evidence {
	principal := cloudidentity.Principal{
		ID:       "checkout-api@acme-prod.iam.gserviceaccount.com",
		Provider: cloudidentity.GCP,
		Kind:     "service_account",
		Project:  "acme-prod",
	}
	scope := "projects/acme-prod"
	consumer := cloudidentity.Workload{
		ID:             "checkout/checkout-api",
		Service:        "checkout-api",
		Environment:    "prod",
		Cluster:        "prod-gke-use1",
		Namespace:      "checkout",
		Name:           "checkout-api",
		Kind:           "Deployment",
		ServiceAccount: "checkout-api",
		Image:          "us-docker.pkg.dev/acme-prod/checkout/checkout-api:2.0.0",
		Source: cloudidentity.SourcePin{
			Repository: "example-org/checkout-api",
			Revision:   "b2c3d4e5",
			Exact:      true,
			Digest:     "sha256:appdigest-gcp",
		},
		Principals: []cloudidentity.Principal{principal},
	}
	declaredGrant := cloudidentity.Grant{
		ID:        "grant-storage-access",
		Effect:    "Allow",
		Actions:   []string{"storage.objects.get", "storage.objects.delete"},
		Resources: []string{"projects/_/buckets/checkout-assets"},
		References: []cloudidentity.Reference{{
			Repository: "example-org/infra",
			Revision:   "c3d4e5f6",
			Path:       "modules/checkout/iam.tf",
			StartLine:  5,
			EndLine:    18,
			Digest:     "sha256:iacdigest-gcp",
		}},
	}
	observedGrant := declaredGrant
	observedGrant.References = []cloudidentity.Reference{{
		API:        "iam.serviceAccounts.getIamPolicy",
		Scope:      scope,
		ObservedAt: baseTime,
		Digest:     "sha256:livedigest-gcp",
	}}
	return cloudidentity.Evidence{
		Schema:                    cloudidentity.SchemaVersion,
		Principal:                 principal,
		Scope:                     scope,
		Consumers:                 []cloudidentity.Workload{consumer},
		ConsumerInventoryComplete: true,
		Declared: cloudidentity.PolicyState{
			Grants:     []cloudidentity.Grant{declaredGrant},
			Complete:   true,
			ObservedAt: baseTime,
			References: declaredGrant.References,
		},
		Observed: cloudidentity.PolicyState{
			Grants:     []cloudidentity.Grant{observedGrant},
			Complete:   true,
			ObservedAt: baseTime,
			References: observedGrant.References,
		},
		Definitions: cloudidentity.MergeDefinitions(cloudidentity.Definitions{
			Complete: true,
			Actions:  []cloudidentity.ActionDefinition{{Name: "storage.objects.get"}, {Name: "storage.objects.delete"}},
		}),
		Investigations: []cloudidentity.Investigation{{
			ConsumerID: consumer.ID,
			Source:     consumer.Source,
			Requirements: []cloudidentity.Requirement{{
				Provider:    cloudidentity.GCP,
				Service:     "storage",
				Operation:   "objects.get",
				Action:      "storage.objects.get",
				Resources:   []string{"projects/_/buckets/checkout-assets"},
				ConsumerIDs: []string{consumer.ID},
				References: []cloudidentity.Reference{{
					Repository: consumer.Source.Repository,
					Revision:   consumer.Source.Revision,
					Path:       "internal/storage/client.go",
					StartLine:  22,
					EndLine:    27,
					Digest:     "sha256:appdigest-gcp",
				}},
			}},
			Validation: cloudidentity.Validation{
				Analyzer:           "go-ast",
				SourceDigest:       "sha256:appdigest-gcp",
				CitationsVerified:  true,
				OperationsVerified: true,
				ScopeComplete:      true,
				CoveredFiles:       []string{"internal/storage/client.go"},
			},
		}},
		CollectedAt: baseTime,
	}
}

func cloudIdentityEvidenceEvent(t *testing.T, id string, evidence cloudidentity.Evidence) *cerebrov1.EventEnvelope {
	t.Helper()
	payload, err := json.Marshal(evidence)
	if err != nil {
		t.Fatalf("marshal evidence: %v", err)
	}
	attrs := map[string]string{
		"principal_id":   evidence.Principal.ID,
		"resource_id":    evidence.Principal.ID,
		"cloud_provider": string(evidence.Principal.Provider),
		"scope":          evidence.Scope,
		"resource_type":  "cloud_identity.principal",
	}
	if evidence.Principal.Account != "" {
		attrs["account_id"] = evidence.Principal.Account
	}
	if evidence.Principal.Project != "" {
		attrs["project_id"] = evidence.Principal.Project
	}
	return &cerebrov1.EventEnvelope{
		Id:         id,
		TenantId:   "writer",
		SourceId:   cloudidentity.SourceID,
		Kind:       cloudidentity.EventKind,
		Payload:    payload,
		Attributes: attrs,
		OccurredAt: timestamppb.New(evidence.CollectedAt),
	}
}
