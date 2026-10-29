package findings

import (
	"context"
	"strings"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/cloudidentity"
)

func TestCloudIdentitySharedPrincipalRuleSupportedForDistinctServices(t *testing.T) {
	baseTime := time.Date(2026, time.March, 4, 9, 0, 0, 0, time.UTC)
	evidence := cloudIdentitySharedDistinctServicesEvidence(baseTime)
	sharing := cloudidentity.AssessSharing(evidence)
	if sharing.Status != cloudidentity.Supported {
		t.Fatalf("fixture sharing.Status = %q, want %q; keep this fixture in sync with cloudidentity.AssessSharing", sharing.Status, cloudidentity.Supported)
	}

	rule := newCloudIdentitySharedPrincipalRuleWithClock(func() time.Time { return baseTime })
	runtime := &cerebrov1.SourceRuntime{Id: "writer-cloud-identity", SourceId: cloudidentity.SourceID, TenantId: "writer"}
	event := cloudIdentityEvidenceEvent(t, "event-shared-1", evidence)

	records, err := rule.Evaluate(context.Background(), runtime, event)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("Evaluate() returned %d records, want 1", len(records))
	}
	finding := records[0]
	if finding.RuleID != cloudIdentitySharedPrincipalRuleID {
		t.Fatalf("RuleID = %q, want %q", finding.RuleID, cloudIdentitySharedPrincipalRuleID)
	}
	if !strings.Contains(finding.Attributes["shared_services"], "payments-processor") || !strings.Contains(finding.Attributes["shared_services"], "notifications-worker") {
		t.Fatalf("shared_services = %q, want both payments-processor and notifications-worker", finding.Attributes["shared_services"])
	}
	wantPrincipalURN := cloudIdentityPrincipalScopeURN("writer", evidence.Principal.Provider, evidence.Principal.ID, evidence.Scope)
	if !containsTrimmed(finding.ResourceURNs, wantPrincipalURN) {
		t.Fatalf("ResourceURNs = %#v, want principal URN %q", finding.ResourceURNs, wantPrincipalURN)
	}
	wantAssessmentDigest, err := cloudIdentityDigest(sharing)
	if err != nil {
		t.Fatalf("cloudIdentityDigest(sharing) error = %v", err)
	}
	if got := finding.Attributes["cloud_identity_assessment_digest"]; got != wantAssessmentDigest {
		t.Fatalf("Attributes[cloud_identity_assessment_digest] = %q, want %q (actual machine sharing output digest, not an ID string)", got, wantAssessmentDigest)
	}
	if finding.Severity == "" {
		t.Fatal("Severity must not be empty")
	}
}

func TestCloudIdentitySharedPrincipalRuleClearForServiceReplicas(t *testing.T) {
	baseTime := time.Date(2026, time.March, 4, 9, 0, 0, 0, time.UTC)
	evidence := cloudIdentitySharedReplicaServicesEvidence(baseTime)
	sharing := cloudidentity.AssessSharing(evidence)
	if sharing.Status == cloudidentity.Supported {
		t.Fatalf("fixture sharing.Status = %q, want non-Supported: replicas of the same logical service are not a sharing violation", sharing.Status)
	}

	rule := newCloudIdentitySharedPrincipalRuleWithClock(func() time.Time { return baseTime })
	runtime := &cerebrov1.SourceRuntime{Id: "writer-cloud-identity", SourceId: cloudidentity.SourceID, TenantId: "writer"}
	event := cloudIdentityEvidenceEvent(t, "event-replica-1", evidence)

	records, err := rule.Evaluate(context.Background(), runtime, event)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("Evaluate() returned %d records for replica consumers, want 0", len(records))
	}
}

func TestCloudIdentitySharedPrincipalRuleCloseOnClear(t *testing.T) {
	baseTime := time.Date(2026, time.March, 4, 9, 0, 0, 0, time.UTC)
	rule := newCloudIdentitySharedPrincipalRuleWithClock(func() time.Time { return baseTime })
	counterRule, ok := durableStateCounterEventRule(rule)
	if !ok {
		t.Fatal("cloud-identity-shared-principal does not implement durable CounterEventRule")
	}

	replica := cloudIdentitySharedReplicaServicesEvidence(baseTime)
	sharing := cloudidentity.AssessSharing(replica)
	if sharing.Status != cloudidentity.Clear {
		t.Fatalf("fixture sharing.Status = %q, want %q; keep this fixture in sync with cloudidentity.AssessSharing", sharing.Status, cloudidentity.Clear)
	}
	event := cloudIdentityEvidenceEvent(t, "event-close-shared-1", replica)
	anchor, closes := counterRule.CloseOnEvent(event)
	if !closes || anchor == "" {
		t.Fatalf("CloseOnEvent(clear sharing) = %q/%v, want non-empty/true", anchor, closes)
	}
}

// TestCloudIdentitySharedPrincipalRuleStaleEvidenceNeitherOpensNorCloses pins
// VAL item 5 for sharing: AssessSharing itself has no freshness input, so the
// rule gates on the injected trusted clock directly; evidence collected 72h
// before the evaluation clock must neither open nor close a sharing finding.
func TestCloudIdentitySharedPrincipalRuleStaleEvidenceNeitherOpensNorCloses(t *testing.T) {
	evalTime := time.Date(2026, time.March, 10, 9, 0, 0, 0, time.UTC)
	staleCollectedAt := evalTime.Add(-72 * time.Hour)

	rule := newCloudIdentitySharedPrincipalRuleWithClock(func() time.Time { return evalTime })
	runtime := &cerebrov1.SourceRuntime{Id: "writer-cloud-identity", SourceId: cloudidentity.SourceID, TenantId: "writer"}

	staleShared := cloudIdentitySharedDistinctServicesEvidence(staleCollectedAt)
	openEvent := cloudIdentityEvidenceEvent(t, "event-stale-shared-open-1", staleShared)
	records, err := rule.Evaluate(context.Background(), runtime, openEvent)
	if err != nil {
		t.Fatalf("Evaluate(stale sharing) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("Evaluate(stale sharing) returned %d records, want 0 (stale evidence must not open a finding)", len(records))
	}

	counterRule, ok := durableStateCounterEventRule(rule)
	if !ok {
		t.Fatal("cloud-identity-shared-principal does not implement durable CounterEventRule")
	}
	staleClear := cloudIdentitySharedReplicaServicesEvidence(staleCollectedAt)
	closeEvent := cloudIdentityEvidenceEvent(t, "event-stale-shared-close-1", staleClear)
	if anchor, closes := counterRule.CloseOnEvent(closeEvent); closes || anchor != "" {
		t.Fatalf("CloseOnEvent(stale clear sharing) = %q/%v, want empty/false (stale evidence must not close a finding)", anchor, closes)
	}
}

// TestCloudIdentitySharedPrincipalRuleFutureEvidenceNeitherOpensNorCloses
// covers the symmetric future-dated case from VAL item 5 for sharing.
func TestCloudIdentitySharedPrincipalRuleFutureEvidenceNeitherOpensNorCloses(t *testing.T) {
	evalTime := time.Date(2026, time.March, 10, 9, 0, 0, 0, time.UTC)
	futureCollectedAt := evalTime.Add(72 * time.Hour)

	rule := newCloudIdentitySharedPrincipalRuleWithClock(func() time.Time { return evalTime })
	runtime := &cerebrov1.SourceRuntime{Id: "writer-cloud-identity", SourceId: cloudidentity.SourceID, TenantId: "writer"}

	futureShared := cloudIdentitySharedDistinctServicesEvidence(futureCollectedAt)
	openEvent := cloudIdentityEvidenceEvent(t, "event-future-shared-open-1", futureShared)
	records, err := rule.Evaluate(context.Background(), runtime, openEvent)
	if err != nil {
		t.Fatalf("Evaluate(future sharing) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("Evaluate(future sharing) returned %d records, want 0 (future-dated evidence must not open a finding)", len(records))
	}
}

// TestCloudIdentitySharedPrincipalRuleFreshEvidenceStillOpensAndCloses is the
// control case for VAL item 5: evidence within the freshness window still
// opens a Supported sharing finding and closes it on a later Clear cohort.
func TestCloudIdentitySharedPrincipalRuleFreshEvidenceStillOpensAndCloses(t *testing.T) {
	evalTime := time.Date(2026, time.March, 10, 9, 0, 0, 0, time.UTC)
	freshCollectedAt := evalTime.Add(-1 * time.Hour)

	rule := newCloudIdentitySharedPrincipalRuleWithClock(func() time.Time { return evalTime })
	runtime := &cerebrov1.SourceRuntime{Id: "writer-cloud-identity", SourceId: cloudidentity.SourceID, TenantId: "writer"}

	freshShared := cloudIdentitySharedDistinctServicesEvidence(freshCollectedAt)
	openEvent := cloudIdentityEvidenceEvent(t, "event-fresh-shared-open-1", freshShared)
	records, err := rule.Evaluate(context.Background(), runtime, openEvent)
	if err != nil {
		t.Fatalf("Evaluate(fresh sharing) error = %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("Evaluate(fresh sharing) returned %d records, want 1", len(records))
	}

	counterRule, ok := durableStateCounterEventRule(rule)
	if !ok {
		t.Fatal("cloud-identity-shared-principal does not implement durable CounterEventRule")
	}
	freshClear := cloudIdentitySharedReplicaServicesEvidence(freshCollectedAt)
	closeEvent := cloudIdentityEvidenceEvent(t, "event-fresh-shared-close-1", freshClear)
	if anchor, closes := counterRule.CloseOnEvent(closeEvent); !closes || anchor == "" {
		t.Fatalf("CloseOnEvent(fresh clear sharing) = %q/%v, want non-empty/true", anchor, closes)
	}
}

func TestCloudIdentitySharedPrincipalRuleDistinctFingerprintFromExcessRule(t *testing.T) {
	baseTime := time.Date(2026, time.March, 4, 9, 0, 0, 0, time.UTC)
	evidence := cloudIdentityAWSExcessEvidence(baseTime)
	principalURN := cloudIdentityPrincipalScopeURN("writer", evidence.Principal.Provider, evidence.Principal.ID, evidence.Scope)
	excessFingerprint := hashFindingFingerprint(cloudIdentityExcessPrivilegeRuleID, principalURN)
	sharingFingerprint := hashFindingFingerprint(cloudIdentitySharedPrincipalRuleID, principalURN)
	if excessFingerprint == "" || sharingFingerprint == "" {
		t.Fatal("fingerprints must not be empty")
	}
	if excessFingerprint == sharingFingerprint {
		t.Fatal("excess-privilege and shared-principal findings for the same principal+scope anchor must use distinct fingerprints")
	}
}

// --- fixtures ---

func cloudIdentitySharedDistinctServicesEvidence(baseTime time.Time) cloudidentity.Evidence {
	evidence := cloudIdentityAWSExcessEvidence(baseTime)
	// Trim to a clean, no-excess policy so this fixture isolates the sharing
	// condition from the excess-privilege condition.
	evidence.Declared.Grants[0].Actions = []string{"s3:GetObject"}
	evidence.Observed.Grants[0].Actions = []string{"s3:GetObject"}

	secondConsumer := cloudidentity.Workload{
		ID:             "notifications/notifications-worker",
		Service:        "notifications-worker",
		Environment:    "prod",
		Cluster:        "prod-use1",
		Namespace:      "notifications",
		Name:           "notifications-worker",
		Kind:           "Deployment",
		ServiceAccount: "notifications-worker",
		Image:          "111111111111.dkr.ecr.us-east-1.amazonaws.com/notifications-worker:4.5.6",
		Source: cloudidentity.SourcePin{
			Repository: "example-org/notifications-worker",
			Revision:   "e5f6a7b8",
			Exact:      true,
		},
		Principals: []cloudidentity.Principal{evidence.Principal},
	}
	evidence.Consumers = append(evidence.Consumers, secondConsumer)
	evidence.Investigations = append(evidence.Investigations, cloudidentity.Investigation{
		ConsumerID: secondConsumer.ID,
		Source:     secondConsumer.Source,
		Requirements: []cloudidentity.Requirement{{
			Provider:    cloudidentity.AWS,
			Service:     "s3",
			Operation:   "GetObject",
			Action:      "s3:GetObject",
			Resources:   []string{"arn:aws:s3:::payments-bucket/*"},
			ConsumerIDs: []string{secondConsumer.ID},
			References: []cloudidentity.Reference{{
				Repository: secondConsumer.Source.Repository,
				Revision:   secondConsumer.Source.Revision,
				Path:       "internal/storage/client.go",
				StartLine:  12,
				EndLine:    16,
				Digest:     "sha256:notifdigest",
			}},
		}},
		Validation: cloudidentity.Validation{
			Analyzer:           "go-ast",
			SourceDigest:       "sha256:notifdigest",
			CitationsVerified:  true,
			OperationsVerified: true,
			ScopeComplete:      true,
			CoveredFiles:       []string{"internal/storage/client.go"},
		},
	})
	// Both consumers must be positively linked by observed (live) trust for
	// AssessSharing to count them. The first service assumes the role through
	// the base fixture's IRSA statement; the second through EKS Pod Identity,
	// which needs both the live association evidence (ResolvedIdentifiers
	// aws_pod_identity_role:<KSA subject> == this principal) and a trust
	// statement letting pods.eks.amazonaws.com mint credentials, restricted by
	// session tags to exactly that workload.
	if evidence.ResolvedIdentifiers == nil {
		evidence.ResolvedIdentifiers = map[string]string{}
	}
	for _, c := range evidence.Consumers {
		subject := "k8s://" + c.Cluster + "/" + c.Namespace + "/sa/" + c.ServiceAccount
		evidence.ResolvedIdentifiers["aws_pod_identity_role:"+subject] = evidence.Principal.ID
	}
	podIdentityTrust := cloudidentity.Grant{
		ID:      "pod-identity-trust",
		Effect:  "Allow",
		Actions: []string{"sts:AssumeRole", "sts:TagSession"},
		Members: []string{"Service:pods.eks.amazonaws.com"},
		Conditions: []cloudidentity.Condition{
			{Operator: "StringEquals", Key: "aws:RequestTag/eks-cluster-name", Values: []string{secondConsumer.Cluster}},
			{Operator: "StringEquals", Key: "aws:RequestTag/kubernetes-namespace", Values: []string{secondConsumer.Namespace}},
			{Operator: "StringEquals", Key: "aws:RequestTag/kubernetes-service-account", Values: []string{secondConsumer.ServiceAccount}},
		},
	}
	evidence.Observed.Trust = append(append([]cloudidentity.Grant{}, evidence.Observed.Trust...), podIdentityTrust)
	evidence.CollectedAt = baseTime
	return evidence
}

func cloudIdentitySharedReplicaServicesEvidence(baseTime time.Time) cloudidentity.Evidence {
	evidence := cloudIdentitySharedDistinctServicesEvidence(baseTime)
	// Replicas of the same logical service: same Service/Name, different namespace.
	evidence.Consumers[1].Service = evidence.Consumers[0].Service
	evidence.Consumers[1].Name = evidence.Consumers[0].Name
	return evidence
}
