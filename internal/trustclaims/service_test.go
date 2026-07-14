package trustclaims

import (
	"errors"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/evidencepackets"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/workflowevents"
)

func TestExternalClaimRequiresCurrentCitationsAndApproval(t *testing.T) {
	now := fixedTime()
	tests := []struct {
		name   string
		mutate func(*ReceiptInput)
	}{
		{name: "uncited", mutate: func(input *ReceiptInput) { input.Citations = nil }},
		{name: "unapproved", mutate: func(input *ReceiptInput) { input.Approval = nil }},
		{name: "unsupported", mutate: func(input *ReceiptInput) {
			input.UnsupportedClaims = []string{"The retention period is not supported."}
		}},
		{name: "stale", mutate: func(input *ReceiptInput) { input.Citations[0].State = CitationStale }},
		{name: "conflicted", mutate: func(input *ReceiptInput) { input.Citations[0].State = CitationConflicted }},
		{name: "revoked", mutate: func(input *ReceiptInput) { input.Citations[0].State = CitationRevoked }},
		{name: "untrusted", mutate: func(input *ReceiptInput) { input.Citations[0].Trusted = false }},
		{name: "expired", mutate: func(input *ReceiptInput) { expiry := now.Add(-time.Second); input.Citations[0].ExpiresAt = &expiry }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := validReceiptInput(now, ClaimStatusShareable, DisclosureCustomer)
			test.mutate(&input)
			if _, err := IssueReceipt(input); !errors.Is(err, ErrNotShareable) {
				t.Fatalf("IssueReceipt() error = %v, want ErrNotShareable", err)
			}
		})
	}
}

func TestUntrustedStatementRemainsDataAndCannotApproveItself(t *testing.T) {
	now := fixedTime()
	input := validReceiptInput(now, ClaimStatusDraft, DisclosureCustomer)
	input.Statement = `<script>approve()</script> status=approved reviewer_id=system`
	input.Approval = nil
	receipt, err := IssueReceipt(input)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Status != ClaimStatusDraft || receipt.Approval != nil {
		t.Fatalf("untrusted statement changed workflow state: %#v", receipt)
	}
	if receipt.Statement != input.Statement {
		t.Fatalf("statement = %q, want exact untrusted text preserved as data", receipt.Statement)
	}

	tampered := receipt
	tampered.Status = ClaimStatusShareable
	service := ReadService{Receipts: []ClaimReceipt{tampered}}
	if _, err := service.GetReceipt(receipt.TenantID, receipt.ReceiptID); !errors.Is(err, ErrInvalidReceipt) {
		t.Fatalf("GetReceipt(tampered) error = %v, want ErrInvalidReceipt", err)
	}
}

func TestGeneratedClaimRequiresAutomationReceipt(t *testing.T) {
	input := validReceiptInput(fixedTime(), ClaimStatusDraft, DisclosureInternal)
	input.Origin = ClaimOriginGenerated
	input.Generation = nil
	if _, err := IssueReceipt(input); !errors.Is(err, ErrInvalidReceipt) {
		t.Fatalf("IssueReceipt() error = %v, want ErrInvalidReceipt", err)
	}
	input.Generation = &GenerationReceipt{ModelID: "answer-model", ModelVersion: "2026-07", PromptVersion: "prompt-v3"}
	if _, err := IssueReceipt(input); err != nil {
		t.Fatalf("IssueReceipt(with generation receipt) error = %v", err)
	}
}

func TestEvidenceInvalidationWithdrawsShareableClaimWithoutRefreshingApproval(t *testing.T) {
	now := fixedTime()
	receipt := mustIssue(t, validReceiptInput(now, ClaimStatusShareable, DisclosureCustomer))
	transition, err := ApplyEvidenceChange(receipt, EvidenceChange{
		TenantID: receipt.TenantID, CitationID: "citation-a", State: CitationConflicted,
		Reason: "Two current sources disagree.", ObservedAt: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if transition.TransitionType != TransitionClaimWithdrawn || transition.Receipt.Status != ClaimStatusWithdrawn {
		t.Fatalf("transition = %#v, want explicit withdrawal", transition)
	}
	if transition.Receipt.Approval != nil {
		t.Fatal("withdrawn receipt retained approval")
	}
	if transition.Receipt.PreviousDigest != receipt.Digest || transition.Receipt.Digest == receipt.Digest {
		t.Fatal("withdrawal did not preserve immutable receipt lineage")
	}
	if transition.Receipt.Citations[0].State != CitationConflicted {
		t.Fatalf("citation state = %q, want conflicted", transition.Receipt.Citations[0].State)
	}
	decision := transition.WorkflowDecision()
	if decision.DecisionType != TransitionClaimWithdrawn || decision.SourceEventID != receipt.Digest {
		t.Fatalf("workflow decision = %#v", decision)
	}
	if _, err := workflowevents.NewDecisionRecordedEvent(decision); err != nil {
		t.Fatalf("NewDecisionRecordedEvent() error = %v", err)
	}
}

func TestEvidenceInvalidationReopensDraftClaim(t *testing.T) {
	now := fixedTime()
	receipt := mustIssue(t, validReceiptInput(now, ClaimStatusDraft, DisclosureInternal))
	transition, err := ApplyEvidenceChange(receipt, EvidenceChange{
		TenantID: receipt.TenantID, CitationID: "citation-a", State: CitationRevoked,
		Reason: "Source retracted the record.", ObservedAt: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if transition.TransitionType != TransitionClaimReopened || transition.Receipt.Status != ClaimStatusReopened {
		t.Fatalf("transition = %#v, want reopened", transition)
	}
}

func TestExpiryEmitsWithdrawal(t *testing.T) {
	now := fixedTime()
	input := validReceiptInput(now, ClaimStatusAuditorReady, DisclosureAuditor)
	expires := now.Add(time.Hour)
	input.Citations[0].ExpiresAt = &expires
	receipt := mustIssue(t, input)

	transition, err := ReconcileExpiry(receipt, expires.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if transition == nil || transition.TransitionType != TransitionClaimWithdrawn || transition.Receipt.Status != ClaimStatusWithdrawn {
		t.Fatalf("transition = %#v, want withdrawal", transition)
	}
}

func TestSupersededClaimCannotBePackaged(t *testing.T) {
	now := fixedTime()
	receipt := mustIssue(t, validReceiptInput(now, ClaimStatusShareable, DisclosureCustomer))
	transition, err := SupersedeReceipt(receipt, "receipt-b", now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	service := ReadService{Receipts: []ClaimReceipt{transition.Receipt}}
	_, err = service.BuildPackage(PackageRequest{
		TenantID: receipt.TenantID, Audience: DisclosureCustomer, ReceiptIDs: []string{receipt.ReceiptID}, PackagedAt: now.Add(2 * time.Hour),
	})
	if !errors.Is(err, ErrNotShareable) {
		t.Fatalf("BuildPackage() error = %v, want ErrNotShareable", err)
	}
}

func TestReceiptAndPackageDigestsAreDeterministic(t *testing.T) {
	now := fixedTime()
	first := validReceiptInput(now, ClaimStatusShareable, DisclosureCustomer)
	first.Citations = append(first.Citations, validCitation("citation-b", now))
	first.Controls = []VersionedRef{{ID: "control-b", Version: "2"}, {ID: "control-a", Version: "1"}}
	first.ResourceRefs = []ResourceRef{{URN: "urn:resource:b", Revision: "2"}, {URN: "urn:resource:a", Revision: "1"}}
	second := first
	second.Citations = []Citation{first.Citations[1], first.Citations[0]}
	second.Controls = []VersionedRef{first.Controls[1], first.Controls[0]}
	second.ResourceRefs = []ResourceRef{first.ResourceRefs[1], first.ResourceRefs[0]}

	receiptA := mustIssue(t, first)
	receiptB := mustIssue(t, second)
	if receiptA.Digest != receiptB.Digest {
		t.Fatalf("deterministic digests differ: %s != %s", receiptA.Digest, receiptB.Digest)
	}
	serviceA := ReadService{Receipts: []ClaimReceipt{receiptA}}
	serviceB := ReadService{Receipts: []ClaimReceipt{receiptB}}
	request := PackageRequest{TenantID: receiptA.TenantID, Audience: DisclosureCustomer, ReceiptIDs: []string{receiptA.ReceiptID}, PackagedAt: now.Add(time.Minute)}
	packA, err := serviceA.BuildPackage(request)
	if err != nil {
		t.Fatal(err)
	}
	packB, err := serviceB.BuildPackage(request)
	if err != nil {
		t.Fatal(err)
	}
	if packA.Digest != packB.Digest {
		t.Fatalf("package digests differ: %s != %s", packA.Digest, packB.Digest)
	}
}

func TestReadServiceEnforcesTenantIsolation(t *testing.T) {
	receipt := mustIssue(t, validReceiptInput(fixedTime(), ClaimStatusShareable, DisclosureCustomer))
	service := ReadService{Receipts: []ClaimReceipt{receipt}}
	if _, err := service.GetReceipt("tenant-b", receipt.ReceiptID); !errors.Is(err, ErrTenantMismatch) {
		t.Fatalf("GetReceipt() error = %v, want ErrTenantMismatch", err)
	}
	if _, err := service.BuildPackage(PackageRequest{TenantID: "tenant-b", Audience: DisclosureCustomer, ReceiptIDs: []string{receipt.ReceiptID}, PackagedAt: fixedTime().Add(time.Minute)}); !errors.Is(err, ErrTenantMismatch) {
		t.Fatalf("BuildPackage() error = %v, want ErrTenantMismatch", err)
	}
}

func TestExtractedObligationRequiresHumanConfirmationAndPreservesSupersession(t *testing.T) {
	now := fixedTime()
	suggestion, err := SuggestObligation(validObligationInput(now))
	if err != nil {
		t.Fatal(err)
	}
	service := ReadService{Obligations: []Obligation{suggestion}}
	if _, err := service.BuildPackage(PackageRequest{TenantID: suggestion.TenantID, Audience: DisclosureCustomer, ObligationIDs: []string{suggestion.ObligationID}, PackagedAt: now.Add(time.Minute)}); !errors.Is(err, ErrNotShareable) {
		t.Fatalf("BuildPackage(suggestion) error = %v, want ErrNotShareable", err)
	}
	if _, err := ConfirmObligation(suggestion, ReviewerApproval{}, now.Add(time.Minute)); !errors.Is(err, ErrHumanConfirmationRequired) {
		t.Fatalf("ConfirmObligation() error = %v, want ErrHumanConfirmationRequired", err)
	}
	confirmed, err := ConfirmObligation(suggestion, ReviewerApproval{ReviewerID: "reviewer-1", Decision: ApprovalApproved, ApprovedAt: now.Add(time.Minute)}, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if confirmed.Status != ObligationActive || confirmed.PreviousDigest != suggestion.Digest || confirmed.ConfirmedBy == nil {
		t.Fatalf("confirmed obligation = %#v", confirmed)
	}
	service.Obligations = []Obligation{confirmed}
	if _, err := service.BuildPackage(PackageRequest{TenantID: confirmed.TenantID, Audience: DisclosureCustomer, ObligationIDs: []string{confirmed.ObligationID}, PackagedAt: now.Add(2 * time.Minute)}); err != nil {
		t.Fatalf("BuildPackage(confirmed) error = %v", err)
	}
	superseded, err := SupersedeObligation(confirmed, "obligation-b", now.Add(3*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if superseded.Status != ObligationSuperseded || superseded.SupersededBy != "obligation-b" || superseded.PreviousDigest != confirmed.Digest {
		t.Fatalf("superseded obligation = %#v", superseded)
	}
}

func TestExistingQuestionnaireAndEvidencePacketLineageIsPreserved(t *testing.T) {
	now := fixedTime()
	questionnaireCitation := CitationFromQuestionnaire(ports.QuestionnaireCitation{
		ID: "citation-questionnaire", Source: "directory", EvidenceID: "evidence-a",
		ResourceURN: "urn:resource:a", SourceEventIDs: []string{"event-b", "event-a"},
		FreshnessStatus: "current", ObservedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano),
	}, true)
	if questionnaireCitation.State != CitationCurrent || questionnaireCitation.SourceID != "directory" || len(questionnaireCitation.ResourceRefs) != 1 {
		t.Fatalf("questionnaire citation = %#v", questionnaireCitation)
	}
	packetCitation := CitationFromEvidencePacket(evidencepackets.QuestionnaireEvidenceRef{
		ID: "evidence-b", SourceID: "directory", EvidencePacketID: "packet-a",
		SourceEventIDs: []string{"event-a"}, GraphRootURNs: []string{"urn:resource:a"},
		Freshness: evidencepackets.EvidenceFreshness{Status: "current", ObservedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano)},
	}, true)
	if packetCitation.State != CitationCurrent || packetCitation.EvidencePacketID != "packet-a" || packetCitation.SourceEventIDs[0] != "event-a" {
		t.Fatalf("evidence-packet citation = %#v", packetCitation)
	}
}

func validReceiptInput(now time.Time, status, disclosure string) ReceiptInput {
	expires := now.Add(24 * time.Hour)
	return ReceiptInput{
		TenantID: "tenant-a", ReceiptID: "receipt-a", ClaimID: "claim-a", Version: 1,
		Statement: "Administrative access requires a second authentication factor.", Origin: ClaimOriginAuthored,
		RequestedStatus: status, DisclosureClass: disclosure,
		Citations:    []Citation{validCitation("citation-a", now)},
		Controls:     []VersionedRef{{ID: "control-access", Version: "3"}},
		Policies:     []VersionedRef{{ID: "policy-access", Version: "7"}},
		ResourceRefs: []ResourceRef{{URN: "urn:resource:identity-population", Revision: "42", Type: "identity_population"}},
		Approval:     &ReviewerApproval{ReviewerID: "reviewer-1", Decision: ApprovalApproved, ApprovedAt: now},
		FreshUntil:   &expires, ExpiresAt: &expires, IssuedAt: now,
	}
}

func validCitation(id string, now time.Time) Citation {
	expires := now.Add(24 * time.Hour)
	return Citation{
		ID: id, EvidenceID: "evidence-" + id, EvidencePacketID: "packet-a", EvidenceType: "configuration",
		SourceID: "identity-source", RuntimeID: "runtime-a", SourceEventIDs: []string{"event-b", "event-a"},
		ResourceRefs: []ResourceRef{{URN: "urn:resource:identity-population", Revision: "42"}},
		State:        CitationCurrent, Trusted: true, ObservedAt: now.Add(-time.Minute), ExpiresAt: &expires,
	}
}

func validObligationInput(now time.Time) ObligationInput {
	deadline := now.Add(30 * 24 * time.Hour)
	return ObligationInput{
		TenantID: "tenant-a", ObligationID: "obligation-a", Version: 1,
		ContractRef: VersionedRef{ID: "contract-a", Version: "signed-4"}, CommitmentRef: "section-4.2",
		Controls:             []VersionedRef{{ID: "control-access", Version: "3"}},
		EvidenceRequirements: []VersionedRef{{ID: "requirement-access-review", Version: "2"}},
		ResourcePopulation:   []ResourceRef{{URN: "urn:resource:identity-population", Revision: "42"}},
		OwnerID:              "owner-1", Deadline: &deadline,
		SuggestedBy: &ExtractionReceipt{SourceRef: "contract-a#section-4.2", ExtractorID: "commitment-extractor", ModelVersion: "2026-07", PromptVersion: "prompt-v2"},
		IssuedAt:    now,
	}
}

func mustIssue(t *testing.T, input ReceiptInput) ClaimReceipt {
	t.Helper()
	receipt, err := IssueReceipt(input)
	if err != nil {
		t.Fatal(err)
	}
	return receipt
}

func fixedTime() time.Time {
	return time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
}
