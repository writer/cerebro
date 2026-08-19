package sourcehealth

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestAuthorityEvidenceStreamIsAppendOnlyAndAuditable(t *testing.T) {
	stream := NewAuthorityEvidenceStream()
	first, err := stream.Append(authorityEvidenceFixture("decision-promote", 1, AuthorityDecisionPromote))
	if err != nil {
		t.Fatalf("append promotion evidence: %v", err)
	}
	second, err := stream.Append(AuthorityEvidenceRecord{
		TenantID:                  "tenant-a",
		SourceID:                  "custom_deposit",
		FamilyID:                  "assets",
		AuthorityEpoch:            2,
		DecisionID:                "decision-rollback",
		DecisionKind:              AuthorityDecisionRollback,
		InputEvidenceDigestSHA256: strings.Repeat("b", 64),
		ActorID:                   "system:cutover",
		Timestamp:                 time.Date(2026, 8, 19, 12, 5, 0, 0, time.UTC),
		ReasonCode:                "rollback_requested",
		PreviousDecisionID:        first.DecisionID,
	})
	if err != nil {
		t.Fatalf("append rollback evidence: %v", err)
	}
	if first.RecordDigestSHA256 == "" || second.RecordDigestSHA256 == "" || first.RecordDigestSHA256 == second.RecordDigestSHA256 {
		t.Fatalf("record digests are not distinct: %#v %#v", first, second)
	}
	history := stream.History("tenant-a", "custom_deposit", "assets")
	if len(history) != 2 || history[0].DecisionID != "decision-promote" || history[1].DecisionID != "decision-rollback" {
		t.Fatalf("history = %#v, want ordered family decisions", history)
	}
	if _, err := stream.Append(authorityEvidenceFixture("decision-promote", 3, AuthorityDecisionPromote)); !errors.Is(err, ErrAuthorityEvidenceImmutable) {
		t.Fatalf("duplicate decision append error = %v, want immutable", err)
	}
	mutated := first
	mutated.ReasonCode = "changed"
	if err := stream.Mutate(first.DecisionID, mutated); !errors.Is(err, ErrAuthorityEvidenceImmutable) {
		t.Fatalf("mutate evidence error = %v, want immutable", err)
	}
	if ref := AuthorityEvidenceReceiptRef(first); ref != "authority-evidence:decision-promote:1" {
		t.Fatalf("receipt ref = %q", ref)
	}
}

func TestAuthorityEvidenceRejectsMalformedDigestAndUnsignedPromotion(t *testing.T) {
	malformed := authorityEvidenceFixture("decision-bad-digest", 1, AuthorityDecisionPromote)
	malformed.InputEvidenceDigestSHA256 = "not-a-sha"
	if err := ValidateAuthorityEvidenceRecord(malformed); !errors.Is(err, ErrAuthorityEvidenceInvalid) {
		t.Fatalf("malformed digest error = %v, want invalid", err)
	}
	unsigned := authorityEvidenceFixture("decision-unsigned", 1, AuthorityDecisionPromote)
	unsigned.AuthenticatedReceiptID = ""
	unsigned.ReceiptSignature = ""
	if err := ValidateAuthorityEvidenceRecord(unsigned); !errors.Is(err, ErrAuthorityEvidenceInvalid) || !strings.Contains(err.Error(), "signed or authenticated") {
		t.Fatalf("unsigned promotion error = %v, want signed/authenticated rejection", err)
	}
	blocked := unsigned
	blocked.DecisionKind = AuthorityDecisionShadowOnlyBlocked
	blocked.ReasonCode = "missing_provider_proof"
	if err := ValidateAuthorityEvidenceRecord(blocked); err != nil {
		t.Fatalf("shadow-only block evidence should not require promotion signature: %v", err)
	}
}

func authorityEvidenceFixture(decisionID string, epoch uint64, kind AuthorityDecisionKind) AuthorityEvidenceRecord {
	return AuthorityEvidenceRecord{
		TenantID:                  "tenant-a",
		SourceID:                  "custom_deposit",
		FamilyID:                  "assets",
		AuthorityEpoch:            epoch,
		DecisionID:                decisionID,
		DecisionKind:              kind,
		InputEvidenceDigestSHA256: strings.Repeat("a", 64),
		ActorID:                   "system:cutover",
		Timestamp:                 time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC),
		ReasonCode:                "provider_proof_complete",
		AuthenticatedReceiptID:    "receipt:promotion",
	}
}
