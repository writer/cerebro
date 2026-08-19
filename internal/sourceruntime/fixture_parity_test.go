package sourceruntime

import (
	"strings"
	"testing"
)

func TestRustFixtureParity(t *testing.T) {
	matrix, err := BuildFixtureParityMatrix("../..")
	if err != nil {
		t.Fatalf("BuildFixtureParityMatrix() error = %v", err)
	}
	if matrix.CorpusRevision == "" {
		t.Fatal("fixture corpus revision is empty")
	}
	if len(matrix.Comparisons) == 0 {
		t.Fatal("fixture parity matrix is empty")
	}
	for _, comparison := range matrix.Comparisons {
		if comparison.Receipt.MismatchCount != 0 {
			t.Fatalf("%s/%s/%s mismatch receipt: %#v", comparison.Receipt.SourceID, comparison.Receipt.FamilyID, comparison.Receipt.CaseID, comparison.Receipt)
		}
		if comparison.Receipt.GoPageDigestSHA256 != comparison.Receipt.RustPageDigestSHA256 {
			t.Fatalf("%s/%s/%s Go/Rust page digest mismatch", comparison.Receipt.SourceID, comparison.Receipt.FamilyID, comparison.Receipt.CaseID)
		}
		if comparison.Receipt.CursorDigestSHA256 == "" || comparison.Receipt.CheckpointDigestSHA256 == "" || comparison.Receipt.ReceiptDigestSHA256 == "" {
			t.Fatalf("%s/%s/%s receipt has empty digest fields: %#v", comparison.Receipt.SourceID, comparison.Receipt.FamilyID, comparison.Receipt.CaseID, comparison.Receipt)
		}
	}
	t.Logf("fixture parity matrix corpus_revision=%s cases=%d mismatch_count=%d first_receipt=%#v",
		matrix.CorpusRevision, len(matrix.Comparisons), matrix.MismatchCount, matrix.Comparisons[0].Receipt)
}

func TestRustFixtureParityCoversPageSemantics(t *testing.T) {
	base := FixtureParityInput{
		SourceID:  "fixture",
		FamilyID:  "identity_user",
		CaseID:    "page",
		Operation: FixtureParityReadPage,
		Payload:   []byte(`{"items":[{"id":"u1","name":"Ada"},{"id":"u2","name":"Grace"}]}`),
		Limit:     10,
	}
	for _, test := range []struct {
		name     string
		input    FixtureParityInput
		want     []string
		wantZero bool
	}{
		{
			name:  "first_middle_final",
			input: base,
			want:  []string{"final_page"},
		},
		{
			name: "empty",
			input: FixtureParityInput{
				SourceID: "fixture", FamilyID: "identity_user", CaseID: "empty",
				Operation: FixtureParityReadPage, Payload: []byte(`[]`), Limit: 10,
			},
			want:     []string{"empty_page"},
			wantZero: true,
		},
		{
			name: "malformed_record",
			input: FixtureParityInput{
				SourceID: "fixture", FamilyID: "identity_user", CaseID: "malformed",
				Operation: FixtureParityReadPage, Payload: []byte(`{"items":[`), Limit: 10,
			},
			want:     []string{"malformed_record"},
			wantZero: true,
		},
		{
			name: "permission_denied_rate_limited",
			input: FixtureParityInput{
				SourceID: "fixture", FamilyID: "identity_user", CaseID: "permission_denied",
				Operation: FixtureParityReadPage, Payload: []byte(`{"error":{"status":403,"reason":"permission_denied"}}`), Limit: 10,
			},
			want:     []string{"final_page"},
			wantZero: true,
		},
		{
			name: "duplicate_event",
			input: FixtureParityInput{
				SourceID: "fixture", FamilyID: "identity_user", CaseID: "duplicate",
				Operation: FixtureParityReadPage, Payload: []byte(`{"items":[{"id":"u1"},{"id":"u1"}]}`), Limit: 10,
			},
			want: []string{"duplicate_event", "final_page"},
		},
		{
			name: "event_limit_deferral",
			input: FixtureParityInput{
				SourceID: "fixture", FamilyID: "identity_user", CaseID: "limited",
				Operation: FixtureParityReadPage, Payload: []byte(`{"items":[{"id":"u1"},{"id":"u2"}]}`), Limit: 1,
			},
			want: []string{"event_limit_deferral"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			comparison, err := CompareFixtureParity(test.input, "test-corpus")
			if err != nil {
				t.Fatalf("CompareFixtureParity() error = %v", err)
			}
			if comparison.Receipt.MismatchCount != 0 {
				t.Fatalf("mismatch count = %d", comparison.Receipt.MismatchCount)
			}
			joined := strings.Join(append(comparison.GoPage.ShortCircuitReasons, comparison.GoPage.ReconciliationReasons...), ",")
			for _, want := range test.want {
				if !strings.Contains(joined, want) {
					t.Fatalf("reasons %q do not contain %q", joined, want)
				}
			}
			if test.wantZero && comparison.GoPage.AcceptedCount != 0 {
				t.Fatalf("accepted count = %d, want 0", comparison.GoPage.AcceptedCount)
			}
		})
	}

	notModified := base
	first, err := ExecuteFixtureParityPage(base)
	if err != nil {
		t.Fatal(err)
	}
	notModified.Checkpoint = first.ProposedCheckpoint
	second, err := ExecuteFixtureParityPage(notModified)
	if err != nil {
		t.Fatal(err)
	}
	if !containsString(second.ShortCircuitReasons, "not_modified") || !containsString(second.ReconciliationReasons, "equal_watermark") {
		t.Fatalf("equal watermark/not-modified reasons missing: %#v", second)
	}

	check := base
	check.Operation = FixtureParityCheck
	discover := base
	discover.Operation = FixtureParityDiscover
	for _, input := range []FixtureParityInput{check, discover} {
		comparison, err := CompareFixtureParity(input, "test-corpus")
		if err != nil {
			t.Fatalf("%s CompareFixtureParity() error = %v", input.Operation, err)
		}
		if comparison.Receipt.MismatchCount != 0 {
			t.Fatalf("%s mismatch count = %d", input.Operation, comparison.Receipt.MismatchCount)
		}
	}
}

func containsString(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}
