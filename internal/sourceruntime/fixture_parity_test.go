package sourceruntime

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRustFixtureParityGoOracleArtifactMatchesCurrentOracle(t *testing.T) {
	matrix, err := BuildGoFixtureOracleMatrix("../..")
	if err != nil {
		t.Fatalf("BuildGoFixtureOracleMatrix() error = %v", err)
	}
	if matrix.CorpusRevision == "" {
		t.Fatal("fixture corpus revision is empty")
	}
	if len(matrix.Cases) == 0 {
		t.Fatal("fixture Go oracle matrix is empty")
	}
	for _, oracle := range matrix.Cases {
		if oracle.ProviderNetworkEgress {
			t.Fatalf("%s/%s/%s/%s oracle used provider network egress", oracle.SourceID, oracle.FamilyID, oracle.CaseID, oracle.Operation)
		}
		if oracle.GoPageDigestSHA256 == "" || oracle.OracleDigestSHA256 == "" {
			t.Fatalf("%s/%s/%s/%s oracle has empty digest fields: %#v", oracle.SourceID, oracle.FamilyID, oracle.CaseID, oracle.Operation, oracle)
		}
	}

	artifactPath := filepath.Join("..", "..", "crates", "source-runtime-next", "testdata", "go_fixture_oracle.json")
	// #nosec G304 -- fixed repository-relative artifact path assembled from constants.
	payload, err := os.ReadFile(artifactPath)
	if err != nil {
		t.Fatalf("read Go fixture oracle artifact: %v", err)
	}
	var artifact FixtureGoOracleMatrix
	if err := json.Unmarshal(payload, &artifact); err != nil {
		t.Fatalf("decode Go fixture oracle artifact: %v", err)
	}
	current, err := json.MarshalIndent(matrix, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	current = append(current, '\n')
	if string(payload) != string(current) {
		t.Fatalf("Go fixture oracle artifact drifted; regenerate %s from BuildGoFixtureOracleMatrix", artifactPath)
	}

	operationsByFixture := map[string]map[FixtureParityOperation]bool{}
	for _, oracle := range artifact.Cases {
		key := oracle.SourceID + "/" + oracle.FamilyID + "/" + oracle.CaseID
		if operationsByFixture[key] == nil {
			operationsByFixture[key] = map[FixtureParityOperation]bool{}
		}
		operationsByFixture[key][oracle.Operation] = true
	}
	for fixture, operations := range operationsByFixture {
		for _, operation := range []FixtureParityOperation{FixtureParityCheck, FixtureParityDiscover, FixtureParityReadPage} {
			if !operations[operation] {
				t.Fatalf("%s missing operation %s from Go oracle artifact", fixture, operation)
			}
		}
	}
	t.Logf("fixture Go oracle corpus_revision=%s cases=%d first_oracle=%#v",
		matrix.CorpusRevision, len(matrix.Cases), matrix.Cases[0])
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
			page, err := ExecuteGoFixtureOraclePage(test.input)
			if err != nil {
				t.Fatalf("ExecuteGoFixtureOraclePage() error = %v", err)
			}
			joined := strings.Join(append(page.ShortCircuitReasons, page.ReconciliationReasons...), ",")
			for _, want := range test.want {
				if !strings.Contains(joined, want) {
					t.Fatalf("reasons %q do not contain %q", joined, want)
				}
			}
			if test.wantZero && page.AcceptedCount != 0 {
				t.Fatalf("accepted count = %d, want 0", page.AcceptedCount)
			}
		})
	}

	notModified := base
	first, err := ExecuteGoFixtureOraclePage(base)
	if err != nil {
		t.Fatal(err)
	}
	notModified.Checkpoint = first.ProposedCheckpoint
	second, err := ExecuteGoFixtureOraclePage(notModified)
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
		page, err := ExecuteGoFixtureOraclePage(input)
		if err != nil {
			t.Fatalf("%s ExecuteGoFixtureOraclePage() error = %v", input.Operation, err)
		}
		if page.Operation != input.Operation {
			t.Fatalf("%s page operation = %s", input.Operation, page.Operation)
		}
	}
}

func TestFixtureProofDigestEncodingMatchesRustVector(t *testing.T) {
	got := digestFixtureRecord(map[string]any{"id": "user-1", "name": "Ada"})
	const want = "E4911FD30E7D4F0E4BA68D619B6F6FC12C25652AE38AFEEB8ED5F68D5CC2B598"
	if got != want {
		t.Fatalf("digestFixtureRecord() = %q, want shared Go/Rust vector %q", got, want)
	}
	if got != strings.ToUpper(got) {
		t.Fatalf("fixture proof digest is not uppercase: %q", got)
	}
}

func TestFixtureParityReceiptRequiresCrossLanguageComparison(t *testing.T) {
	input := FixtureParityInput{
		SourceID: "fixture", FamilyID: "identity_user", CaseID: "page",
		Operation: FixtureParityReadPage, Payload: []byte(`{"items":[{"id":"u1"}]}`), Limit: 10,
	}
	goPage, err := ExecuteGoFixtureOraclePage(input)
	if err != nil {
		t.Fatal(err)
	}
	rustPage := goPage
	rustPage.AcceptedCount++
	comparison, err := CompareFixtureParityAgainstRustPage(input, "test-corpus", goPage, rustPage)
	if err != nil {
		t.Fatal(err)
	}
	if comparison.Receipt.MismatchCount == 0 {
		t.Fatalf("mismatch_count = 0 for divergent Go/Rust pages: %#v", comparison.Receipt)
	}
	if comparison.Receipt.GoPageDigestSHA256 == comparison.Receipt.RustPageDigestSHA256 {
		t.Fatalf("Go/Rust page digests unexpectedly match: %#v", comparison.Receipt)
	}
	if comparison.Receipt.ReceiptDigestSHA256 == "" {
		t.Fatalf("receipt digest is empty: %#v", comparison.Receipt)
	}
}

func TestFixtureParityInputsCoverEveryOperationPerManifestCase(t *testing.T) {
	inputs, err := BuildFixtureParityInputs("../..")
	if err != nil {
		t.Fatal(err)
	}
	operationsByFixture := map[string]map[FixtureParityOperation]bool{}
	for _, input := range inputs {
		key := input.SourceID + "/" + input.FamilyID + "/" + input.CaseID
		if operationsByFixture[key] == nil {
			operationsByFixture[key] = map[FixtureParityOperation]bool{}
		}
		operationsByFixture[key][input.Operation] = true
	}
	if len(operationsByFixture) == 0 {
		t.Fatal("no fixture manifest cases found")
	}
	for fixture, operations := range operationsByFixture {
		for _, operation := range []FixtureParityOperation{FixtureParityCheck, FixtureParityDiscover, FixtureParityReadPage} {
			if !operations[operation] {
				t.Fatalf("%s missing operation %s", fixture, operation)
			}
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
