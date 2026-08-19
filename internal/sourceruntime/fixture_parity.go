package sourceruntime

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/writer/cerebro/internal/sourcefixture"
)

const fixtureParityCorpusVersion = "cerebro.source-fixture-parity.v1"

type FixtureParityOperation string

const (
	FixtureParityCheck    FixtureParityOperation = "check"
	FixtureParityDiscover FixtureParityOperation = "discover"
	FixtureParityReadPage FixtureParityOperation = "read-page"
)

type FixtureParityInput struct {
	SourceID      string                 `json:"source_id"`
	FamilyID      string                 `json:"family_id"`
	CaseID        string                 `json:"case_id"`
	Payload       []byte                 `json:"-"`
	PayloadSHA256 string                 `json:"payload_sha256,omitempty"`
	Operation     FixtureParityOperation `json:"operation"`
	Cursor        string                 `json:"cursor,omitempty"`
	Checkpoint    string                 `json:"checkpoint,omitempty"`
	Limit         int                    `json:"limit,omitempty"`
}

type FixtureParityEvent struct {
	EventID       string `json:"event_id"`
	Kind          string `json:"kind"`
	InputIndex    int    `json:"input_index"`
	PayloadSHA256 string `json:"payload_sha256"`
}

type FixtureParityQuarantine struct {
	Category   string `json:"category"`
	FieldPath  string `json:"field_path"`
	InputIndex int    `json:"input_index"`
}

type FixtureParityDuplicate struct {
	EventID         string `json:"event_id"`
	InputIndex      int    `json:"input_index"`
	FirstInputIndex int    `json:"first_input_index"`
}

type FixtureParityPage struct {
	SourceID              string                    `json:"source_id"`
	FamilyID              string                    `json:"family_id"`
	CaseID                string                    `json:"case_id"`
	Operation             FixtureParityOperation    `json:"operation"`
	AcceptedEvents        []FixtureParityEvent      `json:"accepted_events"`
	Quarantines           []FixtureParityQuarantine `json:"quarantines"`
	Duplicates            []FixtureParityDuplicate  `json:"duplicates"`
	ScannedCount          int                       `json:"scanned_count"`
	AcceptedCount         int                       `json:"accepted_count"`
	RejectedCount         int                       `json:"rejected_count"`
	NextCursor            string                    `json:"next_cursor,omitempty"`
	ProposedCheckpoint    string                    `json:"proposed_checkpoint,omitempty"`
	ShortCircuitReasons   []string                  `json:"short_circuit_reasons,omitempty"`
	ReconciliationReasons []string                  `json:"reconciliation_reasons,omitempty"`
}

type FixtureParityReceipt struct {
	SchemaVersion          string   `json:"schema_version"`
	CorpusRevision         string   `json:"corpus_revision"`
	SourceID               string   `json:"source_id"`
	FamilyID               string   `json:"family_id"`
	CaseID                 string   `json:"case_id"`
	Operation              string   `json:"operation"`
	GoPageDigestSHA256     string   `json:"go_page_digest_sha256"`
	RustPageDigestSHA256   string   `json:"rust_page_digest_sha256"`
	CursorDigestSHA256     string   `json:"cursor_digest_sha256"`
	CheckpointDigestSHA256 string   `json:"checkpoint_digest_sha256"`
	QuarantineSummary      []string `json:"quarantine_summary"`
	MismatchCount          int      `json:"mismatch_count"`
	ReceiptDigestSHA256    string   `json:"receipt_digest_sha256"`
}

type FixtureParityComparison struct {
	GoPage   FixtureParityPage    `json:"go_page"`
	RustPage FixtureParityPage    `json:"rust_page"`
	Receipt  FixtureParityReceipt `json:"receipt"`
}

type FixtureGoOracleCase struct {
	SourceID              string                 `json:"source_id"`
	FamilyID              string                 `json:"family_id"`
	CaseID                string                 `json:"case_id"`
	Operation             FixtureParityOperation `json:"operation"`
	PayloadSHA256         string                 `json:"payload_sha256,omitempty"`
	GoPage                FixtureParityPage      `json:"go_page"`
	GoPageDigestSHA256    string                 `json:"go_page_digest_sha256"`
	OracleDigestSHA256    string                 `json:"oracle_digest_sha256"`
	OfflineProof          string                 `json:"offline_proof"`
	ProviderNetworkEgress bool                   `json:"provider_network_egress"`
}

type FixtureGoOracleMatrix struct {
	SchemaVersion  string                `json:"schema_version"`
	CorpusRevision string                `json:"corpus_revision"`
	Cases          []FixtureGoOracleCase `json:"cases"`
}

type FixtureParityMatrix struct {
	CorpusRevision string                    `json:"corpus_revision"`
	Comparisons    []FixtureParityComparison `json:"comparisons"`
	MismatchCount  int                       `json:"mismatch_count"`
}

func BuildFixtureParityInputs(root string) ([]FixtureParityInput, error) {
	var inputs []FixtureParityInput
	if err := sourcefixture.WalkBundles(root, func(bundle sourcefixture.Bundle) error {
		for _, operation := range []FixtureParityOperation{
			FixtureParityCheck,
			FixtureParityDiscover,
			FixtureParityReadPage,
		} {
			inputs = append(inputs, FixtureParityInput{
				SourceID:      bundle.Manifest.SourceID,
				FamilyID:      bundle.Manifest.Family,
				CaseID:        bundle.Manifest.Case,
				Payload:       bundle.Payload,
				PayloadSHA256: bundle.Manifest.Response.SHA256,
				Operation:     operation,
				Limit:         1000,
			})
		}
		return nil
	}); err != nil {
		return nil, err
	}
	sort.Slice(inputs, func(i, j int) bool {
		left := fixtureParityInputKey(inputs[i])
		right := fixtureParityInputKey(inputs[j])
		return left < right
	})
	return inputs, nil
}

func BuildGoFixtureOracleMatrix(root string) (FixtureGoOracleMatrix, error) {
	inputs, err := BuildFixtureParityInputs(root)
	if err != nil {
		return FixtureGoOracleMatrix{}, err
	}
	corpusRevision, err := fixtureCorpusRevision(inputs)
	if err != nil {
		return FixtureGoOracleMatrix{}, err
	}
	matrix := FixtureGoOracleMatrix{
		SchemaVersion:  fixtureParityCorpusVersion,
		CorpusRevision: corpusRevision,
	}
	for _, input := range inputs {
		page, err := ExecuteGoFixtureOraclePage(input)
		if err != nil {
			return FixtureGoOracleMatrix{}, err
		}
		pageDigest, err := CanonicalSourceRuntimeDigest(page)
		if err != nil {
			return FixtureGoOracleMatrix{}, err
		}
		oracle := FixtureGoOracleCase{
			SourceID:              input.SourceID,
			FamilyID:              input.FamilyID,
			CaseID:                input.CaseID,
			Operation:             input.Operation,
			PayloadSHA256:         input.PayloadSHA256,
			GoPage:                page,
			GoPageDigestSHA256:    pageDigest,
			OfflineProof:          "fixture_only_no_provider_network",
			ProviderNetworkEgress: false,
		}
		oracleDigest, err := CanonicalSourceRuntimeDigest(oracle)
		if err != nil {
			return FixtureGoOracleMatrix{}, err
		}
		oracle.OracleDigestSHA256 = oracleDigest
		matrix.Cases = append(matrix.Cases, oracle)
	}
	return matrix, nil
}

func CompareFixtureParityAgainstRustPage(input FixtureParityInput, corpusRevision string, goPage, rustPage FixtureParityPage) (FixtureParityComparison, error) {
	receipt, err := fixtureParityReceipt(input, corpusRevision, goPage, rustPage)
	if err != nil {
		return FixtureParityComparison{}, err
	}
	return FixtureParityComparison{GoPage: goPage, RustPage: rustPage, Receipt: receipt}, nil
}

func ExecuteGoFixtureOraclePage(input FixtureParityInput) (FixtureParityPage, error) {
	page := FixtureParityPage{
		SourceID:       input.SourceID,
		FamilyID:       input.FamilyID,
		CaseID:         input.CaseID,
		Operation:      input.Operation,
		NextCursor:     input.Cursor,
		AcceptedEvents: []FixtureParityEvent{},
		Quarantines:    []FixtureParityQuarantine{},
		Duplicates:     []FixtureParityDuplicate{},
	}
	switch input.Operation {
	case FixtureParityCheck:
		page.ProposedCheckpoint = input.Checkpoint
		page.ShortCircuitReasons = []string{"check_only"}
		return page, nil
	case FixtureParityDiscover:
		page.AcceptedEvents = append(page.AcceptedEvents, fixtureParityEvent(input, 0, map[string]any{
			"source_id": input.SourceID,
			"family_id": input.FamilyID,
			"case_id":   input.CaseID,
			"operation": "discover",
		}))
		page.ScannedCount = 1
		page.AcceptedCount = 1
		page.ProposedCheckpoint = digestFixtureValue(map[string]any{"discovered": page.AcceptedEvents})
		return page, nil
	case FixtureParityReadPage:
	default:
		return FixtureParityPage{}, fmt.Errorf("unsupported fixture parity operation %q", input.Operation)
	}
	records, err := fixtureRecords(input.Payload)
	if err != nil {
		page.Quarantines = append(page.Quarantines, FixtureParityQuarantine{
			Category:   "malformed_record",
			FieldPath:  "$",
			InputIndex: 0,
		})
		page.RejectedCount = 1
		page.ProposedCheckpoint = input.Checkpoint
		page.ShortCircuitReasons = []string{"malformed_record"}
		return page, nil
	}
	if len(records) == 0 {
		page.ShortCircuitReasons = []string{"empty_page"}
		page.ProposedCheckpoint = input.Checkpoint
		return page, nil
	}
	seen := map[string]int{}
	for index, record := range records {
		page.ScannedCount++
		if missingFixtureIdentity(record) {
			page.Quarantines = append(page.Quarantines, FixtureParityQuarantine{
				Category:   "missing_identity",
				FieldPath:  "$.id",
				InputIndex: index,
			})
			page.RejectedCount++
			continue
		}
		event := fixtureParityEvent(input, index, record)
		if first, ok := seen[event.EventID]; ok {
			page.Duplicates = append(page.Duplicates, FixtureParityDuplicate{
				EventID:         event.EventID,
				InputIndex:      index,
				FirstInputIndex: first,
			})
			continue
		}
		seen[event.EventID] = index
		if input.Limit > 0 && len(page.AcceptedEvents) >= input.Limit {
			page.NextCursor = fmt.Sprintf("fixture://%s/%s/%s/%d", input.SourceID, input.FamilyID, input.CaseID, index)
			page.ShortCircuitReasons = appendStableReason(page.ShortCircuitReasons, "event_limit_deferral")
			continue
		}
		page.AcceptedEvents = append(page.AcceptedEvents, event)
	}
	page.AcceptedCount = len(page.AcceptedEvents)
	if page.NextCursor == "" {
		page.ShortCircuitReasons = appendStableReason(page.ShortCircuitReasons, "final_page")
	}
	page.ProposedCheckpoint = digestFixtureValue(map[string]any{
		"source_id": input.SourceID,
		"family_id": input.FamilyID,
		"case_id":   input.CaseID,
		"accepted":  page.AcceptedEvents,
	})
	if input.Checkpoint != "" && input.Checkpoint == page.ProposedCheckpoint {
		page.ShortCircuitReasons = appendStableReason(page.ShortCircuitReasons, "not_modified")
		page.ReconciliationReasons = appendStableReason(page.ReconciliationReasons, "equal_watermark")
	}
	if len(page.Duplicates) > 0 {
		page.ReconciliationReasons = appendStableReason(page.ReconciliationReasons, "duplicate_event")
	}
	return page, nil
}

func fixtureParityReceipt(input FixtureParityInput, corpusRevision string, goPage, rustPage FixtureParityPage) (FixtureParityReceipt, error) {
	goDigest, err := CanonicalSourceRuntimeDigest(goPage)
	if err != nil {
		return FixtureParityReceipt{}, err
	}
	rustDigest, err := CanonicalSourceRuntimeDigest(rustPage)
	if err != nil {
		return FixtureParityReceipt{}, err
	}
	mismatchCount := 0
	if goDigest != rustDigest {
		mismatchCount = 1
	}
	receipt := FixtureParityReceipt{
		SchemaVersion:          fixtureParityCorpusVersion,
		CorpusRevision:         corpusRevision,
		SourceID:               input.SourceID,
		FamilyID:               input.FamilyID,
		CaseID:                 input.CaseID,
		Operation:              string(input.Operation),
		GoPageDigestSHA256:     goDigest,
		RustPageDigestSHA256:   rustDigest,
		CursorDigestSHA256:     digestFixtureValue(goPage.NextCursor),
		CheckpointDigestSHA256: digestFixtureValue(goPage.ProposedCheckpoint),
		QuarantineSummary:      quarantineSummary(goPage.Quarantines),
		MismatchCount:          mismatchCount,
	}
	receiptDigest, err := CanonicalSourceRuntimeDigest(receipt)
	if err != nil {
		return FixtureParityReceipt{}, err
	}
	receipt.ReceiptDigestSHA256 = receiptDigest
	return receipt, nil
}

func fixtureRecords(payload []byte) ([]any, error) {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	var records []any
	collectFixtureRecords(value, &records)
	return records, nil
}

func collectFixtureRecords(value any, records *[]any) {
	switch typed := value.(type) {
	case []any:
		*records = append(*records, typed...)
	case map[string]any:
		for _, key := range []string{"data", "items", "results", "records", "users", "members", "logs", "assets", "repositories"} {
			if child, ok := typed[key]; ok {
				if list, ok := child.([]any); ok {
					*records = append(*records, list...)
					return
				}
			}
		}
		*records = append(*records, typed)
	}
}

func fixtureParityEvent(input FixtureParityInput, index int, record any) FixtureParityEvent {
	payloadDigest := digestFixtureValue(record)
	return FixtureParityEvent{
		EventID:       digestFixtureValue(map[string]any{"source_id": input.SourceID, "family_id": input.FamilyID, "case_id": input.CaseID, "payload_sha256": payloadDigest}),
		Kind:          input.SourceID + "." + input.FamilyID,
		InputIndex:    index,
		PayloadSHA256: payloadDigest,
	}
}

func missingFixtureIdentity(record any) bool {
	object, ok := record.(map[string]any)
	if !ok {
		return false
	}
	for _, field := range []string{"id", "ID", "uuid", "key", "name", "login", "email"} {
		if value, ok := object[field]; ok && strings.TrimSpace(fmt.Sprint(value)) != "" {
			return false
		}
	}
	return true
}

func fixtureCorpusRevision(inputs []FixtureParityInput) (string, error) {
	entries := make([]string, 0, len(inputs))
	for _, input := range inputs {
		payloadDigest := input.PayloadSHA256
		if payloadDigest == "" {
			payloadDigest = digestFixtureValue(json.RawMessage(input.Payload))
		}
		entries = append(entries, filepath.ToSlash(fixtureParityInputKey(input))+":"+payloadDigest)
	}
	sort.Strings(entries)
	return digestFixtureValue(entries), nil
}

func fixtureParityInputKey(input FixtureParityInput) string {
	return input.SourceID + "/" + input.FamilyID + "/" + input.CaseID + "/" + string(input.Operation)
}

func digestFixtureValue(value any) string {
	digest, err := CanonicalSourceRuntimeDigest(value)
	if err != nil {
		return ""
	}
	return digest
}

func quarantineSummary(quarantines []FixtureParityQuarantine) []string {
	summary := make([]string, 0, len(quarantines))
	for _, quarantine := range quarantines {
		summary = append(summary, quarantine.Category+":"+quarantine.FieldPath)
	}
	sort.Strings(summary)
	return summary
}

func appendStableReason(reasons []string, reason string) []string {
	for _, existing := range reasons {
		if existing == reason {
			return reasons
		}
	}
	reasons = append(reasons, reason)
	sort.Strings(reasons)
	return reasons
}
