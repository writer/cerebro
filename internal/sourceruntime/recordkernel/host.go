package recordkernel

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/writer/cerebro/internal/wasmjson"
)

const (
	recordKernelABIVersion = 1
	recordKernelMaxInput   = 1 << 20
	recordKernelMaxOutput  = 2 << 20
)

// ErrRecordKernelUnavailable indicates that the bounded record mapping guest could not run.
var ErrRecordKernelUnavailable = errors.New("source record kernel is unavailable")

//go:embed recordkernel.wasm
var recordKernelWasm []byte

var recordKernelEvaluator = wasmjson.New(wasmjson.Config{
	Name:              "embedded source record kernel",
	Module:            recordKernelWasm,
	ABIVersion:        recordKernelABIVersion,
	ABIVersionExport:  "cerebro_recordkernel_abi_version",
	AllocateExport:    "cerebro_recordkernel_alloc",
	EvaluateExport:    "cerebro_recordkernel_evaluate",
	MemoryLimitPages:  128,
	MaxInputBytes:     recordKernelMaxInput,
	MaxOutputBytes:    recordKernelMaxOutput,
	InitializeTimeout: 30 * time.Second,
	CallTimeout:       2 * time.Second,
})

// RecordMappingContract sets the identity fields and hard page bounds enforced by the kernel.
type RecordMappingContract struct {
	SourceID       string `json:"source_id"`
	Family         string `json:"family"`
	IDField        string `json:"id_field"`
	MaxRecords     int    `json:"max_records"`
	MaxRecordBytes int    `json:"max_record_bytes"`
}

// RecordMappingPage carries one provider page and the cursor to commit after mapping succeeds.
type RecordMappingPage struct {
	Records    []json.RawMessage `json:"records"`
	NextCursor string            `json:"next_cursor,omitempty"`
}

// RecordMappingRequest binds one page to one contract and execution attempt.
type RecordMappingRequest struct {
	Contract  RecordMappingContract `json:"contract"`
	Page      RecordMappingPage     `json:"page"`
	AttemptID string                `json:"attempt_id"`
}

// RecordMappingOutcome is either a mapped page with a receipt or a bounded contract rejection.
type RecordMappingOutcome struct {
	Outcome  string                 `json:"outcome"`
	Response *RecordMappingResponse `json:"response,omitempty"`
	Code     string                 `json:"code,omitempty"`
	Message  string                 `json:"message,omitempty"`
}

// RecordMappingResponse contains stable accepted records, quarantines, and a page receipt.
type RecordMappingResponse struct {
	SourceID    string                    `json:"source_id"`
	Family      string                    `json:"family"`
	AttemptID   string                    `json:"attempt_id"`
	Accepted    []RecordMappingAccepted   `json:"accepted"`
	Quarantined []RecordMappingQuarantine `json:"quarantined"`
	Checkpoint  RecordMappingCheckpoint   `json:"checkpoint"`
	Receipt     RecordMappingReceipt      `json:"receipt"`
}

// RecordMappingAccepted is one identity-addressable, canonicalized source record.
type RecordMappingAccepted struct {
	ExternalID        string          `json:"external_id"`
	FingerprintSHA256 string          `json:"fingerprint_sha256"`
	Payload           json.RawMessage `json:"payload"`
}

// RecordMappingQuarantine identifies a rejected row without returning its payload.
type RecordMappingQuarantine struct {
	InputIndex        int    `json:"input_index"`
	Code              string `json:"code"`
	FingerprintSHA256 string `json:"fingerprint_sha256"`
}

// RecordMappingCheckpoint is safe to persist only after the mapped page is accepted.
type RecordMappingCheckpoint struct {
	NextCursor  string `json:"next_cursor,omitempty"`
	InputSHA256 string `json:"input_sha256"`
}

// RecordMappingReceipt summarizes the exact accepted and quarantined output.
type RecordMappingReceipt struct {
	Accepted      int    `json:"accepted"`
	Quarantined   int    `json:"quarantined"`
	RecordsSHA256 string `json:"records_sha256"`
}

// EvaluateRecordMapping runs one bounded page through a fresh capability-free Wasm instance.
func EvaluateRecordMapping(ctx context.Context, request RecordMappingRequest) (RecordMappingOutcome, error) {
	payload, err := json.Marshal(request)
	if err != nil {
		return RecordMappingOutcome{}, fmt.Errorf("%w: encode request: %w", ErrRecordKernelUnavailable, err)
	}
	result, err := recordKernelEvaluator.Evaluate(ctx, payload)
	if err != nil {
		return RecordMappingOutcome{}, fmt.Errorf("%w: %w", ErrRecordKernelUnavailable, err)
	}
	var outcome RecordMappingOutcome
	if err := json.Unmarshal(result, &outcome); err != nil {
		return RecordMappingOutcome{}, fmt.Errorf("%w: decode response: %w", ErrRecordKernelUnavailable, err)
	}
	if outcome.Outcome != "mapped" && outcome.Outcome != "rejected" {
		return RecordMappingOutcome{}, fmt.Errorf("%w: unknown outcome %q", ErrRecordKernelUnavailable, outcome.Outcome)
	}
	if outcome.Outcome == "mapped" && outcome.Response == nil {
		return RecordMappingOutcome{}, fmt.Errorf("%w: mapped outcome is missing its response", ErrRecordKernelUnavailable)
	}
	if outcome.Outcome == "rejected" && (outcome.Response != nil || outcome.Code == "") {
		return RecordMappingOutcome{}, fmt.Errorf("%w: rejected outcome has an invalid shape", ErrRecordKernelUnavailable)
	}
	return outcome, nil
}
