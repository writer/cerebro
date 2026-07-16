package recordkernel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/tetratelabs/wazero"
	"github.com/writer/cerebro/internal/wasmjson"
)

func TestRecordKernelMapsDeterministicallyAndQuarantinesBadRows(t *testing.T) {
	t.Parallel()
	request := recordKernelTestRequest()
	first, err := EvaluateRecordMapping(context.Background(), request)
	if err != nil {
		t.Fatalf("EvaluateRecordMapping() error = %v", err)
	}
	second, err := EvaluateRecordMapping(context.Background(), request)
	if err != nil {
		t.Fatalf("EvaluateRecordMapping() second error = %v", err)
	}
	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatalf("json.Marshal(first) error = %v", err)
	}
	secondJSON, err := json.Marshal(second)
	if err != nil {
		t.Fatalf("json.Marshal(second) error = %v", err)
	}
	if string(firstJSON) != string(secondJSON) {
		t.Fatalf("record kernel is not deterministic:\nfirst:  %s\nsecond: %s", firstJSON, secondJSON)
	}
	if first.Outcome != "mapped" || first.Response == nil {
		t.Fatalf("outcome = %#v; want mapped response", first)
	}
	if got := []string{first.Response.Accepted[0].ExternalID, first.Response.Accepted[1].ExternalID}; got[0] != "user-a" || got[1] != "user-b" {
		t.Fatalf("accepted identity order = %v; want [user-a user-b]", got)
	}
	if len(first.Response.Quarantined) != 1 || first.Response.Quarantined[0].Code != "external_id_invalid" {
		t.Fatalf("quarantined = %#v; want one external_id_invalid row", first.Response.Quarantined)
	}
	if len(first.Response.Receipt.RecordsSHA256) != 64 || len(first.Response.Checkpoint.InputSHA256) != 64 {
		t.Fatalf("receipt digests are not SHA-256: %#v", first.Response)
	}
}

func TestRecordKernelCanonicalizesObjectKeyOrderAcrossEmbeddedCalls(t *testing.T) {
	t.Parallel()
	firstRequest := recordKernelTestRequest()
	firstRequest.Page.Records = []json.RawMessage{
		json.RawMessage(`{"id":"user-a","profile":{"z":1,"a":2}}`),
	}
	secondRequest := recordKernelTestRequest()
	secondRequest.Page.Records = []json.RawMessage{
		json.RawMessage(`{"profile":{"a":2,"z":1},"id":"user-a"}`),
	}

	first, err := EvaluateRecordMapping(context.Background(), firstRequest)
	if err != nil {
		t.Fatalf("EvaluateRecordMapping(first) error = %v", err)
	}
	second, err := EvaluateRecordMapping(context.Background(), secondRequest)
	if err != nil {
		t.Fatalf("EvaluateRecordMapping(second) error = %v", err)
	}
	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatalf("json.Marshal(first) error = %v", err)
	}
	secondJSON, err := json.Marshal(second)
	if err != nil {
		t.Fatalf("json.Marshal(second) error = %v", err)
	}
	if string(firstJSON) != string(secondJSON) {
		t.Fatalf("key order changed the embedded result:\nfirst:  %s\nsecond: %s", firstJSON, secondJSON)
	}
}

func TestRecordKernelReturnsBoundedContractRejection(t *testing.T) {
	t.Parallel()
	request := recordKernelTestRequest()
	request.Contract.SourceID = " source-with-whitespace"

	outcome, err := EvaluateRecordMapping(context.Background(), request)
	if err != nil {
		t.Fatalf("EvaluateRecordMapping() error = %v", err)
	}
	if outcome.Outcome != "rejected" || outcome.Code != "source_id_invalid" || outcome.Response != nil {
		t.Fatalf("outcome = %#v; want source_id_invalid rejection", outcome)
	}
	if strings.Contains(outcome.Message, "user-a") {
		t.Fatalf("rejection leaked record payload: %q", outcome.Message)
	}
}

func TestRecordKernelMapsEmptyPageAndPreservesCursor(t *testing.T) {
	t.Parallel()
	request := recordKernelTestRequest()
	request.Page.Records = nil

	outcome, err := EvaluateRecordMapping(context.Background(), request)
	if err != nil {
		t.Fatalf("EvaluateRecordMapping() error = %v", err)
	}
	if outcome.Outcome != "mapped" || outcome.Response == nil {
		t.Fatalf("outcome = %#v; want mapped response", outcome)
	}
	if len(outcome.Response.Accepted) != 0 || len(outcome.Response.Quarantined) != 0 {
		t.Fatalf("response = %#v; want no mapped records", outcome.Response)
	}
	if outcome.Response.Checkpoint.NextCursor != request.Page.NextCursor {
		t.Fatalf("next cursor = %q; want %q", outcome.Response.Checkpoint.NextCursor, request.Page.NextCursor)
	}
}

func TestRecordKernelReturnsBoundedRejectionForNegativeLimits(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		code string
		set  func(*RecordMappingContract)
	}{
		{
			name: "records",
			code: "max_records_invalid",
			set:  func(contract *RecordMappingContract) { contract.MaxRecords = -1 },
		},
		{
			name: "record bytes",
			code: "max_record_bytes_invalid",
			set:  func(contract *RecordMappingContract) { contract.MaxRecordBytes = -1 },
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := recordKernelTestRequest()
			test.set(&request.Contract)

			outcome, err := EvaluateRecordMapping(context.Background(), request)
			if err != nil {
				t.Fatalf("EvaluateRecordMapping() error = %v", err)
			}
			if outcome.Outcome != "rejected" || outcome.Code != test.code || outcome.Response != nil {
				t.Fatalf("outcome = %#v; want %s rejection", outcome, test.code)
			}
		})
	}
}

func TestRecordKernelRejectsOversizedInputBeforeGuestExecution(t *testing.T) {
	t.Parallel()
	request := recordKernelTestRequest()
	request.Page.Records = []json.RawMessage{json.RawMessage(`{"id":"user-a","blob":"` + strings.Repeat("a", recordKernelMaxInput) + `"}`)}

	_, err := EvaluateRecordMapping(context.Background(), request)
	if !errors.Is(err, wasmjson.ErrInputTooLarge) {
		t.Fatalf("EvaluateRecordMapping() error = %v; want %v", err, wasmjson.ErrInputTooLarge)
	}
}

func TestRecordKernelRejectsOversizedHostFieldsBeforeEncoding(t *testing.T) {
	t.Parallel()
	request := recordKernelTestRequest()
	request.AttemptID = strings.Repeat("a", recordKernelMaxInput+1)

	_, err := EvaluateRecordMapping(context.Background(), request)
	if !errors.Is(err, wasmjson.ErrInputTooLarge) {
		t.Fatalf("EvaluateRecordMapping() error = %v; want %v", err, wasmjson.ErrInputTooLarge)
	}
}

func TestRecordKernelMapsARequestNearTheConfiguredInputBudget(t *testing.T) {
	t.Parallel()
	request := recordKernelTestRequest()
	request.Contract.MaxRecords = 3
	request.Contract.MaxRecordBytes = 220 << 10
	request.Page.Records = make([]json.RawMessage, 0, 3)
	for index := range 3 {
		payload, err := json.Marshal(map[string]string{
			"id":   fmt.Sprintf("user-%d", index),
			"blob": strings.Repeat("a", 200<<10),
		})
		if err != nil {
			t.Fatalf("json.Marshal(record %d) error = %v", index, err)
		}
		request.Page.Records = append(request.Page.Records, payload)
	}

	outcome, err := EvaluateRecordMapping(context.Background(), request)
	if err != nil {
		t.Fatalf("EvaluateRecordMapping() error = %v", err)
	}
	if outcome.Response == nil || outcome.Response.Receipt.Accepted != 3 {
		t.Fatalf("outcome = %#v; want three accepted records", outcome)
	}
}

func TestRecordKernelHasNoAmbientImports(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	runtime := wazero.NewRuntime(ctx)
	t.Cleanup(func() { _ = runtime.Close(ctx) })
	compiled, err := runtime.CompileModule(ctx, recordKernelWasm)
	if err != nil {
		t.Fatalf("CompileModule() error = %v", err)
	}
	if got := len(compiled.ImportedFunctions()); got != 0 {
		t.Fatalf("imported functions = %d; want 0", got)
	}
	if got := len(compiled.ImportedMemories()); got != 0 {
		t.Fatalf("imported memories = %d; want 0", got)
	}
}

func recordKernelTestRequest() RecordMappingRequest {
	return RecordMappingRequest{
		Contract: RecordMappingContract{
			SourceID:       "directory",
			Family:         "identity",
			IDField:        "id",
			MaxRecords:     10,
			MaxRecordBytes: 1_024,
		},
		Page: RecordMappingPage{
			Records: []json.RawMessage{
				json.RawMessage(`{"id":"user-b","name":"B"}`),
				json.RawMessage(`{"name":"missing"}`),
				json.RawMessage(`{"id":"user-a","name":"A"}`),
			},
			NextCursor: "cursor-2",
		},
		AttemptID: "attempt-1",
	}
}
