package eventadmission

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"unicode"

	"github.com/fxamacker/cbor/v2"
	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"google.golang.org/protobuf/proto"
)

// These benchmarks answer separate questions. EndToEnd measures the production
// boundary. WasmEvaluation measures a pre-encoded request through a fresh guest
// instance. HostRequestEncoding and HostResponseDecoding measure the JSON bridge.
// EquivalentGoJSON is a benchmark-only implementation that produces byte-for-byte
// equivalent outcomes for the corpus below; it is not a production fallback.
// NativeEvaluation measures the persistent Rust process with the JSON parity
// protocol. NativeCBOREvaluation measures the production protocol.

func TestAdmissionNativeWorkerMatchesWasmCorpus(t *testing.T) {
	path := os.Getenv(NativeWorkerPathEnv)
	if path == "" {
		t.Skipf("%s is not configured", NativeWorkerPathEnv)
	}
	client, err := NewNativeClient(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})
	ctx := context.Background()
	for _, workload := range admissionBenchmarkWorkloads() {
		t.Run(workload.name, func(t *testing.T) {
			request, encodeErr := encodeAdmissionRequest(workload.events, workload.contracts)
			if encodeErr != nil {
				t.Fatalf("encodeAdmissionRequest() error = %v", encodeErr)
			}
			wasmResult, evaluateErr := eventAdmissionEvaluator.Evaluate(ctx, request)
			if evaluateErr != nil {
				t.Fatalf("Wasm Evaluate() error = %v", evaluateErr)
			}
			nativeResult, evaluateErr := client.Evaluate(ctx, request)
			if evaluateErr != nil {
				t.Fatalf("native Evaluate() error = %v", evaluateErr)
			}
			if !bytes.Equal(nativeResult, wasmResult) {
				t.Fatalf("native and Wasm implementations diverged\nnative: %s\nWasm:   %s", nativeResult, wasmResult)
			}

			requestValue, encodeErr := newAdmissionRequest(workload.events, workload.contracts)
			if encodeErr != nil {
				t.Fatalf("newAdmissionRequest() error = %v", encodeErr)
			}
			cborRequest, encodeErr := cbor.Marshal(requestValue)
			if encodeErr != nil {
				t.Fatalf("CBOR request error = %v", encodeErr)
			}
			cborResult, evaluateErr := client.evaluateCBOR(ctx, cborRequest)
			if evaluateErr != nil {
				t.Fatalf("native CBOR Evaluate() error = %v", evaluateErr)
			}
			var wasmOutcome, nativeOutcome admissionOutcome
			if decodeErr := json.Unmarshal(wasmResult, &wasmOutcome); decodeErr != nil {
				t.Fatalf("decode Wasm outcome: %v", decodeErr)
			}
			if decodeErr := cbor.Unmarshal(cborResult, &nativeOutcome); decodeErr != nil {
				t.Fatalf("decode native outcome: %v", decodeErr)
			}
			if !reflect.DeepEqual(nativeOutcome, wasmOutcome) {
				t.Fatalf("native CBOR and Wasm outcomes diverged\nnative: %#v\nWasm:   %#v", nativeOutcome, wasmOutcome)
			}
		})
	}
}

func TestAdmissionNativePoolHandlesConcurrentPages(t *testing.T) {
	path := os.Getenv(NativeWorkerPathEnv)
	if path == "" {
		t.Skipf("%s is not configured", NativeWorkerPathEnv)
	}
	admitter, err := NewNativeAdmitter(context.Background(), path, 2)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := admitter.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})
	workload := acceptedBenchmarkWorkload(100, 0)
	want, err := Admit(context.Background(), workload.events, workload.contracts)
	if err != nil {
		t.Fatalf("Wasm Admit() error = %v", err)
	}

	var wait sync.WaitGroup
	errors := make(chan error, 8)
	for range 8 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			got, admitErr := admitter.Admit(context.Background(), workload.events, workload.contracts)
			if admitErr != nil {
				errors <- admitErr
				return
			}
			if !reflect.DeepEqual(got, want) {
				errors <- fmt.Errorf("native admission response diverged from Wasm")
			}
		}()
	}
	wait.Wait()
	close(errors)
	for err := range errors {
		t.Error(err)
	}
}

type admissionBenchmarkWorkload struct {
	name         string
	events       []*cerebrov1.EventEnvelope
	contracts    []sourcecdk.EventContract
	wantRejected bool
}

var (
	admissionBenchmarkResponse Response
	admissionBenchmarkBytes    []byte
)

func TestAdmissionBenchmarkGoReferenceMatchesRustCorpus(t *testing.T) {
	ctx := context.Background()
	for _, workload := range admissionBenchmarkWorkloads() {
		t.Run(workload.name, func(t *testing.T) {
			request, err := encodeAdmissionRequest(workload.events, workload.contracts)
			if err != nil {
				t.Fatalf("encodeAdmissionRequest() error = %v", err)
			}
			rustResult, err := eventAdmissionEvaluator.Evaluate(ctx, request)
			if err != nil {
				t.Fatalf("Rust Evaluate() error = %v", err)
			}
			goResult, err := benchmarkGoEquivalentJSON(request)
			if err != nil {
				t.Fatalf("Go equivalent error = %v", err)
			}
			if !bytes.Equal(rustResult, goResult) {
				t.Fatalf("equivalent implementations diverged\nRust: %s\nGo:   %s", rustResult, goResult)
			}
			_, decodeErr := decodeAdmissionResult(rustResult, workload.events)
			if workload.wantRejected {
				if !errors.Is(decodeErr, ErrBatchRejected) {
					t.Fatalf("decodeAdmissionResult() error = %v; want %v", decodeErr, ErrBatchRejected)
				}
			} else if decodeErr != nil {
				t.Fatalf("decodeAdmissionResult() error = %v", decodeErr)
			}
		})
	}
}

func BenchmarkAdmissionSmoke(b *testing.B) {
	ctx := context.Background()
	workload := acceptedBenchmarkWorkload(100, 0)
	if _, err := admitBenchmarkWorkload(ctx, workload); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		response, err := admitBenchmarkWorkload(ctx, workload)
		if err != nil {
			b.Fatal(err)
		}
		admissionBenchmarkResponse = response
	}
}

func BenchmarkAdmissionEndToEnd(b *testing.B) {
	for _, workload := range admissionBenchmarkWorkloads() {
		b.Run(workload.name, func(b *testing.B) {
			ctx := context.Background()
			if _, err := admitBenchmarkWorkload(ctx, workload); err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				response, err := admitBenchmarkWorkload(ctx, workload)
				if err != nil {
					b.Fatal(err)
				}
				admissionBenchmarkResponse = response
			}
		})
	}
}

func BenchmarkAdmissionHostRequestEncoding(b *testing.B) {
	for _, workload := range admissionBenchmarkWorkloads() {
		b.Run(workload.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				request, err := encodeAdmissionRequest(workload.events, workload.contracts)
				if err != nil {
					b.Fatal(err)
				}
				admissionBenchmarkBytes = request
			}
		})
	}
}

func BenchmarkAdmissionWasmEvaluation(b *testing.B) {
	for _, workload := range admissionBenchmarkWorkloads() {
		b.Run(workload.name, func(b *testing.B) {
			ctx := context.Background()
			request, err := encodeAdmissionRequest(workload.events, workload.contracts)
			if err != nil {
				b.Fatal(err)
			}
			if _, err := eventAdmissionEvaluator.Evaluate(ctx, request); err != nil {
				b.Fatal(err)
			}
			b.SetBytes(int64(len(request)))
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				result, err := eventAdmissionEvaluator.Evaluate(ctx, request)
				if err != nil {
					b.Fatal(err)
				}
				admissionBenchmarkBytes = result
			}
		})
	}
}

func BenchmarkAdmissionNativeEvaluation(b *testing.B) {
	for _, workload := range admissionBenchmarkWorkloads() {
		b.Run(workload.name, func(b *testing.B) {
			client := nativeBenchmarkClient(b)
			ctx := context.Background()
			request, err := encodeAdmissionRequest(workload.events, workload.contracts)
			if err != nil {
				b.Fatal(err)
			}
			if _, err := client.Evaluate(ctx, request); err != nil {
				b.Fatal(err)
			}
			b.SetBytes(int64(len(request)))
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				result, evaluateErr := client.Evaluate(ctx, request)
				if evaluateErr != nil {
					b.Fatal(evaluateErr)
				}
				admissionBenchmarkBytes = result
			}
		})
	}
}

func BenchmarkAdmissionNativeCBOREvaluation(b *testing.B) {
	for _, workload := range admissionBenchmarkWorkloads() {
		b.Run(workload.name, func(b *testing.B) {
			client := nativeBenchmarkClient(b)
			ctx := context.Background()
			request, err := newAdmissionRequest(workload.events, workload.contracts)
			if err != nil {
				b.Fatal(err)
			}
			payload, err := cbor.Marshal(request)
			if err != nil {
				b.Fatal(err)
			}
			if _, err := client.evaluateCBOR(ctx, payload); err != nil {
				b.Fatal(err)
			}
			b.SetBytes(int64(len(payload)))
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				result, evaluateErr := client.evaluateCBOR(ctx, payload)
				if evaluateErr != nil {
					b.Fatal(evaluateErr)
				}
				admissionBenchmarkBytes = result
			}
		})
	}
}

func BenchmarkAdmissionNativeEndToEnd(b *testing.B) {
	for _, workload := range admissionBenchmarkWorkloads() {
		b.Run(workload.name, func(b *testing.B) {
			client := nativeBenchmarkClient(b)
			ctx := context.Background()
			if _, err := admitNativeBenchmarkWorkload(ctx, client, workload); err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				response, err := admitNativeBenchmarkWorkload(ctx, client, workload)
				if err != nil {
					b.Fatal(err)
				}
				admissionBenchmarkResponse = response
			}
		})
	}
}

func BenchmarkAdmissionHostResponseDecoding(b *testing.B) {
	for _, workload := range admissionBenchmarkWorkloads() {
		b.Run(workload.name, func(b *testing.B) {
			ctx := context.Background()
			request, err := encodeAdmissionRequest(workload.events, workload.contracts)
			if err != nil {
				b.Fatal(err)
			}
			result, err := eventAdmissionEvaluator.Evaluate(ctx, request)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				response, decodeErr := decodeAdmissionResult(result, workload.events)
				if workload.wantRejected {
					if !errors.Is(decodeErr, ErrBatchRejected) {
						b.Fatalf("decode error = %v; want %v", decodeErr, ErrBatchRejected)
					}
				} else if decodeErr != nil {
					b.Fatal(decodeErr)
				}
				admissionBenchmarkResponse = response
			}
		})
	}
}

func BenchmarkAdmissionEquivalentGoJSON(b *testing.B) {
	for _, workload := range admissionBenchmarkWorkloads() {
		b.Run(workload.name, func(b *testing.B) {
			request, err := encodeAdmissionRequest(workload.events, workload.contracts)
			if err != nil {
				b.Fatal(err)
			}
			b.SetBytes(int64(len(request)))
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				result, err := benchmarkGoEquivalentJSON(request)
				if err != nil {
					b.Fatal(err)
				}
				admissionBenchmarkBytes = result
			}
		})
	}
}

func BenchmarkAdmissionWasmIsolationFloor(b *testing.B) {
	ctx := context.Background()
	request, err := json.Marshal(admissionRequest{SchemaVersion: SchemaVersion, Contracts: []sourcecdk.EventContract{}, Events: []eventEnvelope{}})
	if err != nil {
		b.Fatal(err)
	}
	if _, err := eventAdmissionEvaluator.Evaluate(ctx, request); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		result, err := eventAdmissionEvaluator.Evaluate(ctx, request)
		if err != nil {
			b.Fatal(err)
		}
		admissionBenchmarkBytes = result
	}
}

func BenchmarkAdmissionColdWasmEvaluation(b *testing.B) {
	workload := admissionBenchmarkWorkloads()[1]
	request, err := encodeAdmissionRequest(workload.events, workload.contracts)
	if err != nil {
		b.Fatal(err)
	}
	ctx := context.Background()
	b.SetBytes(int64(len(request)))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		evaluator := newEventAdmissionEvaluator()
		result, evaluateErr := evaluator.Evaluate(ctx, request)
		if evaluateErr != nil {
			b.Fatal(evaluateErr)
		}
		admissionBenchmarkBytes = result
		b.StopTimer()
		if err := evaluator.Close(ctx); err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
	}
}

func admitBenchmarkWorkload(ctx context.Context, workload admissionBenchmarkWorkload) (Response, error) {
	response, err := Admit(ctx, workload.events, workload.contracts)
	if workload.wantRejected {
		if !errors.Is(err, ErrBatchRejected) {
			if err == nil {
				return Response{}, errors.New("Admit() accepted a workload that requires batch rejection")
			}
			return Response{}, fmt.Errorf("Admit() must return a batch rejection: %w", err)
		}
		return response, nil
	}
	return response, err
}

func admitNativeBenchmarkWorkload(ctx context.Context, client *NativeClient, workload admissionBenchmarkWorkload) (Response, error) {
	response, err := admitNative(ctx, client, workload.events, workload.contracts)
	if workload.wantRejected {
		if !errors.Is(err, ErrBatchRejected) {
			if err == nil {
				return Response{}, errors.New("native admission accepted a workload that requires batch rejection")
			}
			return Response{}, fmt.Errorf("native admission must return a batch rejection: %w", err)
		}
		return response, nil
	}
	return response, err
}

func nativeBenchmarkClient(b *testing.B) *NativeClient {
	b.Helper()
	path := os.Getenv(NativeWorkerPathEnv)
	if path == "" {
		b.Skipf("%s is not configured", NativeWorkerPathEnv)
	}
	client, err := NewNativeClient(context.Background(), path)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() {
		if err := client.Close(); err != nil {
			b.Errorf("Close() error = %v", err)
		}
	})
	return client
}

func admissionBenchmarkWorkloads() []admissionBenchmarkWorkload {
	return []admissionBenchmarkWorkload{
		acceptedBenchmarkWorkload(1, 0),
		acceptedBenchmarkWorkload(100, 0),
		acceptedBenchmarkWorkload(1_000, 0),
		acceptedBenchmarkWorkload(MaxEvents, 0),
		quarantineBenchmarkWorkload(1_000),
		duplicateBenchmarkWorkload(1_000),
		conflictBenchmarkWorkload(1_000),
		acceptedBenchmarkWorkload(100, 1<<10),
		acceptedBenchmarkWorkload(100, 10<<10),
	}
}

func acceptedBenchmarkWorkload(count, blobBytes int) admissionBenchmarkWorkload {
	name := fmt.Sprintf("accepted/events_%d", count)
	if blobBytes != 0 {
		name = fmt.Sprintf("accepted/events_%d/payload_%dk", count, blobBytes>>10)
	}
	events := make([]*cerebrov1.EventEnvelope, 0, count)
	for index := 0; index < count; index++ {
		events = append(events, admissionBenchmarkEvent(index, blobBytes, false))
	}
	return admissionBenchmarkWorkload{name: name, events: events, contracts: testContracts()}
}

func quarantineBenchmarkWorkload(count int) admissionBenchmarkWorkload {
	events := make([]*cerebrov1.EventEnvelope, 0, count)
	for index := 0; index < count; index++ {
		events = append(events, admissionBenchmarkEvent(index, 0, index%10 == 9))
	}
	return admissionBenchmarkWorkload{name: fmt.Sprintf("quarantine_10_percent/events_%d", count), events: events, contracts: testContracts()}
}

func duplicateBenchmarkWorkload(count int) admissionBenchmarkWorkload {
	events := make([]*cerebrov1.EventEnvelope, 0, count)
	for index := 0; index < count; index++ {
		if index%10 == 9 {
			events = append(events, proto.Clone(events[len(events)-1]).(*cerebrov1.EventEnvelope))
			continue
		}
		events = append(events, admissionBenchmarkEvent(index, 0, false))
	}
	return admissionBenchmarkWorkload{name: fmt.Sprintf("duplicate_10_percent/events_%d", count), events: events, contracts: testContracts()}
}

func conflictBenchmarkWorkload(count int) admissionBenchmarkWorkload {
	events := acceptedBenchmarkWorkload(count, 0).events
	events[len(events)-1].Id = events[0].GetId()
	return admissionBenchmarkWorkload{
		name:         fmt.Sprintf("conflicting_duplicate/events_%d", count),
		events:       events,
		contracts:    testContracts(),
		wantRejected: true,
	}
}

func admissionBenchmarkEvent(index, blobBytes int, quarantine bool) *cerebrov1.EventEnvelope {
	identity := fmt.Sprintf(`{"id":"user-%d"}`, index)
	if quarantine {
		identity = `{}`
	}
	payload := fmt.Sprintf(`{"identity":%s}`, identity)
	if blobBytes != 0 {
		payload = fmt.Sprintf(`{"blob":"%s","identity":%s}`, strings.Repeat("x", blobBytes), identity)
	}
	event := testEvent(fmt.Sprintf("event-%d", index), payload)
	event.Attributes = map[string]string{
		"resource_id":   fmt.Sprintf("user-%d", index),
		"resource_type": "identity",
	}
	return event
}

func benchmarkGoEquivalentJSON(payload []byte) ([]byte, error) {
	var request admissionRequest
	if err := json.Unmarshal(payload, &request); err != nil {
		return nil, err
	}
	outcome, err := benchmarkGoAdmission(request)
	if err != nil {
		return nil, err
	}
	return json.Marshal(outcome)
}

func benchmarkGoAdmission(request admissionRequest) (admissionOutcome, error) {
	contracts := make(map[string]sourcecdk.EventContract, len(request.Contracts))
	for _, contract := range request.Contracts {
		normalized, err := sourcecdk.NormalizeEventContract(contract)
		if err != nil {
			return admissionOutcome{}, err
		}
		sort.Strings(normalized.RequiredAttributes)
		sort.Strings(normalized.RequiredPayloadFields)
		contracts[normalized.Kind] = normalized
	}
	accepted := make([]Accepted, 0, len(request.Events))
	quarantined := make([]Rejection, 0)
	duplicates := make([]Duplicate, 0)
	scannedDigests := make([]string, 0, len(request.Events))
	type seenEvent struct {
		index  int
		digest string
	}
	seen := make(map[string]seenEvent, len(request.Events))
	for inputIndex, event := range request.Events {
		var canonicalPayload any
		if err := json.Unmarshal([]byte(event.PayloadJSON), &canonicalPayload); err != nil {
			return admissionOutcome{}, err
		}
		eventDigest, err := benchmarkDigest(benchmarkReceiptEvent{
			ID: event.ID, TenantID: event.TenantID, SourceID: event.SourceID, Kind: event.Kind,
			OccurredAt: event.OccurredAt, SchemaRef: event.SchemaRef, Payload: canonicalPayload, Attributes: event.Attributes,
		})
		if err != nil {
			return admissionOutcome{}, err
		}
		scannedDigests = append(scannedDigests, eventDigest)
		decision, rejection := benchmarkValidateEvent(inputIndex, event, canonicalPayload, contracts)
		if decision == "rejected" {
			return admissionOutcome{Outcome: "rejected", Rejection: rejection}, nil
		}
		if decision == "quarantined" {
			quarantined = append(quarantined, *rejection)
			continue
		}
		if first, ok := seen[event.ID]; ok {
			if first.digest != eventDigest {
				return admissionOutcome{Outcome: "rejected", Rejection: benchmarkEventRejection(
					inputIndex, "duplicate_event_conflict", "id",
					fmt.Sprintf("event id %q conflicts with input index %d", event.ID, first.index),
				)}, nil
			}
			duplicates = append(duplicates, Duplicate{
				InputIndex: inputIndex, FirstInputIndex: first.index, EventID: event.ID, EventSHA256: eventDigest,
			})
			continue
		}
		seen[event.ID] = seenEvent{index: inputIndex, digest: eventDigest}
		accepted = append(accepted, Accepted{InputIndex: inputIndex, EventID: event.ID, EventSHA256: eventDigest})
	}
	scannedSHA, err := benchmarkDigest(scannedDigests)
	if err != nil {
		return admissionOutcome{}, err
	}
	acceptedSHA, err := benchmarkDigest(accepted)
	if err != nil {
		return admissionOutcome{}, err
	}
	resultSHA, err := benchmarkDigest([]any{scannedSHA, accepted, quarantined, duplicates})
	if err != nil {
		return admissionOutcome{}, err
	}
	return admissionOutcome{Outcome: "admitted", Response: &Response{
		SchemaVersion: SchemaVersion,
		Accepted:      accepted,
		Quarantined:   quarantined,
		Duplicates:    duplicates,
		Receipt: Receipt{
			Scanned: len(request.Events), Accepted: len(accepted), Quarantined: len(quarantined), Duplicates: len(duplicates),
			ScannedSHA256: scannedSHA, AcceptedSHA256: acceptedSHA, ResultSHA256: resultSHA,
		},
	}}, nil
}

type benchmarkReceiptEvent struct {
	ID         string            `json:"id"`
	TenantID   string            `json:"tenant_id"`
	SourceID   string            `json:"source_id"`
	Kind       string            `json:"kind"`
	OccurredAt *timestamp        `json:"occurred_at"`
	SchemaRef  string            `json:"schema_ref"`
	Payload    any               `json:"payload"`
	Attributes map[string]string `json:"attributes"`
}

func benchmarkValidateEvent(inputIndex int, event eventEnvelope, payload any, contracts map[string]sourcecdk.EventContract) (string, *Rejection) {
	for field, value := range map[string]string{
		"id": event.ID, "tenant_id": event.TenantID, "source_id": event.SourceID, "kind": event.Kind, "schema_ref": event.SchemaRef,
	} {
		if !benchmarkValidRequiredText(value) {
			return "rejected", benchmarkEventRejection(inputIndex, "invalid_event_envelope", field, field+" is required without surrounding whitespace")
		}
	}
	if event.OccurredAt == nil || event.OccurredAt.Seconds < -62_135_596_800 || event.OccurredAt.Seconds > 253_402_300_799 || event.OccurredAt.Nanos < 0 || event.OccurredAt.Nanos >= 1_000_000_000 {
		return "rejected", benchmarkEventRejection(inputIndex, "invalid_timestamp", "occurred_at", "occurred_at is outside the protobuf timestamp range")
	}
	if len(event.Attributes) > 512 {
		return "rejected", benchmarkEventRejection(inputIndex, "attribute_limit_exceeded", "attributes", "attribute count exceeds 512")
	}
	for key := range event.Attributes {
		if !benchmarkValidRequiredText(key) {
			return "rejected", benchmarkEventRejection(inputIndex, "invalid_attribute_key", "attributes", "attribute keys must not be empty or contain surrounding whitespace")
		}
	}
	if len(contracts) == 0 {
		return "accepted", nil
	}
	contract, ok := contracts[event.Kind]
	if !ok {
		return "rejected", benchmarkEventRejection(inputIndex, "event_contract_missing", "kind", fmt.Sprintf("kind %q has no matching event contract", event.Kind))
	}
	if contract.SchemaRef != "" && contract.SchemaRef != event.SchemaRef {
		return "rejected", benchmarkEventRejection(inputIndex, "event_contract_schema_mismatch", "schema_ref", fmt.Sprintf("schema_ref %q does not match contract %q", event.SchemaRef, contract.SchemaRef))
	}
	for _, key := range contract.RequiredAttributes {
		if strings.TrimSpace(event.Attributes[key]) == "" {
			return "quarantined", benchmarkEventRejection(inputIndex, "missing_required_attribute", key, fmt.Sprintf("kind %q is missing required attribute %q", event.Kind, key))
		}
	}
	for _, field := range contract.RequiredPayloadFields {
		if !benchmarkPayloadHasField(payload, field) {
			return "quarantined", benchmarkEventRejection(inputIndex, "missing_required_payload_field", field, fmt.Sprintf("kind %q is missing required payload field %q", event.Kind, field))
		}
	}
	return "accepted", nil
}

func benchmarkEventRejection(inputIndex int, code, field, message string) *Rejection {
	return &Rejection{InputIndex: &inputIndex, Code: code, Field: field, Message: message}
}

func benchmarkValidRequiredText(value string) bool {
	return value != "" && len(value) <= 512 && strings.TrimSpace(value) == value && !strings.ContainsFunc(value, unicode.IsControl)
}

func benchmarkPayloadHasField(payload any, path string) bool {
	for _, candidate := range strings.Split(path, "|") {
		current := payload
		valid := true
		for _, part := range strings.Split(strings.TrimSpace(candidate), ".") {
			object, ok := current.(map[string]any)
			if !ok || strings.TrimSpace(part) == "" {
				valid = false
				break
			}
			current, ok = object[part]
			if !ok || current == nil {
				valid = false
				break
			}
			if text, ok := current.(string); ok && strings.TrimSpace(text) == "" {
				valid = false
				break
			}
		}
		if valid {
			return true
		}
	}
	return false
}

func benchmarkDigest(value any) (string, error) {
	body, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}
