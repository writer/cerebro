package eventadmission

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/wasmhost"
	"github.com/writer/cerebro/internal/wasmjson"
)

const (
	SchemaVersion  = "source-event-admission.v1"
	ABIVersion     = 1
	MaxEvents      = 5_000
	MaxInputBytes  = 32 << 20
	MaxOutputBytes = 8 << 20
)

var (
	// ErrKernelUnavailable means the isolated admission kernel could not return a trusted decision.
	ErrKernelUnavailable = errors.New("source event admission kernel is unavailable")
	// ErrBatchRejected means the kernel rejected the complete page before durable append.
	ErrBatchRejected = errors.New("source event batch was rejected")
)

//go:embed eventadmission.wasm
var eventAdmissionWasm []byte

var eventAdmissionEvaluator = newEventAdmissionEvaluator()

func newEventAdmissionEvaluator() *wasmjson.Evaluator {
	return wasmjson.New(wasmjson.Config{
		Name:              "embedded source event admission kernel",
		Module:            eventAdmissionWasm,
		ABIVersion:        ABIVersion,
		ABIVersionExport:  "cerebro_event_admission_abi_version",
		AllocateExport:    "cerebro_event_admission_alloc",
		EvaluateExport:    "cerebro_event_admission_evaluate",
		MemoryLimitPages:  2048,
		MaxInputBytes:     MaxInputBytes,
		MaxOutputBytes:    MaxOutputBytes,
		InitializeTimeout: 30 * time.Second,
		CallTimeout:       5 * time.Second,
	})
}

type admissionRequest struct {
	SchemaVersion string                    `json:"schema_version"`
	Contracts     []sourcecdk.EventContract `json:"contracts"`
	Events        []eventEnvelope           `json:"events"`
}

type eventEnvelope struct {
	ID          string            `json:"id"`
	TenantID    string            `json:"tenant_id"`
	SourceID    string            `json:"source_id"`
	Kind        string            `json:"kind"`
	OccurredAt  *timestamp        `json:"occurred_at"`
	SchemaRef   string            `json:"schema_ref"`
	PayloadJSON string            `json:"payload_json"`
	Attributes  map[string]string `json:"attributes"`
}

type timestamp struct {
	Seconds int64 `json:"seconds"`
	Nanos   int32 `json:"nanos"`
}

type admissionOutcome struct {
	Outcome   string     `json:"outcome"`
	Response  *Response  `json:"response,omitempty"`
	Rejection *Rejection `json:"rejection,omitempty"`
}

// Response is the complete admission decision for one source page.
type Response struct {
	SchemaVersion string                     `json:"schema_version"`
	Accepted      []Accepted                 `json:"accepted"`
	Quarantined   []Rejection                `json:"quarantined"`
	Duplicates    []Duplicate                `json:"duplicates"`
	Receipt       Receipt                    `json:"receipt"`
	Events        []*cerebrov1.EventEnvelope `json:"-"`
}

// Accepted identifies one input event authorized for durable append.
type Accepted struct {
	InputIndex  int    `json:"input_index"`
	EventID     string `json:"event_id"`
	EventSHA256 string `json:"event_sha256"`
}

// Rejection identifies a bounded event or page failure.
type Rejection struct {
	InputIndex *int   `json:"input_index"`
	Code       string `json:"code"`
	Field      string `json:"field,omitempty"`
	Message    string `json:"message"`
}

// Duplicate identifies one input collapsed into an identical earlier event.
type Duplicate struct {
	InputIndex      int    `json:"input_index"`
	FirstInputIndex int    `json:"first_input_index"`
	EventID         string `json:"event_id"`
	EventSHA256     string `json:"event_sha256"`
}

// Receipt binds the input counts to deterministic admission digests.
type Receipt struct {
	Scanned        int    `json:"scanned"`
	Accepted       int    `json:"accepted"`
	Quarantined    int    `json:"quarantined"`
	Duplicates     int    `json:"duplicates"`
	ScannedSHA256  string `json:"scanned_sha256"`
	AcceptedSHA256 string `json:"accepted_sha256"`
	ResultSHA256   string `json:"result_sha256"`
}

// RejectedError carries the kernel's typed page rejection.
type RejectedError struct {
	Rejection Rejection
}

func (e *RejectedError) Error() string {
	if e == nil {
		return ErrBatchRejected.Error()
	}
	return fmt.Sprintf("%s: %s: %s", ErrBatchRejected, e.Rejection.Code, e.Rejection.Message)
}

func (e *RejectedError) Unwrap() error { return ErrBatchRejected }

// Admit runs one materialized source page through a fresh capability-free Wasm instance.
func Admit(ctx context.Context, events []*cerebrov1.EventEnvelope, contracts []sourcecdk.EventContract) (Response, error) {
	payload, err := encodeAdmissionRequest(events, contracts)
	if err != nil {
		return Response{}, err
	}
	result, err := eventAdmissionEvaluator.Evaluate(ctx, payload)
	if err != nil {
		return Response{}, fmt.Errorf("%w: %w", ErrKernelUnavailable, err)
	}
	return decodeAdmissionResult(result, events)
}

func encodeAdmissionRequest(events []*cerebrov1.EventEnvelope, contracts []sourcecdk.EventContract) ([]byte, error) {
	request := admissionRequest{
		SchemaVersion: SchemaVersion,
		Contracts:     append([]sourcecdk.EventContract{}, contracts...),
		Events:        make([]eventEnvelope, 0, len(events)),
	}
	if rejection := validateTransportContracts(contracts); rejection != nil {
		return nil, &RejectedError{Rejection: *rejection}
	}
	for index, event := range events {
		if rejection := validateTransportEvent(index, event); rejection != nil {
			return nil, &RejectedError{Rejection: *rejection}
		}
		request.Events = append(request.Events, eventForAdmission(event))
	}
	payload, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("%w: encode request: %w", ErrKernelUnavailable, err)
	}
	return payload, nil
}

func decodeAdmissionResult(result []byte, events []*cerebrov1.EventEnvelope) (Response, error) {
	var outcome admissionOutcome
	if err := json.Unmarshal(result, &outcome); err != nil {
		return Response{}, wasmhost.Diagnose(wasmhost.DiagnosticOutputInvalid, fmt.Errorf("%w: decode response: %w", ErrKernelUnavailable, err))
	}
	switch outcome.Outcome {
	case "rejected":
		if outcome.Rejection == nil || outcome.Response != nil || strings.TrimSpace(outcome.Rejection.Code) == "" {
			return Response{}, invalidOutput("rejected outcome has an invalid shape")
		}
		return Response{}, &RejectedError{Rejection: *outcome.Rejection}
	case "admitted":
		if outcome.Response == nil || outcome.Rejection != nil {
			return Response{}, invalidOutput("admitted outcome has an invalid shape")
		}
	default:
		return Response{}, invalidOutput("unknown outcome %q", outcome.Outcome)
	}
	if err := validateResponse(*outcome.Response, events); err != nil {
		return Response{}, err
	}
	for _, accepted := range outcome.Response.Accepted {
		outcome.Response.Events = append(outcome.Response.Events, events[accepted.InputIndex])
	}
	return *outcome.Response, nil
}

func eventForAdmission(event *cerebrov1.EventEnvelope) eventEnvelope {
	if event == nil {
		return eventEnvelope{}
	}
	var occurredAt *timestamp
	if event.GetOccurredAt() != nil {
		occurredAt = &timestamp{Seconds: event.GetOccurredAt().GetSeconds(), Nanos: event.GetOccurredAt().GetNanos()}
	}
	attributes := event.GetAttributes()
	if attributes == nil {
		attributes = map[string]string{}
	}
	return eventEnvelope{
		ID:          event.GetId(),
		TenantID:    event.GetTenantId(),
		SourceID:    event.GetSourceId(),
		Kind:        event.GetKind(),
		OccurredAt:  occurredAt,
		SchemaRef:   event.GetSchemaRef(),
		PayloadJSON: string(event.GetPayload()),
		Attributes:  attributes,
	}
}

func validateResponse(response Response, events []*cerebrov1.EventEnvelope) error {
	if response.SchemaVersion != SchemaVersion {
		return invalidOutput("schema_version = %q", response.SchemaVersion)
	}
	if response.Receipt.Scanned != len(events) ||
		response.Receipt.Accepted != len(response.Accepted) ||
		response.Receipt.Quarantined != len(response.Quarantined) ||
		response.Receipt.Duplicates != len(response.Duplicates) ||
		len(response.Accepted)+len(response.Quarantined)+len(response.Duplicates) != len(events) {
		return invalidOutput("receipt counts do not partition the input")
	}
	if !validDigest(response.Receipt.ScannedSHA256) || !validDigest(response.Receipt.AcceptedSHA256) || !validDigest(response.Receipt.ResultSHA256) {
		return invalidOutput("receipt digest is invalid")
	}
	seen := make(map[int]struct{}, len(events))
	acceptedByIndex := make(map[int]Accepted, len(response.Accepted))
	for _, accepted := range response.Accepted {
		if err := validateDecisionIndex(accepted.InputIndex, events, seen); err != nil {
			return err
		}
		if events[accepted.InputIndex] == nil || accepted.EventID != events[accepted.InputIndex].GetId() || !validDigest(accepted.EventSHA256) {
			return invalidOutput("accepted input %d identity is invalid", accepted.InputIndex)
		}
		acceptedByIndex[accepted.InputIndex] = accepted
	}
	for _, rejection := range response.Quarantined {
		if rejection.InputIndex == nil || strings.TrimSpace(rejection.Code) == "" {
			return invalidOutput("quarantine is missing its input index or code")
		}
		if err := validateDecisionIndex(*rejection.InputIndex, events, seen); err != nil {
			return err
		}
	}
	for _, duplicate := range response.Duplicates {
		if err := validateDecisionIndex(duplicate.InputIndex, events, seen); err != nil {
			return err
		}
		first, firstAccepted := acceptedByIndex[duplicate.FirstInputIndex]
		if duplicate.FirstInputIndex < 0 || duplicate.FirstInputIndex >= duplicate.InputIndex || !firstAccepted ||
			events[duplicate.InputIndex] == nil || duplicate.EventID != events[duplicate.InputIndex].GetId() || !validDigest(duplicate.EventSHA256) {
			return invalidOutput("duplicate input %d identity is invalid", duplicate.InputIndex)
		}
		if first.EventID != duplicate.EventID || first.EventSHA256 != duplicate.EventSHA256 {
			return invalidOutput("duplicate input %d does not match accepted input %d", duplicate.InputIndex, duplicate.FirstInputIndex)
		}
	}
	return nil
}

func validateTransportContracts(contracts []sourcecdk.EventContract) *Rejection {
	for _, contract := range contracts {
		fields := append([]string{contract.Kind, contract.SchemaRef}, contract.RequiredAttributes...)
		fields = append(fields, contract.RequiredPayloadFields...)
		for _, value := range fields {
			if !utf8.ValidString(value) {
				return &Rejection{Code: "invalid_contract", Message: "event contract contains invalid UTF-8"}
			}
		}
	}
	return nil
}

func validateTransportEvent(index int, event *cerebrov1.EventEnvelope) *Rejection {
	if event == nil {
		return &Rejection{InputIndex: &index, Code: "invalid_event_envelope", Message: "event is required"}
	}
	for field, value := range map[string]string{
		"id":         event.GetId(),
		"tenant_id":  event.GetTenantId(),
		"source_id":  event.GetSourceId(),
		"kind":       event.GetKind(),
		"schema_ref": event.GetSchemaRef(),
	} {
		if !utf8.ValidString(value) {
			return &Rejection{InputIndex: &index, Code: "invalid_event_envelope", Field: field, Message: field + " must be valid UTF-8"}
		}
	}
	for key, value := range event.GetAttributes() {
		if !utf8.ValidString(key) || !utf8.ValidString(value) {
			return &Rejection{InputIndex: &index, Code: "invalid_event_envelope", Field: "attributes", Message: "attributes must be valid UTF-8"}
		}
	}
	return nil
}

func validateDecisionIndex(index int, events []*cerebrov1.EventEnvelope, seen map[int]struct{}) error {
	if index < 0 || index >= len(events) {
		return invalidOutput("decision input index %d is out of range", index)
	}
	if _, ok := seen[index]; ok {
		return invalidOutput("input index %d has multiple decisions", index)
	}
	seen[index] = struct{}{}
	return nil
}

func validDigest(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, character := range value[len("sha256:"):] {
		if !strings.ContainsRune("0123456789abcdef", character) {
			return false
		}
	}
	return true
}

func invalidOutput(format string, args ...any) error {
	return wasmhost.Diagnose(wasmhost.DiagnosticOutputInvalid, fmt.Errorf("%w: %s", ErrKernelUnavailable, fmt.Sprintf(format, args...)))
}
