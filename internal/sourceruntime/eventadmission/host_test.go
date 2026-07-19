package eventadmission

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestAdmitReturnsOnlyEventsAuthorizedByKernel(t *testing.T) {
	events := []*cerebrov1.EventEnvelope{
		testEvent("event-1", `{"identity":{"id":"user-1"}}`),
		testEvent("event-2", `{"identity":{}}`),
	}

	response, err := Admit(context.Background(), events, testContracts())
	if err != nil {
		t.Fatalf("Admit() error = %v", err)
	}
	if len(response.Events) != 1 || response.Events[0] != events[0] {
		t.Fatalf("authorized events = %#v; want only event-1", response.Events)
	}
	if len(response.Quarantined) != 1 || response.Quarantined[0].Code != "missing_required_payload_field" {
		t.Fatalf("quarantined = %#v; want event-2 missing payload field", response.Quarantined)
	}
	if response.Quarantined[0].InputIndex == nil || *response.Quarantined[0].InputIndex != 1 {
		t.Fatalf("quarantine index = %#v; want 1", response.Quarantined[0].InputIndex)
	}
	if response.Receipt.Scanned != 2 || response.Receipt.Accepted != 1 || response.Receipt.Quarantined != 1 {
		t.Fatalf("receipt = %#v; want 2/1/1", response.Receipt)
	}
}

func TestAdmitIsDeterministicAcrossPayloadKeyOrder(t *testing.T) {
	first := testEvent("event-1", `{"identity":{"name":"Ada","id":"user-1"}}`)
	second := testEvent("event-1", `{"identity":{"id":"user-1","name":"Ada"}}`)

	firstResponse, err := Admit(context.Background(), []*cerebrov1.EventEnvelope{first}, testContracts())
	if err != nil {
		t.Fatalf("Admit(first) error = %v", err)
	}
	secondResponse, err := Admit(context.Background(), []*cerebrov1.EventEnvelope{second}, testContracts())
	if err != nil {
		t.Fatalf("Admit(second) error = %v", err)
	}
	if firstResponse.Accepted[0].EventSHA256 != secondResponse.Accepted[0].EventSHA256 ||
		firstResponse.Receipt.ResultSHA256 != secondResponse.Receipt.ResultSHA256 {
		t.Fatalf("payload key order changed receipts:\nfirst:  %#v\nsecond: %#v", firstResponse.Receipt, secondResponse.Receipt)
	}
}

func TestAdmitCollapsesIdenticalDuplicates(t *testing.T) {
	event := testEvent("event-1", `{"identity":{"id":"user-1"}}`)
	duplicate := proto.Clone(event).(*cerebrov1.EventEnvelope)

	response, err := Admit(context.Background(), []*cerebrov1.EventEnvelope{event, duplicate}, testContracts())
	if err != nil {
		t.Fatalf("Admit() error = %v", err)
	}
	if len(response.Events) != 1 || len(response.Duplicates) != 1 {
		t.Fatalf("accepted/duplicates = %d/%d; want 1/1", len(response.Events), len(response.Duplicates))
	}
	if response.Duplicates[0].FirstInputIndex != 0 || response.Duplicates[0].InputIndex != 1 {
		t.Fatalf("duplicate = %#v; want input 1 linked to input 0", response.Duplicates[0])
	}
}

func TestAdmitRejectsConflictingDuplicateBeforeReturningEvents(t *testing.T) {
	first := testEvent("event-1", `{"identity":{"id":"user-1"}}`)
	conflict := testEvent("event-1", `{"identity":{"id":"user-2"}}`)

	response, err := Admit(context.Background(), []*cerebrov1.EventEnvelope{first, conflict}, testContracts())
	if !errors.Is(err, ErrBatchRejected) {
		t.Fatalf("Admit() error = %v; want %v", err, ErrBatchRejected)
	}
	if len(response.Events) != 0 {
		t.Fatalf("authorized events = %d; want 0 after batch rejection", len(response.Events))
	}
	var rejected *RejectedError
	if !errors.As(err, &rejected) || rejected.Rejection.Code != "duplicate_event_conflict" {
		t.Fatalf("Admit() error = %#v; want duplicate_event_conflict", err)
	}
}

func TestAdmitRejectsEnvelopeFailuresInsideKernel(t *testing.T) {
	tests := []struct {
		name string
		edit func(*cerebrov1.EventEnvelope)
		code string
	}{
		{name: "invalid payload", edit: func(event *cerebrov1.EventEnvelope) { event.Payload = []byte("{") }, code: "invalid_event_payload"},
		{name: "missing timestamp", edit: func(event *cerebrov1.EventEnvelope) { event.OccurredAt = nil }, code: "invalid_timestamp"},
		{name: "invalid kind", edit: func(event *cerebrov1.EventEnvelope) { event.Kind = "Identity" }, code: "invalid_event_kind"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			event := testEvent("event-1", `{"identity":{"id":"user-1"}}`)
			test.edit(event)
			_, err := Admit(context.Background(), []*cerebrov1.EventEnvelope{event}, nil)
			var rejected *RejectedError
			if !errors.As(err, &rejected) || rejected.Rejection.Code != test.code {
				t.Fatalf("Admit() error = %#v; want %s", err, test.code)
			}
		})
	}
}

func TestAdmitRejectsInvalidUTF8BeforeJSONCanRepairOriginalEvent(t *testing.T) {
	tests := []struct {
		name  string
		field string
		edit  func(*cerebrov1.EventEnvelope)
	}{
		{name: "id", field: "id", edit: func(event *cerebrov1.EventEnvelope) { event.Id = string([]byte{'e', 0xff}) }},
		{name: "payload", field: "payload", edit: func(event *cerebrov1.EventEnvelope) {
			event.Payload = []byte(`{"identity":{"id":"user-` + string([]byte{0xff}) + `"}}`)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			event := testEvent("event-1", `{"identity":{"id":"user-1"}}`)
			test.edit(event)
			response, err := Admit(context.Background(), []*cerebrov1.EventEnvelope{event}, nil)
			if !errors.Is(err, ErrBatchRejected) {
				t.Fatalf("Admit() error = %v; want transport rejection", err)
			}
			if len(response.Events) != 0 {
				t.Fatalf("authorized events = %d; want 0", len(response.Events))
			}
			var rejected *RejectedError
			if !errors.As(err, &rejected) || rejected.Rejection.Code != "invalid_event_envelope" || rejected.Rejection.Field != test.field {
				t.Fatalf("Admit() error = %#v; want invalid %s UTF-8", err, test.field)
			}
		})
	}
}

func TestAdmitLargestBoundedQuarantinePageFitsOutputBudget(t *testing.T) {
	events := make([]*cerebrov1.EventEnvelope, 0, MaxEvents)
	for index := 0; index < MaxEvents; index++ {
		events = append(events, testEvent(fmt.Sprintf("event-%d", index), `{"identity":{}}`))
	}
	response, err := Admit(context.Background(), events, testContracts())
	if err != nil {
		t.Fatalf("Admit() error = %v", err)
	}
	if response.Receipt.Scanned != MaxEvents || response.Receipt.Quarantined != MaxEvents || len(response.Events) != 0 {
		t.Fatalf("receipt/events = %#v/%d; want %d quarantined and none authorized", response.Receipt, len(response.Events), MaxEvents)
	}
}

func TestAdmitReturnsTypedRejectionAboveEventLimit(t *testing.T) {
	events := make([]*cerebrov1.EventEnvelope, MaxEvents+1)
	for index := range events {
		events[index] = testEvent(fmt.Sprintf("event-%d", index), `{"identity":{"id":"user-1"}}`)
	}
	_, err := Admit(context.Background(), events, nil)
	var rejected *RejectedError
	if !errors.As(err, &rejected) || rejected.Rejection.Code != "event_limit_exceeded" {
		t.Fatalf("Admit() error = %#v; want typed event_limit_exceeded", err)
	}
}

func TestAdmitMatchesGoContractDecisionsForRepresentativeCorpus(t *testing.T) {
	tests := []struct {
		name      string
		event     *cerebrov1.EventEnvelope
		contracts []sourcecdk.EventContract
		wantClass string
	}{
		{name: "accepted", event: testEvent("event-1", `{"identity":{"id":"user-1"}}`), contracts: testContracts(), wantClass: "accepted"},
		{name: "quarantined", event: testEvent("event-1", `{"identity":{}}`), contracts: testContracts(), wantClass: "quarantined"},
		{name: "contract missing", event: testEvent("event-1", `{"identity":{"id":"user-1"}}`), contracts: []sourcecdk.EventContract{{Kind: "directory.group", RequiredPayloadFields: []string{"group.id"}}}, wantClass: "rejected"},
		{name: "envelope rejected", event: testEvent("event-1", `{"identity":{"id":"user-1"}}`), contracts: nil, wantClass: "rejected"},
	}
	tests[3].event.SchemaRef = "bad"
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			goErr := sourcecdk.ValidateEventEnvelopeWithContracts(test.event, test.contracts)
			response, rustErr := Admit(context.Background(), []*cerebrov1.EventEnvelope{test.event}, test.contracts)
			rustClass := "accepted"
			if rustErr != nil {
				rustClass = "rejected"
			} else if len(response.Quarantined) != 0 {
				rustClass = "quarantined"
			}
			if rustClass != test.wantClass {
				t.Fatalf("Rust decision = %q; want %q; error=%v", rustClass, test.wantClass, rustErr)
			}
			switch test.wantClass {
			case "accepted":
				if goErr != nil {
					t.Fatalf("Go decision rejected accepted case: %v", goErr)
				}
			case "quarantined":
				if !errors.Is(goErr, sourcecdk.ErrInvalidEventEnvelope) {
					t.Fatalf("Go decision = %v; want %v", goErr, sourcecdk.ErrInvalidEventEnvelope)
				}
			case "rejected":
				if goErr == nil {
					t.Fatal("Go decision accepted a Rust-rejected compatibility case")
				}
			}
		})
	}
}

func TestAdmitHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Admit(ctx, []*cerebrov1.EventEnvelope{testEvent("event-1", `{"identity":{"id":"user-1"}}`)}, testContracts())
	if err == nil || !errors.Is(err, ErrKernelUnavailable) {
		t.Fatalf("Admit() error = %v; want unavailable canceled call", err)
	}
}

func testEvent(id, payload string) *cerebrov1.EventEnvelope {
	return &cerebrov1.EventEnvelope{
		Id:         id,
		TenantId:   "tenant-1",
		SourceId:   "directory",
		Kind:       "directory.identity",
		OccurredAt: timestamppb.New(time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)),
		SchemaRef:  "directory/identity/v1",
		Payload:    []byte(payload),
		Attributes: map[string]string{"resource_id": "user-1"},
	}
}

func testContracts() []sourcecdk.EventContract {
	return []sourcecdk.EventContract{{
		Kind:                  "directory.identity",
		SchemaRef:             "directory/identity/v1",
		RequiredAttributes:    []string{"resource_id"},
		RequiredPayloadFields: []string{"identity.id"},
	}}
}
