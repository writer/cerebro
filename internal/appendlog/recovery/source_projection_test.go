package recovery

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

type codedProjectionError struct{ code string }

func (e codedProjectionError) Error() string               { return "rejected: provider body with secret-token" }
func (e codedProjectionError) ProjectionErrorCode() string { return e.code }

func sourceProjectionTestEvent() *cerebrov1.EventEnvelope {
	return &cerebrov1.EventEnvelope{
		Id:       "okta-user-1",
		TenantId: "writer",
		SourceId: "okta",
		Kind:     "okta.user",
		Payload:  []byte(`{"id":"1"}`),
		Attributes: map[string]string{
			ports.EventAttributeSourceRuntimeID:    "writer-okta",
			ports.EventAttributeSourceCollectionID: "collection-1",
			ports.EventAttributeJobID:              "job-1",
		},
	}
}

func TestSourceProjectionDeadLetterRecordsReprojectionContext(t *testing.T) {
	event := sourceProjectionTestEvent()
	record, err := SourceProjectionDeadLetter(event, fmt.Errorf("project: %w", codedProjectionError{code: "invalid_legacy_projection"}))
	if err != nil {
		t.Fatalf("SourceProjectionDeadLetter() error = %v", err)
	}
	if record.Operation != ports.AppendLogDeadLetterOperationSourceProjection ||
		record.Status != ports.AppendLogDeadLetterStatusPending ||
		record.Subject != "source_projection.okta.user" ||
		record.EventID != "okta-user-1" || record.EventKind != "okta.user" ||
		record.TenantID != "writer" || record.SourceID != "okta" ||
		record.RuntimeID != "writer-okta" || record.JobID != "job-1" ||
		record.ErrorCategory != "invalid_legacy_projection" ||
		record.PayloadHash == "" || record.PayloadBytes == 0 ||
		!strings.HasPrefix(record.ID, "apdl_") {
		t.Fatalf("SourceProjectionDeadLetter() = %#v", record)
	}
	if strings.Contains(record.ErrorMessage, "secret-token") {
		t.Fatalf("ErrorMessage = %q, must not persist the raw projector error", record.ErrorMessage)
	}
	if !proto.Equal(record.Event, event) || record.Event == event {
		t.Fatal("dead letter must hold an independent copy of the appended event")
	}
}

func TestSourceProjectionDeadLetterIDIgnoresPerRunCollectionID(t *testing.T) {
	first, err := SourceProjectionDeadLetter(sourceProjectionTestEvent(), nil)
	if err != nil {
		t.Fatalf("SourceProjectionDeadLetter() error = %v", err)
	}
	retried := sourceProjectionTestEvent()
	retried.Attributes[ports.EventAttributeSourceCollectionID] = "collection-2"
	second, err := SourceProjectionDeadLetter(retried, nil)
	if err != nil {
		t.Fatalf("SourceProjectionDeadLetter() retry error = %v", err)
	}
	if first.ID != second.ID {
		t.Fatalf("retry ID = %q, want %q", second.ID, first.ID)
	}

	changed := sourceProjectionTestEvent()
	changed.Payload = []byte(`{"id":"1","name":"changed"}`)
	third, err := SourceProjectionDeadLetter(changed, nil)
	if err != nil {
		t.Fatalf("SourceProjectionDeadLetter() changed error = %v", err)
	}
	otherRuntime := sourceProjectionTestEvent()
	otherRuntime.Attributes[ports.EventAttributeSourceRuntimeID] = "writer-okta-2"
	fourth, err := SourceProjectionDeadLetter(otherRuntime, nil)
	if err != nil {
		t.Fatalf("SourceProjectionDeadLetter() other runtime error = %v", err)
	}
	if third.ID == first.ID || fourth.ID == first.ID {
		t.Fatal("changed payload or runtime must produce a distinct dead letter")
	}

	appendRecord, err := deadLetterFromEvent(sourceProjectionTestEvent(), &ports.AppendLogPublishExhaustedError{Subject: "events.okta.user"})
	if err != nil {
		t.Fatalf("deadLetterFromEvent() error = %v", err)
	}
	if appendRecord.ID == first.ID {
		t.Fatal("source projection and append dead letters must not share an ID")
	}
}

func TestSourceProjectionErrorCategoryIsBounded(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "no coder", err: errors.New("rejected"), want: SourceProjectionRejectedCategory},
		{name: "nil", err: nil, want: SourceProjectionRejectedCategory},
		{name: "code", err: codedProjectionError{code: "invalid_legacy_projection"}, want: "invalid_legacy_projection"},
		{name: "empty code", err: codedProjectionError{}, want: SourceProjectionRejectedCategory},
		{name: "free text", err: codedProjectionError{code: "bad value: secret"}, want: SourceProjectionRejectedCategory},
		{name: "too long", err: codedProjectionError{code: strings.Repeat("a", maxSourceProjectionCategoryBytes+1)}, want: SourceProjectionRejectedCategory},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := SourceProjectionErrorCategory(test.err); got != test.want {
				t.Fatalf("SourceProjectionErrorCategory() = %q, want %q", got, test.want)
			}
		})
	}
}
