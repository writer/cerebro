package graphactionapi

import (
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/graphactions"
	"github.com/writer/cerebro/internal/ports"
)

func TestInputFromRequestNil(t *testing.T) {
	input := InputFromRequest(nil)
	if input.FindingID != "" || input.Action != "" {
		t.Fatal("expected zero-value Input from nil request")
	}
}

func TestInputFromRequestPopulatesFields(t *testing.T) {
	req := &cerebrov1.ExecuteGraphActionRequest{
		FindingId:      "f-abc",
		Action:         "suspend",
		Target:         "user@example.com",
		Reason:         "policy violation",
		TicketUrl:      "https://ticket.example.com/123",
		IdempotencyKey: "key-1",
		Parameters:     map[string]string{"k": "v"},
		DryRun:         true,
		Approved:       true,
	}
	input := InputFromRequest(req)
	if input.FindingID != "f-abc" {
		t.Fatalf("FindingID = %q, want %q", input.FindingID, "f-abc")
	}
	if input.Action != "suspend" {
		t.Fatalf("Action = %q, want %q", input.Action, "suspend")
	}
	if input.Target != "user@example.com" {
		t.Fatalf("Target = %q, want %q", input.Target, "user@example.com")
	}
	if input.Reason != "policy violation" {
		t.Fatalf("Reason = %q, want %q", input.Reason, "policy violation")
	}
	if input.TicketURL != "https://ticket.example.com/123" {
		t.Fatalf("TicketURL = %q", input.TicketURL)
	}
	if input.IdempotencyKey != "key-1" {
		t.Fatalf("IdempotencyKey = %q", input.IdempotencyKey)
	}
	if input.Parameters["k"] != "v" {
		t.Fatalf("Parameters = %v", input.Parameters)
	}
	if !input.DryRun {
		t.Fatal("DryRun should be true")
	}
	if !input.Approved {
		t.Fatal("Approved should be true")
	}
}

func TestReconcileInputFromRequestNil(t *testing.T) {
	input := ReconcileInputFromRequest(nil)
	if input.FindingID != "" || input.ExternalID != "" {
		t.Fatal("expected zero-value ReconcileInput from nil request")
	}
}

func TestReconcileInputFromRequestPopulatesFields(t *testing.T) {
	req := &cerebrov1.ReconcileGraphActionRequest{
		FindingId:  "f-xyz",
		ExternalId: "ext-1",
	}
	input := ReconcileInputFromRequest(req)
	if input.FindingID != "f-xyz" {
		t.Fatalf("FindingID = %q, want %q", input.FindingID, "f-xyz")
	}
	if input.ExternalID != "ext-1" {
		t.Fatalf("ExternalID = %q, want %q", input.ExternalID, "ext-1")
	}
}

func TestResponseMessageNilResult(t *testing.T) {
	resp := ResponseMessage(nil, nil)
	if resp == nil {
		t.Fatal("expected non-nil response even for nil result")
	}
	if resp.Finding != nil || resp.Action != nil {
		t.Fatal("expected empty response fields")
	}
}

func TestResponseMessagePopulatesTarget(t *testing.T) {
	result := &graphactions.Result{
		Target: "user@test.com",
	}
	resp := ResponseMessage(result, nil)
	if resp.Target != "user@test.com" {
		t.Fatalf("Target = %q, want %q", resp.Target, "user@test.com")
	}
}

func TestReconcileResponseMessageNilResult(t *testing.T) {
	resp := ReconcileResponseMessage(nil, nil)
	if resp == nil {
		t.Fatal("expected non-nil response even for nil result")
	}
	if resp.Finding != nil || resp.Action != nil {
		t.Fatal("expected empty response fields")
	}
}

func TestReconcileResponseMessagePopulatesTarget(t *testing.T) {
	result := &graphactions.Result{
		Target: "user@test.com",
	}
	resp := ReconcileResponseMessage(result, nil)
	if resp.Target != "user@test.com" {
		t.Fatalf("Target = %q, want %q", resp.Target, "user@test.com")
	}
}

func TestActionMessageNil(t *testing.T) {
	if ActionMessage(nil) != nil {
		t.Fatal("expected nil for nil action")
	}
}

func TestActionMessagePopulatesFields(t *testing.T) {
	action := &graphactions.GraphAction{
		ID:                   "act-1",
		Action:               "suspend",
		Provider:             "okta",
		Status:               "completed",
		Target:               "user@example.com",
		ExternalID:           "ext-id",
		ExternalURL:          "https://ext.example.com",
		ExternalStatus:       "done",
		ExternalStatusReason: "auto-completed",
		Reason:               "policy",
		Source:               "cerebro",
		TicketURL:            "https://ticket.example.com/1",
		IdempotencyKey:       "idem-1",
		ActorType:            "human",
		ActorSubject:         "admin@example.com",
		CreatedAtUnix:        1700000000,
		UpdatedAtUnix:        1700000100,
		CompletedAtUnix:      1700000200,
		LastError:            "none",
		Metadata:             map[string]string{"key": "val"},
	}
	msg := ActionMessage(action)
	if msg.Id != "act-1" {
		t.Fatalf("Id = %q", msg.Id)
	}
	if msg.Action != "suspend" {
		t.Fatalf("Action = %q", msg.Action)
	}
	if msg.Provider != "okta" {
		t.Fatalf("Provider = %q", msg.Provider)
	}
	if msg.Status != "completed" {
		t.Fatalf("Status = %q", msg.Status)
	}
	if msg.Target != "user@example.com" {
		t.Fatalf("Target = %q", msg.Target)
	}
	if msg.ExternalId != "ext-id" {
		t.Fatalf("ExternalId = %q", msg.ExternalId)
	}
	if msg.ExternalUrl != "https://ext.example.com" {
		t.Fatalf("ExternalUrl = %q", msg.ExternalUrl)
	}
	if msg.ExternalStatus != "done" {
		t.Fatalf("ExternalStatus = %q", msg.ExternalStatus)
	}
	if msg.Reason != "policy" {
		t.Fatalf("Reason = %q", msg.Reason)
	}
	if msg.TicketUrl != "https://ticket.example.com/1" {
		t.Fatalf("TicketUrl = %q", msg.TicketUrl)
	}
	if msg.IdempotencyKey != "idem-1" {
		t.Fatalf("IdempotencyKey = %q", msg.IdempotencyKey)
	}
	if msg.ActorType != "human" {
		t.Fatalf("ActorType = %q", msg.ActorType)
	}
	if msg.ActorSubject != "admin@example.com" {
		t.Fatalf("ActorSubject = %q", msg.ActorSubject)
	}
	if msg.CreatedAt == nil {
		t.Fatal("CreatedAt should not be nil")
	}
	if msg.UpdatedAt == nil {
		t.Fatal("UpdatedAt should not be nil")
	}
	if msg.CompletedAt == nil {
		t.Fatal("CompletedAt should not be nil")
	}
	if msg.LastError != "none" {
		t.Fatalf("LastError = %q", msg.LastError)
	}
	if msg.Metadata["key"] != "val" {
		t.Fatalf("Metadata = %v", msg.Metadata)
	}
}

func TestActionMessageZeroTimestamps(t *testing.T) {
	action := &graphactions.GraphAction{
		ID:              "act-2",
		CreatedAtUnix:   0,
		UpdatedAtUnix:   0,
		CompletedAtUnix: 0,
	}
	msg := ActionMessage(action)
	if msg.CreatedAt != nil {
		t.Fatal("CreatedAt should be nil for zero timestamp")
	}
	if msg.UpdatedAt != nil {
		t.Fatal("UpdatedAt should be nil for zero timestamp")
	}
	if msg.CompletedAt != nil {
		t.Fatal("CompletedAt should be nil for zero timestamp")
	}
}

func TestExternalRefMessageEmpty(t *testing.T) {
	ref := ports.FindingExternalRef{}
	msg := ExternalRefMessage(ref)
	if msg != nil {
		t.Fatal("expected nil for empty external ref")
	}
}

func TestExternalRefMessagePopulated(t *testing.T) {
	ref := ports.FindingExternalRef{
		System:     "jira",
		Kind:       "ticket",
		ExternalID: "JIRA-123",
		URL:        "https://jira.example.com/JIRA-123",
	}
	msg := ExternalRefMessage(ref)
	if msg == nil {
		t.Fatal("expected non-nil message for valid ref")
	}
	if msg.System != "jira" {
		t.Fatalf("System = %q", msg.System)
	}
	if msg.Kind != "ticket" {
		t.Fatalf("Kind = %q", msg.Kind)
	}
	if msg.ExternalId != "JIRA-123" {
		t.Fatalf("ExternalId = %q", msg.ExternalId)
	}
	if msg.Url != "https://jira.example.com/JIRA-123" {
		t.Fatalf("Url = %q", msg.Url)
	}
}

func TestUnixTimestampZero(t *testing.T) {
	ts := unixTimestamp(0)
	if ts != nil {
		t.Fatal("expected nil for zero seconds")
	}
}

func TestUnixTimestampNegative(t *testing.T) {
	ts := unixTimestamp(-1)
	if ts != nil {
		t.Fatal("expected nil for negative seconds")
	}
}

func TestUnixTimestampPositive(t *testing.T) {
	ts := unixTimestamp(1700000000)
	if ts == nil {
		t.Fatal("expected non-nil timestamp")
	}
	got := ts.AsTime()
	want := time.Unix(1700000000, 0).UTC()
	if !got.Equal(want) {
		t.Fatalf("timestamp = %v, want %v", got, want)
	}
}
