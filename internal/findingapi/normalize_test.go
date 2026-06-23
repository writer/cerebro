package findingapi

import (
	"testing"
	"time"

	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/ports"
)

func TestNormalizeStatusValidValues(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"open", "open"},
		{"OPEN", "open"},
		{"  Open  ", "open"},
		{"finding_status_open", "open"},
		{"resolved", "resolved"},
		{"RESOLVED", "resolved"},
		{"finding_status_resolved", "resolved"},
		{"suppressed", "suppressed"},
		{"SUPPRESSED", "suppressed"},
		{"finding_status_suppressed", "suppressed"},
	}
	for _, tt := range tests {
		got, err := NormalizeStatus(tt.input)
		if err != nil {
			t.Errorf("NormalizeStatus(%q) error = %v", tt.input, err)
			continue
		}
		if got != tt.want {
			t.Errorf("NormalizeStatus(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestNormalizeStatusInvalidValues(t *testing.T) {
	for _, input := range []string{"", "invalid", "closed", "pending"} {
		_, err := NormalizeStatus(input)
		if err == nil {
			t.Errorf("NormalizeStatus(%q) should return error", input)
		}
	}
}

func TestValidateOptionalStatusEmptyPasses(t *testing.T) {
	if err := ValidateOptionalStatus(""); err != nil {
		t.Fatalf("ValidateOptionalStatus(\"\") error = %v", err)
	}
	if err := ValidateOptionalStatus("  "); err != nil {
		t.Fatalf("ValidateOptionalStatus(whitespace) error = %v", err)
	}
}

func TestValidateOptionalStatusValidPasses(t *testing.T) {
	if err := ValidateOptionalStatus("open"); err != nil {
		t.Fatalf("ValidateOptionalStatus(open) error = %v", err)
	}
}

func TestValidateOptionalStatusInvalidFails(t *testing.T) {
	if err := ValidateOptionalStatus("invalid"); err == nil {
		t.Fatal("ValidateOptionalStatus(invalid) should return error")
	}
}

func TestStatusUpdateOptionsWithExpectedStatus(t *testing.T) {
	before := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	opts, err := StatusUpdateOptions("open", before, "manual")
	if err != nil {
		t.Fatalf("StatusUpdateOptions() error = %v", err)
	}
	if opts.ExpectedStatus != "open" {
		t.Fatalf("ExpectedStatus = %q, want open", opts.ExpectedStatus)
	}
	if !opts.LastObservedBefore.Equal(before) {
		t.Fatalf("LastObservedBefore = %v, want %v", opts.LastObservedBefore, before)
	}
	if opts.Source != "manual" {
		t.Fatalf("Source = %q, want manual", opts.Source)
	}
}

func TestStatusUpdateOptionsWithoutExpectedStatus(t *testing.T) {
	opts, err := StatusUpdateOptions("", time.Time{}, "")
	if err != nil {
		t.Fatalf("StatusUpdateOptions() error = %v", err)
	}
	if opts.ExpectedStatus != "" {
		t.Fatalf("ExpectedStatus = %q, want empty", opts.ExpectedStatus)
	}
}

func TestStatusUpdateOptionsInvalidExpectedStatus(t *testing.T) {
	_, err := StatusUpdateOptions("invalid", time.Time{}, "")
	if err == nil {
		t.Fatal("StatusUpdateOptions(invalid) should return error")
	}
}

func TestExternalRefMessagesFiltersIncompleteRefs(t *testing.T) {
	refs := []ports.FindingExternalRef{
		{System: "jira", Kind: "ticket", ExternalID: "ENG-1", URL: "https://jira.example.com/ENG-1"},
		{System: "", Kind: "ticket", ExternalID: "ENG-2"},
		{System: "jira", Kind: "", ExternalID: "ENG-3"},
		{System: "jira", Kind: "ticket", ExternalID: ""},
	}
	messages := ExternalRefMessages(refs)
	if len(messages) != 1 {
		t.Fatalf("ExternalRefMessages() len = %d, want 1", len(messages))
	}
	if messages[0].GetSystem() != "jira" || messages[0].GetExternalId() != "ENG-1" {
		t.Fatalf("message = %+v, want jira/ENG-1", messages[0])
	}
}

func TestExternalRefMessagesReturnsNilForEmpty(t *testing.T) {
	if messages := ExternalRefMessages(nil); messages != nil {
		t.Fatalf("ExternalRefMessages(nil) = %v, want nil", messages)
	}
	if messages := ExternalRefMessages([]ports.FindingExternalRef{}); messages != nil {
		t.Fatalf("ExternalRefMessages(empty) = %v, want nil", messages)
	}
}

func TestExternalRefMessagesTrimsWhitespace(t *testing.T) {
	refs := []ports.FindingExternalRef{
		{System: " jira ", Kind: " ticket ", ExternalID: " ENG-1 ", URL: " https://url "},
	}
	messages := ExternalRefMessages(refs)
	if len(messages) != 1 {
		t.Fatalf("len = %d, want 1", len(messages))
	}
	if messages[0].GetSystem() != "jira" {
		t.Fatalf("System = %q, want jira", messages[0].GetSystem())
	}
	if messages[0].GetUrl() != "https://url" {
		t.Fatalf("URL = %q, want trimmed", messages[0].GetUrl())
	}
}

func TestExternalRefMessagesIncludesObservedAt(t *testing.T) {
	ts := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	refs := []ports.FindingExternalRef{
		{System: "jira", Kind: "ticket", ExternalID: "ENG-1", ObservedAt: ts},
	}
	messages := ExternalRefMessages(refs)
	if len(messages) != 1 {
		t.Fatalf("len = %d, want 1", len(messages))
	}
	if messages[0].GetObservedAt() == nil {
		t.Fatal("ObservedAt should not be nil")
	}
	if !messages[0].GetObservedAt().AsTime().Equal(ts) {
		t.Fatalf("ObservedAt = %v, want %v", messages[0].GetObservedAt().AsTime(), ts)
	}
}

func TestExternalRefFromLinkRequestNil(t *testing.T) {
	ref := ExternalRefFromLinkRequest(nil)
	if ref.System != "" || ref.Kind != "" || ref.ExternalID != "" {
		t.Fatalf("ExternalRefFromLinkRequest(nil) = %+v, want zero", ref)
	}
}

func TestNewMCPActionProposal(t *testing.T) {
	args := MCPArguments{
		"status":  "resolved",
		"reason":  "fixed",
		"missing": nil,
	}
	proposal := NewMCPActionProposal(args, "finding-1", "update_status")
	if proposal["dry_run"] != true {
		t.Fatalf("dry_run = %v, want true", proposal["dry_run"])
	}
	if proposal["finding_id"] != "finding-1" {
		t.Fatalf("finding_id = %v, want finding-1", proposal["finding_id"])
	}
	if proposal["action"] != "update_status" {
		t.Fatalf("action = %v, want update_status", proposal["action"])
	}
	if proposal["status"] != "resolved" {
		t.Fatalf("status = %v, want resolved", proposal["status"])
	}
	if proposal["reason"] != "fixed" {
		t.Fatalf("reason = %v, want fixed", proposal["reason"])
	}
	if proposal["approval_required"] != true {
		t.Fatalf("approval_required = %v, want true", proposal["approval_required"])
	}
}

func TestMCPStringArgHandlesTypes(t *testing.T) {
	tests := []struct {
		name string
		args MCPArguments
		key  string
		want string
	}{
		{"string", MCPArguments{"k": "hello"}, "k", "hello"},
		{"nil", MCPArguments{"k": nil}, "k", ""},
		{"missing", MCPArguments{}, "k", ""},
		{"int", MCPArguments{"k": 42}, "k", "42"},
		{"trimmed", MCPArguments{"k": "  val  "}, "k", "val"},
	}
	for _, tt := range tests {
		got := mcpStringArg(tt.args, tt.key)
		if got != tt.want {
			t.Errorf("mcpStringArg(%s) = %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestMCPActionOutputPropertiesContainsExpectedKeys(t *testing.T) {
	props := MCPActionOutputProperties()
	for _, key := range []string{"dry_run", "finding_id", "action", "status", "graph_action", "target", "approval_required"} {
		if _, ok := props[key]; !ok {
			t.Errorf("MCPActionOutputProperties missing key %q", key)
		}
	}
}

func TestApplyMCPGraphActionProposalNonGraphActionIsNoop(t *testing.T) {
	proposal := MCPActionProposalPayload{"finding_id": "f1"}
	err := ApplyMCPGraphActionProposal(proposal, &ports.FindingRecord{}, "add_note", MCPArguments{}, "write")
	if err != nil {
		t.Fatalf("ApplyMCPGraphActionProposal(add_note) error = %v", err)
	}
	if _, ok := proposal["endpoint"]; ok {
		t.Fatal("endpoint should not be set for non-graph actions")
	}
}

func TestNormalizeStatusHandlesInvalidRequestError(t *testing.T) {
	_, err := NormalizeStatus("bogus")
	if err == nil {
		t.Fatal("NormalizeStatus(bogus) should error")
	}
	if !isInvalidRequest(err) {
		t.Fatalf("error = %v, want ErrInvalidRequest wrapped", err)
	}
}

func isInvalidRequest(err error) bool {
	return err != nil && err.Error() != "" && containsString(err.Error(), findings.ErrInvalidRequest.Error())
}

func containsString(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && findSubstring(s, sub))
}

func findSubstring(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
