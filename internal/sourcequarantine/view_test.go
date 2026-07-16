package sourcequarantine

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

func TestParseListFilter(t *testing.T) {
	tests := []struct {
		limitRaw  string
		stateRaw  string
		wantLimit uint32
		wantState string
		wantValid bool
	}{
		{wantLimit: 50, wantState: "pending", wantValid: true},
		{limitRaw: "2", stateRaw: "resolved", wantLimit: 2, wantState: "resolved", wantValid: true},
		{limitRaw: "0"},
		{limitRaw: "501"},
		{limitRaw: "bad"},
		{stateRaw: "captured"},
	}
	for _, test := range tests {
		limit, state, valid := ParseListFilter(test.limitRaw, test.stateRaw)
		if limit != test.wantLimit || state != test.wantState || valid != test.wantValid {
			t.Fatalf("ParseListFilter(%q, %q) = %d, %q, %t; want %d, %q, %t", test.limitRaw, test.stateRaw, limit, state, valid, test.wantLimit, test.wantState, test.wantValid)
		}
	}
}

func TestFromDurableReturnsProofWithoutStoredPayloadFields(t *testing.T) {
	observedAt := time.Date(2026, 7, 15, 10, 0, 0, 0, time.UTC)
	view := FromDurable(ports.SourceRuntimeQuarantineRecord{
		ID:                       "quarantine-1",
		RuntimeID:                "runtime-1",
		SourceID:                 "directory",
		TenantID:                 "writer",
		EventID:                  "event-1",
		EventKind:                "directory.identity",
		EventSHA256:              "sha256:event",
		FailureCategory:          "missing_required_attribute",
		FailureField:             "resource_id",
		State:                    "pending",
		OccurrenceCount:          2,
		FirstObservedAt:          observedAt,
		LastObservedAt:           observedAt,
		AdmissionABIVersion:      2,
		AdmissionContractsSHA256: "sha256:contracts",
		AdmissionResultSHA256:    "sha256:result",
	})
	body, err := json.Marshal(view)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if !strings.Contains(string(body), `"diagnostic":"Missing required attribute resource_id"`) {
		t.Fatalf("safe view = %s, want concrete diagnostic", body)
	}
	for _, forbidden := range []string{"payload", "event_json", "attributes"} {
		if strings.Contains(string(body), forbidden) {
			t.Fatalf("safe view leaked %q: %s", forbidden, body)
		}
	}
}

func TestFromLegacyReturnsTheStoredDiagnostic(t *testing.T) {
	runtime := legacyRuntime{
		id:       "runtime-1",
		sourceID: "directory",
		tenantID: "writer",
		config: map[string]string{
			legacyFailureCategoryKey: "missing_required_attribute",
			legacyFieldKey:           "resource_id",
			legacyRetryableKey:       "true",
			legacyEventIDKey:         "event-1",
		},
	}
	view, ok := FromLegacy(runtime)
	if !ok {
		t.Fatal("FromLegacy() did not return the stored diagnostic")
	}
	if view.RuntimeID != "runtime-1" || view.Status != "terminal" || !view.Retryable {
		t.Fatalf("FromLegacy() = %#v", view)
	}
	if len(view.Fields) != 1 || view.Fields[0] != "resource_id" {
		t.Fatalf("FromLegacy().Fields = %v", view.Fields)
	}
}

type legacyRuntime struct {
	id       string
	sourceID string
	tenantID string
	config   map[string]string
}

func (r legacyRuntime) GetId() string                { return r.id }
func (r legacyRuntime) GetSourceId() string          { return r.sourceID }
func (r legacyRuntime) GetTenantId() string          { return r.tenantID }
func (r legacyRuntime) GetConfig() map[string]string { return r.config }
