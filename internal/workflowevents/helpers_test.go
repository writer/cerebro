package workflowevents

import (
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestFindingStatusPrunesGraph(t *testing.T) {
	tests := []struct {
		status string
		source string
		want   bool
	}{
		{"resolved", FindingStatusSourceStaleEvaluation, true},
		{"RESOLVED", "STALE_RULE_EVALUATION", true},
		{"  resolved  ", "  stale_rule_evaluation  ", true},
		{"resolved", "manual", false},
		{"open", FindingStatusSourceStaleEvaluation, false},
		{"", FindingStatusSourceStaleEvaluation, false},
		{"resolved", "", false},
	}
	for _, tt := range tests {
		got := FindingStatusPrunesGraph(tt.status, tt.source)
		if got != tt.want {
			t.Errorf("FindingStatusPrunesGraph(%q, %q) = %v, want %v", tt.status, tt.source, got, tt.want)
		}
	}
}

func TestLegacyFindingStatusPrunesGraph(t *testing.T) {
	tests := []struct {
		name       string
		status     string
		source     string
		reason     string
		decisionID string
		outcomeID  string
		want       bool
	}{
		{
			name:   "classic stale resolution",
			status: "resolved", source: "", reason: FindingStatusReasonNoLongerEmitted,
			decisionID: "", outcomeID: "", want: true,
		},
		{
			name:   "case insensitive",
			status: "RESOLVED", source: "", reason: "No longer emitted by latest rule evaluation.",
			decisionID: "", outcomeID: "", want: true,
		},
		{
			name:   "has source so not legacy",
			status: "resolved", source: "manual", reason: FindingStatusReasonNoLongerEmitted,
			decisionID: "", outcomeID: "", want: false,
		},
		{
			name:   "has decision id",
			status: "resolved", source: "", reason: FindingStatusReasonNoLongerEmitted,
			decisionID: "d-1", outcomeID: "", want: false,
		},
		{
			name:   "has outcome id",
			status: "resolved", source: "", reason: FindingStatusReasonNoLongerEmitted,
			decisionID: "", outcomeID: "o-1", want: false,
		},
		{
			name:   "wrong reason",
			status: "resolved", source: "", reason: "other reason",
			decisionID: "", outcomeID: "", want: false,
		},
		{
			name:   "wrong status",
			status: "open", source: "", reason: FindingStatusReasonNoLongerEmitted,
			decisionID: "", outcomeID: "", want: false,
		},
	}
	for _, tt := range tests {
		got := LegacyFindingStatusPrunesGraph(tt.status, tt.source, tt.reason, tt.decisionID, tt.outcomeID)
		if got != tt.want {
			t.Errorf("LegacyFindingStatusPrunesGraph(%s) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestCanonicalWorkflowIDSynthetic(t *testing.T) {
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	id := CanonicalWorkflowID("writer", "decision", "", "triage", []string{"f-1"}, at)
	if id == "" {
		t.Fatal("CanonicalWorkflowID(empty provided) should not be empty")
	}
	if id[:14] != "urn:cerebro:wr" {
		t.Fatalf("CanonicalWorkflowID prefix = %q, want urn:cerebro:writer:...", id[:14])
	}
	id2 := CanonicalWorkflowID("writer", "decision", "", "triage", []string{"f-1"}, at)
	if id != id2 {
		t.Fatalf("CanonicalWorkflowID not stable: %q != %q", id, id2)
	}
}

func TestCanonicalWorkflowIDReplacesSpecialCharsInValue(t *testing.T) {
	id := CanonicalWorkflowID("t", "action", "my action/v1", "", nil, time.Time{})
	// The value portion is after "urn:cerebro:t:action:"
	prefix := "urn:cerebro:t:action:"
	if len(id) <= len(prefix) {
		t.Fatalf("CanonicalWorkflowID too short: %q", id)
	}
	valuePart := id[len(prefix):]
	for _, ch := range []string{" ", "/", ".", ":"} {
		for i := range valuePart {
			if string(valuePart[i]) == ch {
				t.Errorf("CanonicalWorkflowID value part contains %q: %s", ch, valuePart)
			}
		}
	}
}

func TestSchemaForKind(t *testing.T) {
	tests := []struct {
		kind string
		want string
	}{
		{EventKindKnowledgeDecisionRecorded, SchemaKnowledgeDecisionRecorded},
		{EventKindKnowledgeActionRecorded, SchemaKnowledgeActionRecorded},
		{EventKindKnowledgeOutcomeRecorded, SchemaKnowledgeOutcomeRecorded},
		{EventKindFindingRecorded, SchemaFindingRecorded},
		{EventKindFindingNoteAdded, SchemaFindingNoteAdded},
		{EventKindFindingTicketLinked, SchemaFindingTicketLinked},
		{EventKindFindingExternalRefLinked, SchemaFindingExternalRefLinked},
		{EventKindFindingStatusChanged, SchemaFindingStatusChanged},
		{EventKindFindingTombstoned, SchemaFindingTombstoned},
		{"unknown.kind", ""},
		{"", ""},
	}
	for _, tt := range tests {
		got := schemaForKind(tt.kind)
		if got != tt.want {
			t.Errorf("schemaForKind(%q) = %q, want %q", tt.kind, got, tt.want)
		}
	}
}

func TestSchemaForKindTrimsWhitespace(t *testing.T) {
	got := schemaForKind("  " + EventKindFindingRecorded + "  ")
	if got != SchemaFindingRecorded {
		t.Fatalf("schemaForKind(trimmed) = %q, want %q", got, SchemaFindingRecorded)
	}
}

func TestSetDefaultAttributeSkipsExisting(t *testing.T) {
	attrs := map[string]string{"key": "existing"}
	setDefaultAttribute(attrs, "key", "new")
	if attrs["key"] != "existing" {
		t.Fatalf("setDefaultAttribute overwrote existing: %q", attrs["key"])
	}
}

func TestSetDefaultAttributeSetsWhenEmpty(t *testing.T) {
	attrs := map[string]string{}
	setDefaultAttribute(attrs, "key", "value")
	if attrs["key"] != "value" {
		t.Fatalf("setDefaultAttribute did not set: %q", attrs["key"])
	}
}

func TestSetDefaultAttributeSkipsEmptyValue(t *testing.T) {
	attrs := map[string]string{}
	setDefaultAttribute(attrs, "key", "  ")
	if _, ok := attrs["key"]; ok {
		t.Fatal("setDefaultAttribute set empty value")
	}
}

func TestIsSharedEnvelopeEventNilReturnsFalse(t *testing.T) {
	if IsSharedEnvelopeEvent(nil) {
		t.Fatal("IsSharedEnvelopeEvent(nil) should be false")
	}
}

func TestIsSharedEnvelopeEventEmptyPayloadReturnsFalse(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Kind: "workflow.v1.test", Attributes: map[string]string{"envelope_version": "1"}}
	if IsSharedEnvelopeEvent(event) {
		t.Fatal("IsSharedEnvelopeEvent(no payload) should be false")
	}
}

func TestIsSharedEnvelopeEventWrongKindReturnsFalse(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Kind: "other.kind", Payload: []byte("data"), Attributes: map[string]string{"envelope_version": "1"}}
	if IsSharedEnvelopeEvent(event) {
		t.Fatal("IsSharedEnvelopeEvent(wrong kind) should be false")
	}
}

func TestIsSharedEnvelopeEventWrongVersionReturnsFalse(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Kind: "workflow.v1.test", Payload: []byte("data"), Attributes: map[string]string{"envelope_version": "2"}}
	if IsSharedEnvelopeEvent(event) {
		t.Fatal("IsSharedEnvelopeEvent(wrong version) should be false")
	}
}

func TestIsSharedEnvelopeEventValidReturnsTrue(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Kind: "workflow.v1.test", Payload: []byte("data"), Attributes: map[string]string{"envelope_version": "1"}}
	if !IsSharedEnvelopeEvent(event) {
		t.Fatal("IsSharedEnvelopeEvent(valid) should be true")
	}
}

func TestSlug(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"hello world", "hello-world"},
		{"some_value", "some-value"},
		{"path/to/thing", "path-to-thing"},
		{"key:value", "key-value"},
		{"dots.in.name", "dots-in-name"},
		{"  trimmed  ", "trimmed"},
		{"", ""},
	}
	for _, tt := range tests {
		got := slug(tt.input)
		if got != tt.want {
			t.Errorf("slug(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestShortHashStable(t *testing.T) {
	h1 := shortHash("test-value")
	h2 := shortHash("test-value")
	if h1 != h2 {
		t.Fatalf("shortHash not stable: %q != %q", h1, h2)
	}
	if len(h1) != 16 {
		t.Fatalf("shortHash length = %d, want 16", len(h1))
	}
}

func TestShortHashDistinct(t *testing.T) {
	h1 := shortHash("value-a")
	h2 := shortHash("value-b")
	if h1 == h2 {
		t.Fatal("shortHash should produce distinct values for distinct inputs")
	}
}

func TestEventIDStable(t *testing.T) {
	id1 := eventID("tenant", "kind", "primary")
	id2 := eventID("tenant", "kind", "primary")
	if id1 != id2 {
		t.Fatalf("eventID not stable: %q != %q", id1, id2)
	}
	if id1[:14] != "urn:cerebro:te" {
		t.Fatalf("eventID prefix unexpected: %q", id1)
	}
}

func TestParseEventTimeValidRFC3339(t *testing.T) {
	parsed, err := parseEventTime("2026-01-15T10:00:00Z")
	if err != nil {
		t.Fatalf("parseEventTime() error = %v", err)
	}
	if parsed.Year() != 2026 || parsed.Month() != 1 || parsed.Day() != 15 {
		t.Fatalf("parseEventTime() = %v, want 2026-01-15", parsed)
	}
}

func TestParseEventTimeEmptyReturnsNow(t *testing.T) {
	before := time.Now().UTC().Add(-time.Second)
	parsed, err := parseEventTime("")
	if err != nil {
		t.Fatalf("parseEventTime(\"\") error = %v", err)
	}
	if parsed.Before(before) {
		t.Fatalf("parseEventTime(\"\") = %v, want >= %v", parsed, before)
	}
}

func TestParseEventTimeInvalidReturnsError(t *testing.T) {
	_, err := parseEventTime("not-a-date")
	if err == nil {
		t.Fatal("parseEventTime(invalid) should error")
	}
}

func TestAvroReaderBoolean(t *testing.T) {
	reader := newAvroReader([]byte{0, 1})
	val, err := reader.boolean()
	if err != nil || val != false {
		t.Fatalf("boolean(0) = %v, %v, want false, nil", val, err)
	}
	val, err = reader.boolean()
	if err != nil || val != true {
		t.Fatalf("boolean(1) = %v, %v, want true, nil", val, err)
	}
}

func TestAvroReaderBooleanInvalidValue(t *testing.T) {
	reader := newAvroReader([]byte{2})
	_, err := reader.boolean()
	if err == nil {
		t.Fatal("boolean(2) should error")
	}
}

func TestAvroReaderBooleanEOF(t *testing.T) {
	reader := newAvroReader([]byte{})
	_, err := reader.boolean()
	if err == nil {
		t.Fatal("boolean(empty) should error")
	}
}

func TestAvroReaderLongSmallValues(t *testing.T) {
	tests := []struct {
		data []byte
		want int64
	}{
		{[]byte{0}, 0},
		{[]byte{2}, 1},
		{[]byte{1}, -1},
		{[]byte{4}, 2},
		{[]byte{3}, -2},
	}
	for _, tt := range tests {
		reader := newAvroReader(tt.data)
		got, err := reader.long()
		if err != nil {
			t.Fatalf("long(%v) error = %v", tt.data, err)
		}
		if got != tt.want {
			t.Errorf("long(%v) = %d, want %d", tt.data, got, tt.want)
		}
	}
}

func TestAvroReaderLongEOF(t *testing.T) {
	reader := newAvroReader([]byte{})
	_, err := reader.long()
	if err == nil {
		t.Fatal("long(empty) should error")
	}
}

func TestAvroReaderStringRoundTrip(t *testing.T) {
	data := []byte{10, 'h', 'e', 'l', 'l', 'o'}
	reader := newAvroReader(data)
	got, err := reader.string()
	if err != nil {
		t.Fatalf("string() error = %v", err)
	}
	if got != "hello" {
		t.Fatalf("string() = %q, want hello", got)
	}
}

func TestAvroReaderNullableStringNull(t *testing.T) {
	reader := newAvroReader([]byte{0})
	got, err := reader.nullableString()
	if err != nil {
		t.Fatalf("nullableString(null) error = %v", err)
	}
	if got != "" {
		t.Fatalf("nullableString(null) = %q, want empty", got)
	}
}

func TestAvroReaderNullableStringPresent(t *testing.T) {
	data := []byte{2, 6, 'a', 'b', 'c'}
	reader := newAvroReader(data)
	got, err := reader.nullableString()
	if err != nil {
		t.Fatalf("nullableString(present) error = %v", err)
	}
	if got != "abc" {
		t.Fatalf("nullableString(present) = %q, want abc", got)
	}
}

func TestAvroReaderNullableStringInvalidIndex(t *testing.T) {
	reader := newAvroReader([]byte{4})
	_, err := reader.nullableString()
	if err == nil {
		t.Fatal("nullableString(index=2) should error")
	}
}

func TestAvroReaderRemaining(t *testing.T) {
	reader := newAvroReader([]byte{1, 2, 3})
	if reader.remaining() != 3 {
		t.Fatalf("remaining() = %d, want 3", reader.remaining())
	}
	reader.pos = 2
	if reader.remaining() != 1 {
		t.Fatalf("remaining() = %d, want 1", reader.remaining())
	}
}

func TestAvroReaderIntegerOutOfRange(t *testing.T) {
	reader := newAvroReader([]byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x04})
	_, err := reader.integer()
	if err == nil {
		t.Fatal("integer(large) should error for out-of-range value")
	}
}

func TestAvroReaderDoubleEOF(t *testing.T) {
	reader := newAvroReader([]byte{1, 2, 3})
	_, err := reader.double()
	if err == nil {
		t.Fatal("double(short) should error")
	}
}

func TestAvroReaderBytesNegativeLength(t *testing.T) {
	reader := newAvroReader([]byte{1})
	_, err := reader.bytesValue()
	if err == nil {
		t.Fatal("bytesValue(negative length) should error")
	}
}

func TestAvroReaderStringArrayEmpty(t *testing.T) {
	reader := newAvroReader([]byte{0})
	got, err := reader.stringArray()
	if err != nil {
		t.Fatalf("stringArray(empty) error = %v", err)
	}
	if got != nil {
		t.Fatalf("stringArray(empty) = %v, want nil", got)
	}
}

func TestAvroReaderNullableDoubleNull(t *testing.T) {
	reader := newAvroReader([]byte{0})
	got, err := reader.nullableDouble()
	if err != nil {
		t.Fatalf("nullableDouble(null) error = %v", err)
	}
	if got != 0 {
		t.Fatalf("nullableDouble(null) = %f, want 0", got)
	}
}

func TestAvroReaderNullableDoubleInvalidIndex(t *testing.T) {
	reader := newAvroReader([]byte{4})
	_, err := reader.nullableDouble()
	if err == nil {
		t.Fatal("nullableDouble(index=2) should error")
	}
}

func TestAvroReaderMetadataValueVariants(t *testing.T) {
	reader := newAvroReader([]byte{0})
	got, err := reader.metadataValue()
	if err != nil {
		t.Fatalf("metadataValue(null) error = %v", err)
	}
	if got != nil {
		t.Fatalf("metadataValue(null) = %v, want nil", got)
	}
}

func TestAvroReaderMetadataValueInvalidIndex(t *testing.T) {
	reader := newAvroReader([]byte{10})
	_, err := reader.metadataValue()
	if err == nil {
		t.Fatal("metadataValue(index=5) should error")
	}
}
