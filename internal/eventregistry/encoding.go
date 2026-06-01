package eventregistry

import (
	"crypto/rand"
	"fmt"
	"time"
)

const EnvelopeVersion = 1

type EncodeOptions struct {
	EventID        string
	EmittedAt      time.Time
	Attributes     map[string]string
	Environment    string
	Cloud          string
	TenantType     string
	TraceID        string
	RequestID      string
	SessionID      string
	ThreadID       string
	OrgID          string
	TeamID         string
	UserID         string
	APIKeyID       string
	BillingGroupID string
}

type EncodedEvent struct {
	Subject       string
	Version       int
	EventID       string
	EmittedAtMS   int64
	EnvelopeBytes []byte
	Attributes    map[string]string
}

type Encoder struct{}

func (Encoder) Encode(event Event, options EncodeOptions) (EncodedEvent, error) {
	payloadBytes, err := event.EncodeAvro()
	if err != nil {
		return EncodedEvent{}, err
	}
	eventID := options.EventID
	if eventID == "" {
		eventID, err = uuidV4()
		if err != nil {
			return EncodedEvent{}, err
		}
	}
	emittedAt := options.EmittedAt
	if emittedAt.IsZero() {
		emittedAt = time.Now().UTC()
	}
	emittedAtMS := emittedAt.UTC().UnixMilli()
	envelopeBytes, err := encodeEnvelope(event, eventID, emittedAtMS, payloadBytes, options)
	if err != nil {
		return EncodedEvent{}, err
	}
	attrs := map[string]string{
		"event_type":         event.Subject(),
		"event_version":      fmt.Sprintf("%d", event.Version()),
		"schema_fingerprint": event.SchemaFingerprint(),
		"event_id":           eventID,
		"envelope_version":   fmt.Sprintf("%d", EnvelopeVersion),
	}
	for key, value := range options.Attributes {
		if _, exists := attrs[key]; !exists {
			attrs[key] = value
		}
	}
	return EncodedEvent{
		Subject:       event.Subject(),
		Version:       event.Version(),
		EventID:       eventID,
		EmittedAtMS:   emittedAtMS,
		EnvelopeBytes: envelopeBytes,
		Attributes:    attrs,
	}, nil
}

func encodeEnvelope(event Event, eventID string, emittedAtMS int64, payloadBytes []byte, options EncodeOptions) ([]byte, error) {
	w := newAvroWriter()
	w.string(event.Subject())
	w.integer(event.Version())
	w.string(eventID)
	w.long(emittedAtMS)
	w.nullableString(nilIfEmpty(options.Attributes["source_service"]))
	w.nullableString(nilIfEmpty(options.Environment))
	w.nullableString(nilIfEmpty(options.Cloud))
	w.nullableString(nilIfEmpty(options.TenantType))
	w.nullableString(nilIfEmpty(options.TraceID))
	w.nullableString(nilIfEmpty(options.RequestID))
	w.nullableString(nilIfEmpty(options.SessionID))
	w.nullableString(nilIfEmpty(options.ThreadID))
	w.nullableString(nilIfEmpty(options.OrgID))
	w.nullableString(nilIfEmpty(options.TeamID))
	w.nullableString(nilIfEmpty(options.UserID))
	w.nullableString(nilIfEmpty(options.APIKeyID))
	w.nullableString(nilIfEmpty(options.BillingGroupID))
	w.bytesValue(payloadBytes)
	return w.bytes()
}

func nilIfEmpty(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func uuidV4() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate event id: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
