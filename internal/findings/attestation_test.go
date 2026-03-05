package findings

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/policy"
)

func TestParseEd25519PrivateKey(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	seedKey, err := parseEd25519PrivateKey(base64.StdEncoding.EncodeToString(priv.Seed()))
	if err != nil {
		t.Fatalf("seed parse failed: %v", err)
	}
	if !strings.EqualFold(base64.StdEncoding.EncodeToString(seedKey.Public().(ed25519.PublicKey)), base64.StdEncoding.EncodeToString(pub)) {
		t.Fatalf("seed parsed key does not match generated public key")
	}

	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal pkcs8 failed: %v", err)
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	parsed, err := parseEd25519PrivateKey(string(pemKey))
	if err != nil {
		t.Fatalf("pem parse failed: %v", err)
	}
	if !strings.EqualFold(base64.StdEncoding.EncodeToString(parsed.Public().(ed25519.PublicKey)), base64.StdEncoding.EncodeToString(pub)) {
		t.Fatalf("pem parsed key does not match generated public key")
	}
}

func TestTransparencyDevAttestorAttest(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	var seenPayloadHash string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("unexpected method %s", r.Method)
		}
		var req transparencyLogAppendRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request failed: %v", err)
		}
		seenPayloadHash = req.StatementHash
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"entry_id":"entry-1","log_index":12,"integrated_time":"2026-02-27T10:00:00Z","checkpoint":"cp-1"}`))
	}))
	defer server.Close()

	attestor, err := NewTransparencyDevAttestor(TransparencyDevAttestorConfig{
		SigningKey: base64.StdEncoding.EncodeToString(priv),
		LogURL:     server.URL,
		Timeout:    2 * time.Second,
	})
	if err != nil {
		t.Fatalf("failed to create attestor: %v", err)
	}

	result, err := attestor.Attest(context.Background(), FindingAttestationEvent{
		Type:         FindingAttestationCreated,
		ObservedAt:   time.Date(2026, time.February, 27, 10, 15, 0, 0, time.UTC),
		PreviousHash: "",
		Finding: FindingAttestationSnapshot{
			ID:           "finding-1",
			PolicyID:     "policy-1",
			PolicyName:   "Policy",
			Severity:     "high",
			Status:       "OPEN",
			ResourceID:   "res-1",
			ResourceType: "aws_s3_buckets",
			Resource: map[string]interface{}{
				"name": "bucket-1",
			},
			FirstSeen: time.Date(2026, time.February, 27, 10, 15, 0, 0, time.UTC),
			LastSeen:  time.Date(2026, time.February, 27, 10, 15, 0, 0, time.UTC),
		},
	})
	if err != nil {
		t.Fatalf("attest failed: %v", err)
	}
	if result.StatementHash == "" {
		t.Fatalf("expected statement hash")
	}
	if result.StatementHash != seenPayloadHash {
		t.Fatalf("statement hash mismatch with log payload hash")
	}
	if result.LogEntryID != "entry-1" {
		t.Fatalf("expected log entry id entry-1, got %s", result.LogEntryID)
	}

	var envelope dsseEnvelope
	if err := json.Unmarshal([]byte(result.EnvelopeJSON), &envelope); err != nil {
		t.Fatalf("unmarshal envelope failed: %v", err)
	}
	if len(envelope.Signatures) != 1 {
		t.Fatalf("expected one signature")
	}

	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		t.Fatalf("decode payload failed: %v", err)
	}
	sig, err := base64.StdEncoding.DecodeString(envelope.Signatures[0].Sig)
	if err != nil {
		t.Fatalf("decode signature failed: %v", err)
	}
	if !ed25519.Verify(priv.Public().(ed25519.PublicKey), dssePAE(envelope.PayloadType, payload), sig) {
		t.Fatalf("dsse signature verification failed")
	}

	hash := sha256.Sum256(payload)
	expectedHash := "sha256:" + hex.EncodeToString(hash[:])
	if result.StatementHash != expectedHash {
		t.Fatalf("expected statement hash %s, got %s", expectedHash, result.StatementHash)
	}
}

func TestStoreAttestationChain(t *testing.T) {
	store := NewStore()
	attestor := &recordingAttestor{}
	store.SetAttestor(attestor, false)

	pf := policy.Finding{
		ID:       "finding-1",
		PolicyID: "policy-1",
		Severity: "high",
		Resource: map[string]interface{}{"id": "res-1"},
	}

	f := store.Upsert(context.Background(), pf)
	if len(f.Evidence) != 1 {
		t.Fatalf("expected 1 attestation evidence entry after create, got %d", len(f.Evidence))
	}
	firstHash := latestAttestationHash(f.Evidence)
	if firstHash == "" {
		t.Fatalf("expected first attestation hash")
	}
	if got := valueToString(f.Evidence[0].Data["event_type"]); got != string(FindingAttestationCreated) {
		t.Fatalf("expected event type %s, got %s", FindingAttestationCreated, got)
	}

	if !store.Resolve("finding-1") {
		t.Fatalf("resolve failed")
	}
	f = store.Upsert(context.Background(), pf)
	if len(f.Evidence) != 2 {
		t.Fatalf("expected 2 attestation evidence entries after reopen, got %d", len(f.Evidence))
	}
	if got := valueToString(f.Evidence[1].Data["event_type"]); got != string(FindingAttestationReopened) {
		t.Fatalf("expected event type %s, got %s", FindingAttestationReopened, got)
	}
	if got := valueToString(f.Evidence[1].Data["previous_hash"]); got != firstHash {
		t.Fatalf("expected previous hash %s, got %s", firstHash, got)
	}

	if len(attestor.events) != 2 {
		t.Fatalf("expected 2 attestation calls, got %d", len(attestor.events))
	}
	if attestor.events[1].PreviousHash != firstHash {
		t.Fatalf("expected second event previous hash %s, got %s", firstHash, attestor.events[1].PreviousHash)
	}
}

func TestStoreAttestationReobservedToggle(t *testing.T) {
	store := NewStore()
	attestor := &recordingAttestor{}
	store.SetAttestor(attestor, true)

	pf := policy.Finding{ID: "finding-1", PolicyID: "policy-1", Severity: "medium", Resource: map[string]interface{}{"id": "res-1"}}
	store.Upsert(context.Background(), pf)
	f := store.Upsert(context.Background(), pf)

	if len(f.Evidence) != 2 {
		t.Fatalf("expected 2 evidence entries with reobserved enabled, got %d", len(f.Evidence))
	}
	if got := valueToString(f.Evidence[1].Data["event_type"]); got != string(FindingAttestationReobserved) {
		t.Fatalf("expected reobserved event, got %s", got)
	}
}

type recordingAttestor struct {
	mu     sync.Mutex
	events []FindingAttestationEvent
}

func (r *recordingAttestor) Attest(_ context.Context, event FindingAttestationEvent) (*FindingAttestationResult, error) {
	r.mu.Lock()
	r.events = append(r.events, event)
	r.mu.Unlock()

	digest := sha256.Sum256([]byte(string(event.Type) + "|" + event.Finding.ID + "|" + event.PreviousHash + "|" + event.ObservedAt.UTC().Format(time.RFC3339Nano)))
	return &FindingAttestationResult{
		Schema:         attestationStatementSchema,
		EventType:      event.Type,
		ObservedAt:     event.ObservedAt.UTC(),
		PreviousHash:   event.PreviousHash,
		StatementHash:  "sha256:" + hex.EncodeToString(digest[:]),
		PayloadType:    attestationPayloadTypeInToto,
		SignatureKeyID: "test-key",
		EnvelopeJSON:   `{"payloadType":"application/vnd.in-toto+json","payload":"","signatures":[]}`,
		PublicKey:      "test-pub",
	}, nil
}
