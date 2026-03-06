package findings

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	AttestationEvidenceType            = "attestation_chain"
	attestationPayloadTypeInToto       = "application/vnd.in-toto+json"
	attestationInTotoStatementType     = "https://in-toto.io/Statement/v1"
	attestationFindingPredicateType    = "https://github.com/evalops/cerebro/attestation/finding/v1"
	attestationStatementSchema         = "cerebro.finding_attestation.v1"
	attestationUploadKind              = "cerebro.dsse.attestation.v1"
	defaultAttestationHTTPTimeout      = 3 * time.Second
	defaultAttestationEvidenceStatusOK = "logged"
)

type FindingAttestationEventType string

const (
	FindingAttestationCreated    FindingAttestationEventType = "finding.created"
	FindingAttestationReopened   FindingAttestationEventType = "finding.reopened"
	FindingAttestationReobserved FindingAttestationEventType = "finding.reobserved"
)

type FindingAttestationSnapshot struct {
	ID             string
	PolicyID       string
	PolicyName     string
	ControlID      string
	Title          string
	Description    string
	Severity       string
	Status         string
	ResourceID     string
	ResourceName   string
	ResourceType   string
	RiskCategories []string
	Resource       map[string]interface{}
	FirstSeen      time.Time
	LastSeen       time.Time
}

type FindingAttestationEvent struct {
	Type         FindingAttestationEventType
	ObservedAt   time.Time
	PreviousHash string
	Finding      FindingAttestationSnapshot
}

type FindingAttestationResult struct {
	Schema         string
	EventType      FindingAttestationEventType
	ObservedAt     time.Time
	PreviousHash   string
	StatementHash  string
	PayloadType    string
	SignatureKeyID string
	EnvelopeJSON   string
	PublicKey      string
	LogURL         string
	LogEntryID     string
	LogIndex       *int64
	IntegratedTime *time.Time
	Checkpoint     string
	InclusionProof map[string]interface{}
	LogRawResponse map[string]interface{}
}

type FindingAttestor interface {
	Attest(ctx context.Context, event FindingAttestationEvent) (*FindingAttestationResult, error)
}

type TransparencyDevAttestorConfig struct {
	LogURL     string
	SigningKey string
	KeyID      string
	Timeout    time.Duration
	HTTPClient *http.Client
}

type TransparencyDevAttestor struct {
	logClient   transparencyLogClient
	privateKey  ed25519.PrivateKey
	publicKey   ed25519.PublicKey
	keyID       string
	httpTimeout time.Duration
}

func NewTransparencyDevAttestor(cfg TransparencyDevAttestorConfig) (*TransparencyDevAttestor, error) {
	privateKey, err := parseEd25519PrivateKey(cfg.SigningKey)
	if err != nil {
		return nil, fmt.Errorf("parse attestation signing key: %w", err)
	}

	pub := privateKey.Public().(ed25519.PublicKey)
	keyID := strings.TrimSpace(cfg.KeyID)
	if keyID == "" {
		keyID = deriveAttestationKeyID(pub)
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultAttestationHTTPTimeout
	}

	attestor := &TransparencyDevAttestor{
		privateKey:  privateKey,
		publicKey:   pub,
		keyID:       keyID,
		httpTimeout: timeout,
	}

	if strings.TrimSpace(cfg.LogURL) != "" {
		attestor.logClient = newTransparencyDevHTTPClient(strings.TrimSpace(cfg.LogURL), cfg.HTTPClient)
	}

	return attestor, nil
}

func (a *TransparencyDevAttestor) Attest(ctx context.Context, event FindingAttestationEvent) (*FindingAttestationResult, error) {
	if strings.TrimSpace(string(event.Type)) == "" {
		return nil, errors.New("missing attestation event type")
	}
	if strings.TrimSpace(event.Finding.ID) == "" {
		return nil, errors.New("missing finding id")
	}

	observedAt := event.ObservedAt.UTC()
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}

	statement, err := buildFindingAttestationStatement(event, observedAt)
	if err != nil {
		return nil, fmt.Errorf("build attestation statement: %w", err)
	}

	statementJSON, err := json.Marshal(statement)
	if err != nil {
		return nil, fmt.Errorf("marshal attestation statement: %w", err)
	}

	statementDigest := sha256.Sum256(statementJSON)
	statementHash := "sha256:" + hex.EncodeToString(statementDigest[:])

	envelope, err := createDSSEEnvelope(attestationPayloadTypeInToto, statementJSON, a.privateKey, a.keyID)
	if err != nil {
		return nil, fmt.Errorf("create dsse envelope: %w", err)
	}

	envelopeJSONBytes, err := json.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("marshal dsse envelope: %w", err)
	}

	publicKeyB64 := base64.StdEncoding.EncodeToString(a.publicKey)

	result := &FindingAttestationResult{
		Schema:         attestationStatementSchema,
		EventType:      event.Type,
		ObservedAt:     observedAt,
		PreviousHash:   strings.TrimSpace(event.PreviousHash),
		StatementHash:  statementHash,
		PayloadType:    attestationPayloadTypeInToto,
		SignatureKeyID: a.keyID,
		EnvelopeJSON:   string(envelopeJSONBytes),
		PublicKey:      publicKeyB64,
	}

	if a.logClient == nil {
		return result, nil
	}

	timeoutCtx := ctx
	if timeoutCtx == nil {
		timeoutCtx = context.Background()
	}
	if a.httpTimeout > 0 {
		var cancel context.CancelFunc
		timeoutCtx, cancel = context.WithTimeout(timeoutCtx, a.httpTimeout)
		defer cancel()
	}

	receipt, appendErr := a.logClient.Append(timeoutCtx, envelope, statementHash)
	if receipt != nil {
		result.LogURL = receipt.LogURL
		result.LogEntryID = receipt.EntryID
		result.LogIndex = receipt.LogIndex
		result.IntegratedTime = receipt.IntegratedTime
		result.Checkpoint = receipt.Checkpoint
		result.InclusionProof = receipt.InclusionProof
		result.LogRawResponse = receipt.Raw
	}
	if appendErr != nil {
		return result, fmt.Errorf("append transparency log entry: %w", appendErr)
	}

	return result, nil
}

type inTotoStatement struct {
	Type          string                   `json:"_type"`
	Subject       []inTotoSubject          `json:"subject"`
	PredicateType string                   `json:"predicateType"`
	Predicate     findingAttestationRecord `json:"predicate"`
}

type inTotoSubject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

type findingAttestationRecord struct {
	Schema       string                      `json:"schema"`
	EventType    FindingAttestationEventType `json:"event_type"`
	ObservedAt   string                      `json:"observed_at"`
	PreviousHash string                      `json:"previous_hash,omitempty"`
	Finding      findingAttestationPayload   `json:"finding"`
}

type findingAttestationPayload struct {
	ID             string   `json:"id"`
	PolicyID       string   `json:"policy_id"`
	PolicyName     string   `json:"policy_name,omitempty"`
	ControlID      string   `json:"control_id,omitempty"`
	Title          string   `json:"title,omitempty"`
	Description    string   `json:"description,omitempty"`
	Severity       string   `json:"severity"`
	Status         string   `json:"status"`
	ResourceID     string   `json:"resource_id,omitempty"`
	ResourceName   string   `json:"resource_name,omitempty"`
	ResourceType   string   `json:"resource_type,omitempty"`
	RiskCategories []string `json:"risk_categories,omitempty"`
	FirstSeen      string   `json:"first_seen,omitempty"`
	LastSeen       string   `json:"last_seen,omitempty"`
	ResourceDigest string   `json:"resource_digest,omitempty"`
}

func buildFindingAttestationStatement(event FindingAttestationEvent, observedAt time.Time) (*inTotoStatement, error) {
	resourceJSON, err := json.Marshal(event.Finding.Resource)
	if err != nil {
		return nil, fmt.Errorf("marshal resource: %w", err)
	}

	resourceDigest := ""
	if len(resourceJSON) > 0 && string(resourceJSON) != "null" {
		digest := sha256.Sum256(resourceJSON)
		resourceDigest = "sha256:" + hex.EncodeToString(digest[:])
	}

	riskCategories := uniqueSortedStrings(event.Finding.RiskCategories)

	findingPayload := findingAttestationPayload{
		ID:             strings.TrimSpace(event.Finding.ID),
		PolicyID:       strings.TrimSpace(event.Finding.PolicyID),
		PolicyName:     strings.TrimSpace(event.Finding.PolicyName),
		ControlID:      strings.TrimSpace(event.Finding.ControlID),
		Title:          strings.TrimSpace(event.Finding.Title),
		Description:    strings.TrimSpace(event.Finding.Description),
		Severity:       strings.TrimSpace(event.Finding.Severity),
		Status:         strings.TrimSpace(event.Finding.Status),
		ResourceID:     strings.TrimSpace(event.Finding.ResourceID),
		ResourceName:   strings.TrimSpace(event.Finding.ResourceName),
		ResourceType:   strings.TrimSpace(event.Finding.ResourceType),
		RiskCategories: riskCategories,
		ResourceDigest: resourceDigest,
	}
	if !event.Finding.FirstSeen.IsZero() {
		findingPayload.FirstSeen = event.Finding.FirstSeen.UTC().Format(time.RFC3339Nano)
	}
	if !event.Finding.LastSeen.IsZero() {
		findingPayload.LastSeen = event.Finding.LastSeen.UTC().Format(time.RFC3339Nano)
	}

	subjectHash := sha256.Sum256([]byte(findingPayload.ID + "|" + findingPayload.ResourceID + "|" + findingPayload.PolicyID))
	subject := inTotoSubject{
		Name: findingPayload.ResourceID,
		Digest: map[string]string{
			"sha256": hex.EncodeToString(subjectHash[:]),
		},
	}
	if subject.Name == "" {
		subject.Name = findingPayload.ID
	}

	statement := &inTotoStatement{
		Type:          attestationInTotoStatementType,
		PredicateType: attestationFindingPredicateType,
		Subject:       []inTotoSubject{subject},
		Predicate: findingAttestationRecord{
			Schema:       attestationStatementSchema,
			EventType:    event.Type,
			ObservedAt:   observedAt.UTC().Format(time.RFC3339Nano),
			PreviousHash: strings.TrimSpace(event.PreviousHash),
			Finding:      findingPayload,
		},
	}

	return statement, nil
}

type dsseEnvelope struct {
	PayloadType string          `json:"payloadType"`
	Payload     string          `json:"payload"`
	Signatures  []dsseSignature `json:"signatures"`
}

type dsseSignature struct {
	KeyID string `json:"keyid,omitempty"`
	Sig   string `json:"sig"`
}

func createDSSEEnvelope(payloadType string, payload []byte, key ed25519.PrivateKey, keyID string) (dsseEnvelope, error) {
	if strings.TrimSpace(payloadType) == "" {
		return dsseEnvelope{}, errors.New("missing dsse payload type")
	}
	if len(payload) == 0 {
		return dsseEnvelope{}, errors.New("missing dsse payload")
	}
	if len(key) != ed25519.PrivateKeySize {
		return dsseEnvelope{}, errors.New("invalid ed25519 private key")
	}

	pae := dssePAE(payloadType, payload)
	sig := ed25519.Sign(key, pae)

	return dsseEnvelope{
		PayloadType: payloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures: []dsseSignature{
			{
				KeyID: strings.TrimSpace(keyID),
				Sig:   base64.StdEncoding.EncodeToString(sig),
			},
		},
	}, nil
}

func dssePAE(payloadType string, payload []byte) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "DSSEv1 %d %s %d ", len(payloadType), payloadType, len(payload))
	b.Write(payload)
	return b.Bytes()
}

func parseEd25519PrivateKey(raw string) (ed25519.PrivateKey, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("empty key")
	}

	if strings.Contains(raw, "BEGIN") {
		block, _ := pem.Decode([]byte(raw))
		if block == nil {
			return nil, errors.New("invalid PEM key")
		}
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse pkcs8 key: %w", err)
		}
		key, ok := parsed.(ed25519.PrivateKey)
		if !ok {
			return nil, errors.New("key is not ed25519")
		}
		return key, nil
	}

	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(raw)
		if err != nil {
			return nil, fmt.Errorf("decode base64 key: %w", err)
		}
	}

	switch len(decoded) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(decoded), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(decoded), nil
	default:
		return nil, fmt.Errorf("invalid key length: %d", len(decoded))
	}
}

func deriveAttestationKeyID(pub ed25519.PublicKey) string {
	digest := sha256.Sum256(pub)
	return "ed25519:" + hex.EncodeToString(digest[:8])
}

type transparencyLogClient interface {
	Append(ctx context.Context, envelope dsseEnvelope, statementHash string) (*transparencyLogReceipt, error)
}

type transparencyLogReceipt struct {
	LogURL         string
	EntryID        string
	LogIndex       *int64
	IntegratedTime *time.Time
	Checkpoint     string
	InclusionProof map[string]interface{}
	Raw            map[string]interface{}
}

type transparencyDevHTTPClient struct {
	endpoint string
	client   *http.Client
}

func newTransparencyDevHTTPClient(endpoint string, client *http.Client) *transparencyDevHTTPClient {
	if client == nil {
		client = &http.Client{Timeout: defaultAttestationHTTPTimeout}
	}
	return &transparencyDevHTTPClient{endpoint: strings.TrimRight(endpoint, "/"), client: client}
}

type transparencyLogAppendRequest struct {
	APIVersion    string       `json:"api_version"`
	Kind          string       `json:"kind"`
	StatementHash string       `json:"statement_hash"`
	Envelope      dsseEnvelope `json:"dsse_envelope"`
}

func (c *transparencyDevHTTPClient) Append(ctx context.Context, envelope dsseEnvelope, statementHash string) (*transparencyLogReceipt, error) {
	reqBody := transparencyLogAppendRequest{
		APIVersion:    attestationStatementSchema,
		Kind:          attestationUploadKind,
		StatementHash: statementHash,
		Envelope:      envelope,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal log append request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create append request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read append response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		trimmed := strings.TrimSpace(string(respBody))
		if trimmed == "" {
			trimmed = resp.Status
		}
		return nil, fmt.Errorf("transparency log append failed: %s", trimmed)
	}

	receipt := &transparencyLogReceipt{LogURL: c.endpoint}
	if len(bytes.TrimSpace(respBody)) == 0 {
		return receipt, nil
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(respBody, &raw); err != nil {
		return nil, fmt.Errorf("decode append response: %w", err)
	}
	receipt.Raw = raw
	receipt.EntryID = pickString(raw, "entry_id", "uuid", "id", "log_entry_id")
	receipt.Checkpoint = pickString(raw, "checkpoint", "signed_tree_head", "sth")
	receipt.LogIndex = pickInt64(raw, "log_index", "integrated_index", "index")
	receipt.IntegratedTime = pickTime(raw, "integrated_time", "integrated_at", "timestamp")
	receipt.InclusionProof = pickMap(raw, "inclusion_proof", "proof")

	return receipt, nil
}

func pickString(raw map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if value, ok := raw[key]; ok {
			switch v := value.(type) {
			case string:
				if strings.TrimSpace(v) != "" {
					return strings.TrimSpace(v)
				}
			case []byte:
				if len(v) > 0 {
					return strings.TrimSpace(string(v))
				}
			}
		}
	}
	return ""
}

func pickInt64(raw map[string]interface{}, keys ...string) *int64 {
	for _, key := range keys {
		value, ok := raw[key]
		if !ok || value == nil {
			continue
		}
		switch v := value.(type) {
		case float64:
			i := int64(v)
			return &i
		case int64:
			i := v
			return &i
		case int:
			i := int64(v)
			return &i
		case json.Number:
			i, err := v.Int64()
			if err == nil {
				return &i
			}
		case string:
			i, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			if err == nil {
				return &i
			}
		}
	}
	return nil
}

func pickTime(raw map[string]interface{}, keys ...string) *time.Time {
	for _, key := range keys {
		value, ok := raw[key]
		if !ok || value == nil {
			continue
		}

		switch v := value.(type) {
		case string:
			if ts := parseFlexibleTime(v); ts != nil {
				return ts
			}
		case float64:
			t := time.Unix(int64(v), 0).UTC()
			return &t
		case int64:
			t := time.Unix(v, 0).UTC()
			return &t
		case json.Number:
			i, err := v.Int64()
			if err == nil {
				t := time.Unix(i, 0).UTC()
				return &t
			}
		}
	}
	return nil
}

func parseFlexibleTime(value string) *time.Time {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	if parsed, err := time.Parse(time.RFC3339Nano, value); err == nil {
		t := parsed.UTC()
		return &t
	}
	if parsed, err := time.Parse(time.RFC3339, value); err == nil {
		t := parsed.UTC()
		return &t
	}
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
		t := time.Unix(seconds, 0).UTC()
		return &t
	}
	return nil
}

func pickMap(raw map[string]interface{}, keys ...string) map[string]interface{} {
	for _, key := range keys {
		if value, ok := raw[key]; ok {
			if m, ok := value.(map[string]interface{}); ok {
				return m
			}
		}
	}
	return nil
}

func uniqueSortedStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		clean := strings.TrimSpace(value)
		if clean == "" {
			continue
		}
		if _, ok := seen[clean]; ok {
			continue
		}
		seen[clean] = struct{}{}
		out = append(out, clean)
	}
	if len(out) == 0 {
		return nil
	}
	sort.Strings(out)
	return out
}
