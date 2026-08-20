package sourceruntime

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

const sourceRuntimeProtocolRevision = 1

var (
	errProtocolInvalid          = errors.New("invalid source-runtime protocol envelope")
	errProtocolSecretField      = errors.New("source-runtime protocol envelope contains a raw-secret field")
	errAuthorityEvidenceMissing = errors.New("source-family authority evidence is incomplete")
)

type sourceRuntimeOperation string

const (
	sourceRuntimeDescribePlan sourceRuntimeOperation = "DescribePlan"
	sourceRuntimeCheck        sourceRuntimeOperation = "Check"
	sourceRuntimeDiscover     sourceRuntimeOperation = "Discover"
	sourceRuntimeReadPage     sourceRuntimeOperation = "ReadPage"
)

// SourceRuntimeEnvelope is the internal, versioned request/result/receipt/error
// shape shared by Go compatibility tests and the Rust source-runtime contract.
// It intentionally carries public config only; credential references and raw
// provider payloads are outside this protocol baseline.
type SourceRuntimeEnvelope struct {
	Revision     int                      `json:"revision"`
	Operation    sourceRuntimeOperation   `json:"operation"`
	TenantID     string                   `json:"tenant_id"`
	RuntimeID    string                   `json:"runtime_id"`
	SourceID     string                   `json:"source_id"`
	FamilyID     string                   `json:"family_id"`
	AttemptID    string                   `json:"attempt_id"`
	PublicConfig map[string]string        `json:"public_config,omitempty"`
	Cursor       string                   `json:"cursor,omitempty"`
	Checkpoint   string                   `json:"checkpoint,omitempty"`
	Limit        uint32                   `json:"limit,omitempty"`
	Result       *SourceRuntimeResult     `json:"result,omitempty"`
	Receipt      *SourceRuntimeReceipt    `json:"receipt,omitempty"`
	Error        *SourceRuntimeErrorShape `json:"error,omitempty"`
}

type SourceRuntimeResult struct {
	EventsAccepted uint32            `json:"events_accepted"`
	EventsScanned  uint32            `json:"events_scanned"`
	NextCursor     string            `json:"next_cursor,omitempty"`
	Diagnostics    map[string]string `json:"diagnostics,omitempty"`
}

type SourceRuntimeReceipt struct {
	PlanDigestSHA256      string `json:"plan_digest_sha256"`
	RequestDigestSHA256   string `json:"request_digest_sha256"`
	ScannedDigestSHA256   string `json:"scanned_digest_sha256"`
	AcceptedDigestSHA256  string `json:"accepted_digest_sha256"`
	ResultDigestSHA256    string `json:"result_digest_sha256"`
	ReceiptDigestSHA256   string `json:"receipt_digest_sha256"`
	WorkerBuildID         string `json:"worker_build_id"`
	RuntimeFamilyProofRev string `json:"runtime_family_proof_revision"`
}

type SourceRuntimeErrorShape struct {
	Code        string            `json:"code"`
	Category    string            `json:"category"`
	Retryable   bool              `json:"retryable"`
	Diagnostics map[string]string `json:"diagnostics,omitempty"`
}

func ValidateSourceRuntimeEnvelope(envelope SourceRuntimeEnvelope) error {
	if envelope.Revision != sourceRuntimeProtocolRevision {
		return fmt.Errorf("%w: unsupported schema revision %d", errProtocolInvalid, envelope.Revision)
	}
	switch envelope.Operation {
	case sourceRuntimeDescribePlan, sourceRuntimeCheck, sourceRuntimeDiscover, sourceRuntimeReadPage:
	default:
		return fmt.Errorf("%w: unsupported operation %q", errProtocolInvalid, envelope.Operation)
	}
	for name, value := range map[string]string{
		"tenant_id":  envelope.TenantID,
		"runtime_id": envelope.RuntimeID,
		"source_id":  envelope.SourceID,
		"family_id":  envelope.FamilyID,
		"attempt_id": envelope.AttemptID,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%w: %s is required", errProtocolInvalid, name)
		}
	}
	bytes, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("%w: marshal envelope: %w", errProtocolInvalid, err)
	}
	var decoded any
	if err := json.Unmarshal(bytes, &decoded); err != nil {
		return fmt.Errorf("%w: decode envelope: %w", errProtocolInvalid, err)
	}
	if path := firstRawSecretField("", decoded); path != "" {
		return fmt.Errorf("%w: %s", errProtocolSecretField, path)
	}
	return nil
}

// SourceRuntimeCanonicalValue is a JSON-serializable protocol value whose
// digest is computed after canonical key ordering and number decoding.
type SourceRuntimeCanonicalValue interface{}

func CanonicalSourceRuntimeDigest(value SourceRuntimeCanonicalValue) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var decoded any
	if err := decoder.Decode(&decoded); err != nil {
		return "", err
	}
	canonical := new(bytes.Buffer)
	if err := writeCanonicalJSON(canonical, decoded); err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical.Bytes())
	return hex.EncodeToString(sum[:]), nil
}

func writeCanonicalJSON(out *bytes.Buffer, value any) error {
	switch typed := value.(type) {
	case nil:
		out.WriteString("null")
	case bool:
		if typed {
			out.WriteString("true")
		} else {
			out.WriteString("false")
		}
	case json.Number:
		out.WriteString(typed.String())
	case string:
		encoded, err := json.Marshal(typed)
		if err != nil {
			return err
		}
		out.Write(encoded)
	case []any:
		out.WriteByte('[')
		for index, item := range typed {
			if index > 0 {
				out.WriteByte(',')
			}
			if err := writeCanonicalJSON(out, item); err != nil {
				return err
			}
		}
		out.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		out.WriteByte('{')
		for index, key := range keys {
			if index > 0 {
				out.WriteByte(',')
			}
			encoded, err := json.Marshal(key)
			if err != nil {
				return err
			}
			out.Write(encoded)
			out.WriteByte(':')
			if err := writeCanonicalJSON(out, typed[key]); err != nil {
				return err
			}
		}
		out.WriteByte('}')
	default:
		return fmt.Errorf("unsupported canonical JSON value %T", value)
	}
	return nil
}

func CanonicalSourceRuntimeDigestVectors() (map[string]string, error) {
	plan := map[string]any{
		"family_id": "identity_user",
		"limits": map[string]any{
			"event_limit": 250,
			"page_size":   100,
		},
		"operation": "ReadPage",
		"public_config": map[string]any{
			"base_url": "https://provider.example.invalid",
			"org":      "writer",
		},
		"source_id": "fixture",
	}
	request := SourceRuntimeEnvelope{
		Revision:  sourceRuntimeProtocolRevision,
		Operation: sourceRuntimeReadPage,
		TenantID:  "tenant-a",
		RuntimeID: "runtime-a",
		SourceID:  "fixture",
		FamilyID:  "identity_user",
		AttemptID: "attempt-0001",
		PublicConfig: map[string]string{
			"base_url": "https://provider.example.invalid",
			"org":      "writer",
		},
		Cursor:     "cursor-1",
		Checkpoint: "checkpoint-1",
		Limit:      100,
	}
	scanned := []map[string]any{
		{"event_id": "evt-1", "kind": "fixture.identity_user", "provider_id": "u-1"},
		{"event_id": "evt-2", "kind": "fixture.identity_user", "provider_id": "u-2"},
	}
	accepted := []map[string]any{scanned[0]}
	result := SourceRuntimeResult{
		EventsScanned:  2,
		EventsAccepted: 1,
		NextCursor:     "cursor-2",
		Diagnostics: map[string]string{
			"redaction": "provider diagnostics redacted",
		},
	}
	vectors := map[string]any{
		"plan":            plan,
		"request_intent":  request,
		"scanned_events":  scanned,
		"accepted_events": accepted,
		"logical_result":  result,
	}
	out := make(map[string]string, len(vectors)+1)
	for _, name := range sortedAnyKeys(vectors) {
		digest, err := CanonicalSourceRuntimeDigest(vectors[name])
		if err != nil {
			return nil, err
		}
		out[name] = digest
	}
	receipt := SourceRuntimeReceipt{
		PlanDigestSHA256:      out["plan"],
		RequestDigestSHA256:   out["request_intent"],
		ScannedDigestSHA256:   out["scanned_events"],
		AcceptedDigestSHA256:  out["accepted_events"],
		ResultDigestSHA256:    out["logical_result"],
		WorkerBuildID:         "source-runtime-next:test",
		RuntimeFamilyProofRev: "fixture-corpus:v1",
	}
	receiptDigest, err := CanonicalSourceRuntimeDigest(receipt)
	if err != nil {
		return nil, err
	}
	out["worker_receipt"] = receiptDigest
	return out, nil
}

func sortedAnyKeys(values map[string]any) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func firstRawSecretField(path string, value any) string {
	switch typed := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			next := key
			if path != "" {
				next = path + "." + key
			}
			if rawSecretFieldName(key) {
				return next
			}
			if found := firstRawSecretField(next, typed[key]); found != "" {
				return found
			}
		}
	case []any:
		for index, item := range typed {
			next := fmt.Sprintf("%s[%d]", path, index)
			if found := firstRawSecretField(next, item); found != "" {
				return found
			}
		}
	}
	return ""
}

func rawSecretFieldName(name string) bool {
	normalized := normalizeProtocolFieldName(name)
	for _, marker := range []string{
		"api_key",
		"api_secret_key",
		"password",
		"authorization",
		"authorization_header",
		"bearer_token",
		"access_token",
		"refresh_token",
		"api_token",
		"client_secret",
		"cookie",
		"set_cookie",
		"raw_credential",
		"credential_value",
		"secret",
		"token",
		"raw_provider_request",
		"raw_provider_response",
		"raw_provider_error",
		"raw_provider_http_request_body",
		"raw_provider_http_response_body",
		"raw_provider_error_body",
		"raw_provider_payload",
		"provider_payload",
		"provider_request_body",
		"provider_response_body",
		"provider_error_body",
	} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}

func normalizeProtocolFieldName(name string) string {
	runes := []rune(name)
	var builder strings.Builder
	wroteSeparator := false
	for index, current := range runes {
		switch current {
		case '-', ' ', '.', '/':
			if builder.Len() > 0 && !wroteSeparator {
				builder.WriteByte('_')
				wroteSeparator = true
			}
			continue
		}
		var previous, next rune
		if index > 0 {
			previous = runes[index-1]
		}
		if index+1 < len(runes) {
			next = runes[index+1]
		}
		if index > 0 && current >= 'A' && current <= 'Z' && !wroteSeparator &&
			(isProtocolLowerOrDigit(previous) || (isProtocolUpper(previous) && isProtocolLower(next))) {
			builder.WriteByte('_')
		}
		builder.WriteRune([]rune(strings.ToLower(string(current)))[0])
		wroteSeparator = false
	}
	return strings.Trim(builder.String(), "_")
}

func isProtocolLowerOrDigit(value rune) bool {
	return (value >= 'a' && value <= 'z') || (value >= '0' && value <= '9')
}

func isProtocolUpper(value rune) bool {
	return value >= 'A' && value <= 'Z'
}

func isProtocolLower(value rune) bool {
	return value >= 'a' && value <= 'z'
}

type SourceFamilyAuthorityEvidence struct {
	PlanDigest                 string
	FixtureCorpusRevision      string
	SupportedAuthModes         []string
	SupportedPaginationGrammar []string
	SupportedProviderErrors    []string
	EgressAllowlist            []string
	ResponseLimits             string
	CredentialLeaseMode        string
	ProjectionDependency       string
	RollbackReceipt            string
	ParityStatus               string
	CanonicalDigestVectors     []string
	ConfigSafetyProof          string
	CursorCheckpointProof      string
	FencingRecoveryProof       string
	WorkerBuildID              string
	PromotionReceipt           string
}

func ValidateSourceFamilyAuthorityEvidence(evidence SourceFamilyAuthorityEvidence) error {
	missing := missingAuthorityEvidenceFields(evidence)
	if len(missing) > 0 {
		return fmt.Errorf("%w: %s", errAuthorityEvidenceMissing, strings.Join(missing, ", "))
	}
	if !validSHA256Hex(evidence.PlanDigest) {
		return fmt.Errorf("%w: compiled_plan_digest must be SHA-256 hex", errAuthorityEvidenceMissing)
	}
	if !authenticatedPromotionReceipt(evidence.PromotionReceipt) {
		return fmt.Errorf("%w: promotion_receipt must be signed or authenticated", errAuthorityEvidenceMissing)
	}
	return nil
}

func missingAuthorityEvidenceFields(evidence SourceFamilyAuthorityEvidence) []string {
	var missing []string
	if strings.TrimSpace(evidence.PlanDigest) == "" {
		missing = append(missing, "compiled_plan_digest")
	}
	if strings.TrimSpace(evidence.FixtureCorpusRevision) == "" {
		missing = append(missing, "fixture_corpus_revision")
	}
	if len(nonemptyStrings(evidence.SupportedAuthModes)) == 0 {
		missing = append(missing, "supported_auth_modes")
	}
	if len(nonemptyStrings(evidence.SupportedPaginationGrammar)) == 0 {
		missing = append(missing, "supported_pagination_grammar")
	}
	if len(nonemptyStrings(evidence.SupportedProviderErrors)) == 0 {
		missing = append(missing, "supported_provider_error_modes")
	}
	if len(nonemptyStrings(evidence.EgressAllowlist)) == 0 {
		missing = append(missing, "egress_allowlist")
	}
	if strings.TrimSpace(evidence.ResponseLimits) == "" {
		missing = append(missing, "response_decompression_limits")
	}
	if strings.TrimSpace(evidence.CredentialLeaseMode) == "" {
		missing = append(missing, "credential_lease_mode")
	}
	if strings.TrimSpace(evidence.ProjectionDependency) == "" {
		missing = append(missing, "projection_dependency")
	}
	if strings.TrimSpace(evidence.RollbackReceipt) == "" {
		missing = append(missing, "rollback_receipt")
	}
	if strings.TrimSpace(evidence.ParityStatus) == "" {
		missing = append(missing, "fixture_parity_status")
	}
	if len(nonemptyStrings(evidence.CanonicalDigestVectors)) == 0 {
		missing = append(missing, "canonical_digest_vectors")
	}
	if strings.TrimSpace(evidence.ConfigSafetyProof) == "" {
		missing = append(missing, "credential_config_safety_proof")
	}
	if strings.TrimSpace(evidence.CursorCheckpointProof) == "" {
		missing = append(missing, "cursor_checkpoint_rollback_proof")
	}
	if strings.TrimSpace(evidence.FencingRecoveryProof) == "" {
		missing = append(missing, "operational_fencing_recovery_proof")
	}
	if strings.TrimSpace(evidence.WorkerBuildID) == "" {
		missing = append(missing, "worker_runtime_build_identity")
	}
	if strings.TrimSpace(evidence.PromotionReceipt) == "" {
		missing = append(missing, "promotion_receipt")
	}
	sort.Strings(missing)
	return missing
}

func nonemptyStrings(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			out = append(out, strings.TrimSpace(value))
		}
	}
	return out
}

func validSHA256Hex(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func authenticatedPromotionReceipt(value string) bool {
	value = strings.TrimSpace(value)
	return strings.HasPrefix(value, "sig:") || strings.HasPrefix(value, "auth:")
}
