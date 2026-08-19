package sourcehealth

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

var (
	ErrAuthorityEvidenceInvalid   = errors.New("authority evidence is invalid")
	ErrAuthorityEvidenceImmutable = errors.New("authority evidence is immutable")
)

type AuthorityDecisionKind string

const (
	AuthorityDecisionPromote           AuthorityDecisionKind = "promotion"
	AuthorityDecisionRollback          AuthorityDecisionKind = "rollback"
	AuthorityDecisionShadowOnlyBlocked AuthorityDecisionKind = "shadow_only_blocked"
	AuthorityDecisionCapabilityChanged AuthorityDecisionKind = "capability_changed"
)

type AuthorityEvidenceRecord struct {
	TenantID                  string                `json:"tenant_id"`
	SourceID                  string                `json:"source_id"`
	FamilyID                  string                `json:"family_id"`
	AuthorityEpoch            uint64                `json:"authority_epoch"`
	DecisionID                string                `json:"decision_id"`
	DecisionKind              AuthorityDecisionKind `json:"decision_kind"`
	InputEvidenceDigestSHA256 string                `json:"input_evidence_digest_sha256"`
	ActorID                   string                `json:"actor_id"`
	Timestamp                 time.Time             `json:"timestamp"`
	ReasonCode                string                `json:"reason_code"`
	AuthenticatedReceiptID    string                `json:"authenticated_receipt_id,omitempty"`
	ReceiptSignature          string                `json:"receipt_signature,omitempty"`
	PreviousDecisionID        string                `json:"previous_decision_id,omitempty"`
	RecordDigestSHA256        string                `json:"record_digest_sha256"`
}

type AuthorityEvidenceStream struct {
	records []AuthorityEvidenceRecord
	byID    map[string]AuthorityEvidenceRecord
}

func NewAuthorityEvidenceStream() *AuthorityEvidenceStream {
	return &AuthorityEvidenceStream{byID: map[string]AuthorityEvidenceRecord{}}
}

func (s *AuthorityEvidenceStream) Append(record AuthorityEvidenceRecord) (AuthorityEvidenceRecord, error) {
	if s == nil {
		return AuthorityEvidenceRecord{}, fmt.Errorf("%w: stream is required", ErrAuthorityEvidenceInvalid)
	}
	if s.byID == nil {
		s.byID = map[string]AuthorityEvidenceRecord{}
	}
	if _, exists := s.byID[strings.TrimSpace(record.DecisionID)]; exists {
		return AuthorityEvidenceRecord{}, fmt.Errorf("%w: decision_id already exists", ErrAuthorityEvidenceImmutable)
	}
	if err := ValidateAuthorityEvidenceRecord(record); err != nil {
		return AuthorityEvidenceRecord{}, err
	}
	record = normalizedAuthorityEvidenceRecord(record)
	record.RecordDigestSHA256 = authorityEvidenceRecordDigest(record)
	s.records = append(s.records, record)
	s.byID[record.DecisionID] = record
	return record, nil
}

func (s *AuthorityEvidenceStream) Mutate(decisionID string, replacement AuthorityEvidenceRecord) error {
	if s == nil || s.byID == nil {
		return fmt.Errorf("%w: evidence record not found", ErrAuthorityEvidenceInvalid)
	}
	existing, ok := s.byID[strings.TrimSpace(decisionID)]
	if !ok {
		return fmt.Errorf("%w: evidence record not found", ErrAuthorityEvidenceInvalid)
	}
	replacement = normalizedAuthorityEvidenceRecord(replacement)
	replacement.RecordDigestSHA256 = authorityEvidenceRecordDigest(replacement)
	if replacement == existing {
		return nil
	}
	return ErrAuthorityEvidenceImmutable
}

func (s *AuthorityEvidenceStream) History(tenantID, sourceID, familyID string) []AuthorityEvidenceRecord {
	if s == nil {
		return nil
	}
	tenantID = strings.TrimSpace(tenantID)
	sourceID = strings.TrimSpace(sourceID)
	familyID = strings.TrimSpace(familyID)
	out := make([]AuthorityEvidenceRecord, 0, len(s.records))
	for _, record := range s.records {
		if record.TenantID == tenantID && record.SourceID == sourceID && record.FamilyID == familyID {
			out = append(out, record)
		}
	}
	return out
}

func (s *AuthorityEvidenceStream) Get(decisionID string) (AuthorityEvidenceRecord, bool) {
	if s == nil || s.byID == nil {
		return AuthorityEvidenceRecord{}, false
	}
	record, ok := s.byID[strings.TrimSpace(decisionID)]
	return record, ok
}

func ValidateAuthorityEvidenceRecord(record AuthorityEvidenceRecord) error {
	record = normalizedAuthorityEvidenceRecord(record)
	missing := []string{}
	for field, value := range map[string]string{
		"tenant_id":                    record.TenantID,
		"source_id":                    record.SourceID,
		"family_id":                    record.FamilyID,
		"decision_id":                  record.DecisionID,
		"input_evidence_digest_sha256": record.InputEvidenceDigestSHA256,
		"actor_id":                     record.ActorID,
		"reason_code":                  record.ReasonCode,
	} {
		if value == "" {
			missing = append(missing, field)
		}
	}
	if record.AuthorityEpoch == 0 {
		missing = append(missing, "authority_epoch")
	}
	if record.Timestamp.IsZero() {
		missing = append(missing, "timestamp")
	}
	if record.DecisionKind == "" {
		missing = append(missing, "decision_kind")
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		return fmt.Errorf("%w: missing %s", ErrAuthorityEvidenceInvalid, strings.Join(missing, ", "))
	}
	switch record.DecisionKind {
	case AuthorityDecisionPromote, AuthorityDecisionRollback, AuthorityDecisionShadowOnlyBlocked, AuthorityDecisionCapabilityChanged:
	default:
		return fmt.Errorf("%w: unsupported decision_kind %q", ErrAuthorityEvidenceInvalid, record.DecisionKind)
	}
	if !validSHA256Hex(record.InputEvidenceDigestSHA256) {
		return fmt.Errorf("%w: input_evidence_digest_sha256 must be SHA-256 hex", ErrAuthorityEvidenceInvalid)
	}
	if record.DecisionKind == AuthorityDecisionPromote && !authorityReceiptAuthenticated(record) {
		return fmt.Errorf("%w: promotion receipt must be signed or authenticated", ErrAuthorityEvidenceInvalid)
	}
	return nil
}

func AuthorityEvidenceReceiptRef(record AuthorityEvidenceRecord) string {
	record = normalizedAuthorityEvidenceRecord(record)
	if record.DecisionID == "" {
		return ""
	}
	return fmt.Sprintf("authority-evidence:%s:%d", record.DecisionID, record.AuthorityEpoch)
}

func validSHA256Hex(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func authorityReceiptAuthenticated(record AuthorityEvidenceRecord) bool {
	return strings.TrimSpace(record.AuthenticatedReceiptID) != "" ||
		strings.HasPrefix(strings.TrimSpace(record.ReceiptSignature), "sig:")
}

func normalizedAuthorityEvidenceRecord(record AuthorityEvidenceRecord) AuthorityEvidenceRecord {
	record.TenantID = strings.TrimSpace(record.TenantID)
	record.SourceID = strings.TrimSpace(record.SourceID)
	record.FamilyID = strings.TrimSpace(record.FamilyID)
	record.DecisionID = strings.TrimSpace(record.DecisionID)
	record.InputEvidenceDigestSHA256 = strings.ToLower(strings.TrimSpace(record.InputEvidenceDigestSHA256))
	record.ActorID = strings.TrimSpace(record.ActorID)
	record.ReasonCode = strings.TrimSpace(record.ReasonCode)
	record.AuthenticatedReceiptID = strings.TrimSpace(record.AuthenticatedReceiptID)
	record.ReceiptSignature = strings.TrimSpace(record.ReceiptSignature)
	record.PreviousDecisionID = strings.TrimSpace(record.PreviousDecisionID)
	record.Timestamp = record.Timestamp.UTC()
	return record
}

func authorityEvidenceRecordDigest(record AuthorityEvidenceRecord) string {
	record.RecordDigestSHA256 = ""
	bytes, _ := json.Marshal(record)
	sum := sha256.Sum256(bytes)
	return hex.EncodeToString(sum[:])
}
