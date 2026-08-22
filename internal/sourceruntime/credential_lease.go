package sourceruntime

import (
	"errors"
	"strings"
	"time"
)

// CredentialLeaseScope binds an opaque Rust-provider credential reference to
// exactly one operation/page/request intent. It intentionally contains no
// credential bytes.
type CredentialLeaseScope struct {
	TenantID            string
	RuntimeID           string
	SourceID            string
	FamilyID            string
	Operation           string
	RequestIntentDigest string
	LogicalPageID       string
	SourceGeneration    uint64
	AuthorityEpoch      uint64
}

// CredentialLeaseReference is a broker-issued opaque lease reference. The
// reference ID is safe to compare but must not be a reusable bearer credential.
type CredentialLeaseReference struct {
	ReferenceID string
	Scope       CredentialLeaseScope
	IssuedAt    time.Time
	ExpiresAt   time.Time
	Revoked     bool
	Consumed    bool
}

var (
	// ErrCredentialLeaseInvalidScope reports missing or malformed lease scope.
	ErrCredentialLeaseInvalidScope = errors.New("credential lease scope is invalid")
	// ErrCredentialLeaseExpired reports deterministic TTL expiry.
	ErrCredentialLeaseExpired = errors.New("credential lease expired")
	// ErrCredentialLeaseRevoked reports revocation after use or rollback.
	ErrCredentialLeaseRevoked = errors.New("credential lease revoked")
	// ErrCredentialLeaseScopeMismatch reports attempted cross-operation reuse.
	ErrCredentialLeaseScopeMismatch = errors.New("credential lease scope mismatch")
	// ErrCredentialLeaseConsumed reports attempted reuse after one operation.
	ErrCredentialLeaseConsumed = errors.New("credential lease already consumed")
)

// ValidateCredentialLeaseScope checks one complete operation scope.
func ValidateCredentialLeaseScope(scope CredentialLeaseScope) error {
	for _, value := range []string{
		scope.TenantID,
		scope.RuntimeID,
		scope.SourceID,
		scope.FamilyID,
		scope.RequestIntentDigest,
		scope.LogicalPageID,
	} {
		if strings.TrimSpace(value) == "" || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\r\n\t") {
			return ErrCredentialLeaseInvalidScope
		}
	}
	if !isSHA256Hex(scope.RequestIntentDigest) {
		return ErrCredentialLeaseInvalidScope
	}
	if scope.SourceGeneration == 0 || scope.AuthorityEpoch == 0 {
		return ErrCredentialLeaseInvalidScope
	}
	switch scope.Operation {
	case "DescribePlan", "Check", "Discover", "ReadPage":
		return nil
	default:
		return ErrCredentialLeaseInvalidScope
	}
}

// ValidateCredentialLeaseFor rejects a lease before provider access unless it
// exactly matches the requested operation scope and remains unexpired.
func ValidateCredentialLeaseFor(lease CredentialLeaseReference, expected CredentialLeaseScope, now time.Time) error {
	if err := ValidateCredentialLeaseScope(lease.Scope); err != nil {
		return err
	}
	if err := ValidateCredentialLeaseScope(expected); err != nil {
		return err
	}
	if lease.Revoked {
		return ErrCredentialLeaseRevoked
	}
	if lease.Consumed {
		return ErrCredentialLeaseConsumed
	}
	if now.Before(lease.IssuedAt) || !now.Before(lease.ExpiresAt) {
		return ErrCredentialLeaseExpired
	}
	if lease.Scope != expected {
		return ErrCredentialLeaseScopeMismatch
	}
	return nil
}

// ConsumeCredentialLease validates and revokes one operation-scoped lease.
func ConsumeCredentialLease(lease *CredentialLeaseReference, expected CredentialLeaseScope, now time.Time) error {
	if lease == nil {
		return ErrCredentialLeaseInvalidScope
	}
	if err := ValidateCredentialLeaseFor(*lease, expected, now); err != nil {
		return err
	}
	lease.Consumed = true
	lease.Revoked = true
	return nil
}

func isSHA256Hex(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, r := range value {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') && (r < 'A' || r > 'F') {
			return false
		}
	}
	return true
}
