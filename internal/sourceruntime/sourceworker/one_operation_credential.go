package sourceworker

import (
	"context"
	"crypto/subtle"
	"errors"
	"strings"
	"sync"
	"time"
)

// NewOneOperationCredentialRedeemer binds one trusted resolved credential to
// one opaque reference. Neither the redeemer nor its lease implements debug or
// serialization interfaces.
func NewOneOperationCredentialRedeemer(reference string, credential []byte, operationID string, expiresAt time.Time) CredentialRedeemer {
	return &oneOperationCredentialRedeemer{
		reference: strings.TrimSpace(reference), credential: append([]byte(nil), credential...),
		operationID: strings.TrimSpace(operationID), expiresAt: expiresAt.UTC(),
	}
}

type oneOperationCredentialRedeemer struct {
	mu          sync.Mutex
	reference   string
	credential  []byte
	operationID string
	expiresAt   time.Time
	consumed    bool
}

func (r *oneOperationCredentialRedeemer) Redeem(_ context.Context, reference string, _ CredentialScope) (CredentialLease, error) {
	if r == nil {
		return nil, ErrCredentialUnavailable
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.consumed || r.reference == "" || len(r.credential) == 0 || !safeIdentifier(r.operationID) || r.expiresAt.IsZero() || subtle.ConstantTimeCompare([]byte(r.reference), []byte(strings.TrimSpace(reference))) != 1 {
		return nil, ErrCredentialUnavailable
	}
	r.consumed = true
	credential := append([]byte(nil), r.credential...)
	clear(r.credential)
	r.credential = nil
	return &oneOperationCredentialLease{credential: credential, operationID: r.operationID, expiresAt: r.expiresAt}, nil
}

type oneOperationCredentialLease struct {
	mu          sync.Mutex
	credential  []byte
	operationID string
	expiresAt   time.Time
	closed      bool
}

func (l *oneOperationCredentialLease) BearerToken() []byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	return append([]byte(nil), l.credential...)
}

func (l *oneOperationCredentialLease) OperationID() string  { return l.operationID }
func (l *oneOperationCredentialLease) ExpiresAt() time.Time { return l.expiresAt }

func (l *oneOperationCredentialLease) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return errors.New("source worker credential lease is already closed")
	}
	clear(l.credential)
	l.credential = nil
	l.closed = true
	return nil
}
