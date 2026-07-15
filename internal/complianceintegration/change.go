package complianceintegration

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

var ErrInvalidChangeSignal = errors.New("invalid compliance change signal")

// ChangeKind describes how an exact revision changed lifecycle state.
type ChangeKind string

const (
	ChangeCreated ChangeKind = "created"
	ChangeUpdated ChangeKind = "updated"
	ChangeDeleted ChangeKind = "deleted"
	ChangeRevoked ChangeKind = "revoked"
)

// ChangeSignal is a normalized immutable change notification. Revision is the
// exact revision whose dependents must be traversed; Replacement is present only
// for an update and identifies the new exact revision.
type ChangeSignal struct {
	kind        ChangeKind
	revision    RevisionRef
	replacement *RevisionRef
	changedAt   time.Time
}

// NewChangeSignal rejects underspecified updates instead of allowing a
// best-effort impact pass without exact revision identity.
func NewChangeSignal(kind ChangeKind, revision RevisionRef, replacement *RevisionRef, changedAt time.Time) (ChangeSignal, error) {
	kind = ChangeKind(strings.ToLower(strings.TrimSpace(string(kind))))
	if revision.ExactKey() == "" {
		return ChangeSignal{}, fmt.Errorf("%w: revision is required", ErrInvalidChangeSignal)
	}
	if changedAt.IsZero() {
		return ChangeSignal{}, fmt.Errorf("%w: changed_at is required", ErrInvalidChangeSignal)
	}
	changedAt = changedAt.UTC().Truncate(time.Millisecond)
	switch kind {
	case ChangeUpdated:
		if replacement == nil {
			return ChangeSignal{}, fmt.Errorf("%w: updated signal requires replacement revision", ErrInvalidChangeSignal)
		}
		if !revision.SameSubject(*replacement) || replacement.Version() <= revision.Version() {
			return ChangeSignal{}, fmt.Errorf("%w: replacement must be a newer revision of the same subject", ErrInvalidChangeSignal)
		}
	case ChangeCreated, ChangeDeleted, ChangeRevoked:
		if replacement != nil {
			return ChangeSignal{}, fmt.Errorf("%w: %s signal cannot include replacement revision", ErrInvalidChangeSignal, kind)
		}
	default:
		return ChangeSignal{}, fmt.Errorf("%w: unsupported kind %q", ErrInvalidChangeSignal, kind)
	}
	var replacementCopy *RevisionRef
	if replacement != nil {
		value := *replacement
		replacementCopy = &value
	}
	return ChangeSignal{kind: kind, revision: revision, replacement: replacementCopy, changedAt: changedAt}, nil
}

func (s ChangeSignal) Kind() ChangeKind      { return s.kind }
func (s ChangeSignal) Revision() RevisionRef { return s.revision }
func (s ChangeSignal) ChangedAt() time.Time  { return s.changedAt }
func (s ChangeSignal) Replacement() (RevisionRef, bool) {
	if s.replacement == nil {
		return RevisionRef{}, false
	}
	return *s.replacement, true
}
