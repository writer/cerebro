package compliance

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

var ErrInvalidRevision = errors.New("invalid compliance revision")

// ContentDigest is the lowercase SHA-256 digest of normalized semantic content.
// It deliberately remains separate from revision identity: two tenants may
// create different revisions with the same semantic content.
type ContentDigest string

// VersionMetadata describes one immutable revision of a stable logical record.
type VersionMetadata struct {
	ID            string        `json:"id"`
	RevisionID    string        `json:"revision_id"`
	Version       uint64        `json:"version"`
	LastModified  time.Time     `json:"last_modified"`
	ContentDigest ContentDigest `json:"content_digest"`
	CreatedBy     string        `json:"created_by"`
	PredecessorID string        `json:"predecessor_id,omitempty"`
	SuccessorID   string        `json:"successor_id,omitempty"`
}

// RevisionRef identifies one immutable revision of a stable compliance subject.
// ContentDigest covers normalized semantic content, not database metadata.
type RevisionRef struct {
	ID            string        `json:"id"`
	RevisionID    string        `json:"revision_id"`
	Version       uint64        `json:"version"`
	ContentDigest ContentDigest `json:"content_digest"`
	LastModified  time.Time     `json:"last_modified"`
}

// SubjectRef identifies a tenant-scoped subject without copying its lifecycle.
type SubjectRef struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

func NormalizeVersionMetadata(value VersionMetadata) VersionMetadata {
	value.ID = strings.TrimSpace(value.ID)
	value.RevisionID = strings.TrimSpace(value.RevisionID)
	value.LastModified = CanonicalRevisionTime(value.LastModified)
	value.ContentDigest = ContentDigest(strings.TrimSpace(string(value.ContentDigest)))
	value.CreatedBy = strings.TrimSpace(value.CreatedBy)
	value.PredecessorID = strings.TrimSpace(value.PredecessorID)
	value.SuccessorID = strings.TrimSpace(value.SuccessorID)
	return value
}

func NormalizeRevisionRef(value RevisionRef) RevisionRef {
	value.ID = strings.TrimSpace(value.ID)
	value.RevisionID = strings.TrimSpace(value.RevisionID)
	value.ContentDigest = ContentDigest(strings.TrimSpace(string(value.ContentDigest)))
	value.LastModified = CanonicalRevisionTime(value.LastModified)
	return value
}

// CanonicalRevisionTime uses the precision shared by event envelopes and
// canonical assessment hashes.
func CanonicalRevisionTime(value time.Time) time.Time {
	if value.IsZero() {
		return time.Time{}
	}
	return value.UTC().Truncate(time.Millisecond)
}

func (metadata VersionMetadata) Validate() error {
	metadata = NormalizeVersionMetadata(metadata)
	if metadata.ID == "" || metadata.RevisionID == "" || metadata.CreatedBy == "" {
		return fmt.Errorf("%w: id, revision_id, and created_by are required", ErrInvalidRevision)
	}
	if metadata.Version == 0 || metadata.LastModified.IsZero() {
		return fmt.Errorf("%w: version and last_modified are required", ErrInvalidRevision)
	}
	if err := ValidateContentDigest(metadata.ContentDigest); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidRevision, err)
	}
	return nil
}

// Validate checks the required, transport-independent revision invariants.
// Resource-specific identifier validation remains with the owning service.
func (revision RevisionRef) Validate() error {
	revision = NormalizeRevisionRef(revision)
	if strings.TrimSpace(revision.ID) == "" || strings.TrimSpace(revision.RevisionID) == "" {
		return fmt.Errorf("%w: id and revision_id are required", ErrInvalidRevision)
	}
	if revision.Version == 0 {
		return fmt.Errorf("%w: version must be greater than zero", ErrInvalidRevision)
	}
	if err := ValidateContentDigest(revision.ContentDigest); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidRevision, err)
	}
	if revision.LastModified.IsZero() {
		return fmt.Errorf("%w: last_modified is required", ErrInvalidRevision)
	}
	return nil
}

func (reference SubjectRef) Validate() error {
	if strings.TrimSpace(reference.Type) == "" || strings.TrimSpace(reference.ID) == "" {
		return fmt.Errorf("%w: subject type and id are required", ErrInvalidRevision)
	}
	return nil
}
