package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/compliance"
	"github.com/writer/cerebro/internal/ports"
)

const maxAssessmentPlanImplementationRevisions = 500

// ResolveAssessmentPlanLineage converts compatibility IDs into the immutable
// revision identities used by compliance impact analysis. It does not infer a
// current revision: every lookup uses the revision ID supplied by the plan.
func (s *Store) ResolveAssessmentPlanLineage(ctx context.Context, tenantID, programID, scopeRevisionID string, implementationRevisionIDs []string) (compliance.RevisionRef, []compliance.RevisionRef, error) {
	if s == nil || s.db == nil {
		return compliance.RevisionRef{}, nil, errors.New("postgres is not configured")
	}
	if len(implementationRevisionIDs) == 0 || len(implementationRevisionIDs) > maxAssessmentPlanImplementationRevisions {
		return compliance.RevisionRef{}, nil, errors.New("assessment plan implementation revisions must be between 1 and 500")
	}
	scope, err := s.GetProgramScopeRevision(ctx, tenantID, programID, scopeRevisionID)
	if err != nil {
		return compliance.RevisionRef{}, nil, err
	}
	scopeRef := revisionRefFromVersion(scope.Version)
	if err := scopeRef.Validate(); err != nil {
		return compliance.RevisionRef{}, nil, fmt.Errorf("assessment plan scope lineage: %w", err)
	}

	result := make([]compliance.RevisionRef, 0, len(implementationRevisionIDs))
	for _, revisionID := range implementationRevisionIDs {
		ref, lookupErr := s.lookupImplementationRevisionRef(ctx, strings.TrimSpace(tenantID), strings.TrimSpace(programID), strings.TrimSpace(revisionID))
		if lookupErr != nil {
			return compliance.RevisionRef{}, nil, lookupErr
		}
		result = append(result, ref)
	}
	return scopeRef, result, nil
}

func (s *Store) lookupImplementationRevisionRef(ctx context.Context, tenantID, programID, revisionID string) (compliance.RevisionRef, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT implementation_id, revision_id, revision_version, content_digest, created_at
FROM grc_control_implementation_revisions
WHERE tenant_id = $1 AND program_id = $2 AND revision_id = $3
ORDER BY implementation_id
LIMIT 2`, tenantID, programID, revisionID)
	if err != nil {
		return compliance.RevisionRef{}, fmt.Errorf("query assessment plan implementation lineage: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var values []compliance.RevisionRef
	for rows.Next() {
		var id, storedRevisionID, digest string
		var version int64
		var modifiedAt time.Time
		if err := rows.Scan(&id, &storedRevisionID, &version, &digest, &modifiedAt); err != nil {
			return compliance.RevisionRef{}, fmt.Errorf("scan assessment plan implementation lineage: %w", err)
		}
		if version <= 0 {
			return compliance.RevisionRef{}, errors.New("assessment plan implementation lineage version is invalid")
		}
		values = append(values, compliance.NormalizeRevisionRef(compliance.RevisionRef{
			ID: id, RevisionID: storedRevisionID, Version: uint64(version),
			ContentDigest: compliance.ContentDigest(digest), LastModified: modifiedAt,
		}))
	}
	if err := rows.Err(); err != nil {
		return compliance.RevisionRef{}, fmt.Errorf("iterate assessment plan implementation lineage: %w", err)
	}
	if len(values) == 0 {
		return compliance.RevisionRef{}, ports.ErrControlImplementationNotFound
	}
	if len(values) != 1 {
		return compliance.RevisionRef{}, errors.New("assessment plan implementation revision is ambiguous")
	}
	if err := values[0].Validate(); err != nil {
		return compliance.RevisionRef{}, fmt.Errorf("assessment plan implementation lineage: %w", err)
	}
	return values[0], nil
}

func revisionRefFromVersion(value compliance.VersionMetadata) compliance.RevisionRef {
	return compliance.NormalizeRevisionRef(compliance.RevisionRef{
		ID: value.ID, RevisionID: value.RevisionID, Version: value.Version,
		ContentDigest: value.ContentDigest, LastModified: value.LastModified,
	})
}
