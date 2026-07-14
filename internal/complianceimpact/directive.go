package complianceimpact

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/complianceintegration"
)

var ErrInvalidAssessmentDirective = errors.New("invalid change assessment directive")

type AssessmentMode string

const (
	AssessmentModeTargeted           AssessmentMode = "targeted"
	AssessmentModeFullReconciliation AssessmentMode = "full_reconciliation"
)

type AssessmentDirective struct {
	TenantID           string                  `json:"tenant_id"`
	Mode               AssessmentMode          `json:"mode"`
	Change             DirectiveChange         `json:"change"`
	ImpactComplete     bool                    `json:"impact_complete"`
	ObjectiveRevisions []RevisionProvenance    `json:"objective_revisions"`
	PlanRevisions      []RevisionProvenance    `json:"plan_revisions"`
	Invalidations      []DirectiveInvalidation `json:"invalidations"`
	Issues             []DirectiveIssue        `json:"issues"`
	RequestedAt        time.Time               `json:"requested_at"`
	IdempotencyKey     string                  `json:"idempotency_key"`
	Digest             string                  `json:"digest"`
}

type DirectiveChange struct {
	Kind        complianceintegration.ChangeKind `json:"kind"`
	Revision    RevisionProvenance               `json:"revision"`
	Replacement *RevisionProvenance              `json:"replacement,omitempty"`
	ChangedAt   time.Time                        `json:"changed_at"`
}

type DirectiveInvalidation struct {
	Revision RevisionProvenance `json:"revision"`
	Reason   ReasonCode         `json:"reason"`
}

type DirectiveIssue struct {
	Code     ReasonCode         `json:"code"`
	Revision RevisionProvenance `json:"revision"`
	Related  RevisionProvenance `json:"related"`
}

// BuildAssessmentDirective converts an impact result into durable scheduling
// input. Incomplete impact never produces a targeted assessment.
func BuildAssessmentDirective(result Result, requestedAt time.Time) (AssessmentDirective, error) {
	if strings.TrimSpace(result.TenantID) == "" || result.Signal.Revision().TenantID() != result.TenantID || requestedAt.IsZero() {
		return AssessmentDirective{}, ErrInvalidAssessmentDirective
	}
	change := DirectiveChange{Kind: result.Signal.Kind(), Revision: provenance(result.Signal.Revision()), ChangedAt: result.Signal.ChangedAt()}
	if replacement, ok := result.Signal.Replacement(); ok {
		value := provenance(replacement)
		change.Replacement = &value
	}
	directive := AssessmentDirective{
		TenantID: result.TenantID, Change: change, ImpactComplete: result.Complete,
		RequestedAt: requestedAt.UTC(),
	}
	for _, invalidation := range result.Invalidations {
		directive.Invalidations = append(directive.Invalidations, DirectiveInvalidation{Revision: provenance(invalidation.Revision), Reason: invalidation.Reason})
	}
	for _, issue := range result.Issues {
		directive.Issues = append(directive.Issues, DirectiveIssue{Code: issue.Code, Revision: provenance(issue.Revision), Related: provenance(issue.Related)})
	}
	if result.Complete {
		directive.Mode = AssessmentModeTargeted
		for _, objective := range result.Objectives {
			directive.ObjectiveRevisions = append(directive.ObjectiveRevisions, provenance(objective.Revision))
		}
		for _, plan := range result.Plans {
			directive.PlanRevisions = append(directive.PlanRevisions, provenance(plan.Revision))
		}
	} else {
		directive.Mode = AssessmentModeFullReconciliation
	}
	sort.Slice(directive.ObjectiveRevisions, func(i, j int) bool {
		return provenanceKey(directive.ObjectiveRevisions[i]) < provenanceKey(directive.ObjectiveRevisions[j])
	})
	sort.Slice(directive.PlanRevisions, func(i, j int) bool {
		return provenanceKey(directive.PlanRevisions[i]) < provenanceKey(directive.PlanRevisions[j])
	})
	directive.Digest = ""
	directive.IdempotencyKey = ""
	identity := directive
	identity.RequestedAt = time.Time{}
	identityPayload, err := json.Marshal(identity)
	if err != nil {
		return AssessmentDirective{}, err
	}
	identitySum := sha256.Sum256(identityPayload)
	directive.IdempotencyKey = "compliance-change-assessment:" + hex.EncodeToString(identitySum[:16])
	payload, err := json.Marshal(directive)
	if err != nil {
		return AssessmentDirective{}, err
	}
	sum := sha256.Sum256(payload)
	directive.Digest = "sha256:" + hex.EncodeToString(sum[:])
	return directive, nil
}
