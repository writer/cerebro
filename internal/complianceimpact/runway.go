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

var ErrInvalidSourceRunway = errors.New("invalid source trust runway")

type RunwayState string

const (
	RunwayHealthy RunwayState = "healthy"
	RunwayWarning RunwayState = "warning"
	RunwayBlind   RunwayState = "blind"
	RunwayUnknown RunwayState = "unknown"
)

type RunwayReason string

const (
	RunwaySourceUnhealthy    RunwayReason = "source_unhealthy"
	RunwayCoverageIncomplete RunwayReason = "coverage_incomplete"
	RunwayCheckpointMissing  RunwayReason = "checkpoint_missing"
	RunwayEvidenceExpiring   RunwayReason = "evidence_expiring"
	RunwaySourceAuthExpiring RunwayReason = "source_auth_expiring"
	RunwayCollectionOverdue  RunwayReason = "collection_overdue"
)

type SourceRunwayInput struct {
	TenantID            string                            `json:"tenant_id"`
	Objective           complianceintegration.RevisionRef `json:"objective"`
	SourceProof         complianceintegration.RevisionRef `json:"source_proof"`
	AsOf                time.Time                         `json:"as_of"`
	LastSuccessfulAt    time.Time                         `json:"last_successful_at"`
	ExpectedCadence     time.Duration                     `json:"expected_cadence"`
	MaximumStaleness    time.Duration                     `json:"maximum_staleness"`
	CredentialExpiresAt time.Time                         `json:"credential_expires_at,omitempty"`
	EvidenceExpiresAt   time.Time                         `json:"evidence_expires_at,omitempty"`
	SourceHealthy       bool                              `json:"source_healthy"`
	CoverageComplete    bool                              `json:"coverage_complete"`
}

type SourceRunway struct {
	TenantID    string             `json:"tenant_id"`
	Objective   RevisionProvenance `json:"objective"`
	SourceProof RevisionProvenance `json:"source_proof"`
	State       RunwayState        `json:"state"`
	BlindAt     time.Time          `json:"blind_at"`
	Remaining   time.Duration      `json:"remaining"`
	Reasons     []RunwayReason     `json:"reasons"`
	Digest      string             `json:"digest"`
}

func CalculateSourceRunway(input SourceRunwayInput) (SourceRunway, error) {
	input.TenantID = strings.TrimSpace(input.TenantID)
	if input.TenantID == "" || input.Objective.TenantID() != input.TenantID || input.SourceProof.TenantID() != input.TenantID ||
		input.AsOf.IsZero() || input.ExpectedCadence <= 0 || input.MaximumStaleness <= 0 || input.LastSuccessfulAt.After(input.AsOf) {
		return SourceRunway{}, ErrInvalidSourceRunway
	}
	result := SourceRunway{TenantID: input.TenantID, Objective: provenance(input.Objective), SourceProof: provenance(input.SourceProof), State: RunwayHealthy}
	deadlines := make([]time.Time, 0, 3)
	if input.LastSuccessfulAt.IsZero() {
		result.State = RunwayUnknown
		result.Reasons = append(result.Reasons, RunwayCheckpointMissing)
	} else {
		deadlines = append(deadlines, input.LastSuccessfulAt.UTC().Add(input.MaximumStaleness))
	}
	if !input.CredentialExpiresAt.IsZero() {
		deadlines = append(deadlines, input.CredentialExpiresAt.UTC())
	}
	if !input.EvidenceExpiresAt.IsZero() {
		deadlines = append(deadlines, input.EvidenceExpiresAt.UTC())
	}
	if !input.SourceHealthy {
		result.State = RunwayBlind
		result.Reasons = append(result.Reasons, RunwaySourceUnhealthy)
	}
	if !input.CoverageComplete {
		result.State = RunwayBlind
		result.Reasons = append(result.Reasons, RunwayCoverageIncomplete)
	}
	if len(deadlines) != 0 {
		sort.Slice(deadlines, func(i, j int) bool { return deadlines[i].Before(deadlines[j]) })
		result.BlindAt = deadlines[0]
		result.Remaining = result.BlindAt.Sub(input.AsOf.UTC())
		if !result.BlindAt.After(input.AsOf.UTC()) {
			result.State = RunwayBlind
			if !input.LastSuccessfulAt.IsZero() {
				result.Reasons = append(result.Reasons, RunwayCollectionOverdue)
			}
		} else if result.State == RunwayHealthy && result.Remaining <= 2*input.ExpectedCadence {
			result.State = RunwayWarning
		}
		if !input.CredentialExpiresAt.IsZero() && input.CredentialExpiresAt.UTC().Equal(result.BlindAt) {
			result.Reasons = append(result.Reasons, RunwaySourceAuthExpiring)
		}
		if !input.EvidenceExpiresAt.IsZero() && input.EvidenceExpiresAt.UTC().Equal(result.BlindAt) {
			result.Reasons = append(result.Reasons, RunwayEvidenceExpiring)
		}
	}
	result.Reasons = uniqueRunwayReasons(result.Reasons)
	result.Digest = ""
	payload, err := json.Marshal(result)
	if err != nil {
		return SourceRunway{}, err
	}
	sum := sha256.Sum256(payload)
	result.Digest = "sha256:" + hex.EncodeToString(sum[:])
	return result, nil
}

func uniqueRunwayReasons(values []RunwayReason) []RunwayReason {
	seen := map[RunwayReason]struct{}{}
	for _, value := range values {
		seen[value] = struct{}{}
	}
	result := make([]RunwayReason, 0, len(seen))
	for value := range seen {
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}
