package sourcecertification

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/connectorcatalog"
	"github.com/writer/cerebro/internal/sourcecdk"
)

type Tier string

const (
	TierCataloged          Tier = "cataloged"
	TierSpecVerified       Tier = "spec_verified"
	TierContractTested     Tier = "contract_tested"
	TierProductionObserved Tier = "production_observed"
	TierOutcomeValidated   Tier = "outcome_validated"

	AvailabilityAvailable              = "available"
	AvailabilityPreview                = "preview"
	AvailabilityBelowMinimum           = "below_minimum"
	AvailabilityConfiguredBelowMinimum = "configured_below_minimum"
	AvailabilityInvalidated            = "invalidated"
)

const DefaultRuntimeFreshness = 24 * time.Hour

var ErrInvalidTier = errors.New("invalid certification tier")

type RuntimeObservation struct {
	Configured     bool      `json:"configured"`
	Healthy        bool      `json:"healthy"`
	LastObservedAt time.Time `json:"last_observed_at,omitempty"`
	Fresh          bool      `json:"fresh"`
}

type RuntimeCount struct {
	Total   int
	Healthy int
}

type OutcomeObservation struct {
	Accepted       bool      `json:"accepted"`
	Receipt        string    `json:"receipt,omitempty"`
	LastObservedAt time.Time `json:"last_observed_at,omitempty"`
}

type Input struct {
	SourceID      string
	Certification *sourcecdk.CatalogCertification
	ProviderAPI   connectorcatalog.RuntimeProviderAPIDepth
	Runtime       RuntimeObservation
	Outcome       OutcomeObservation
	Now           time.Time
}

type Result struct {
	SourceID       string                                   `json:"source_id"`
	EffectiveTier  Tier                                     `json:"effective_tier"`
	StaticTier     Tier                                     `json:"static_tier"`
	DynamicTier    Tier                                     `json:"dynamic_tier"`
	Invalidated    bool                                     `json:"invalidated"`
	Expired        bool                                     `json:"expired"`
	Owner          string                                   `json:"owner,omitempty"`
	ReviewedAt     string                                   `json:"reviewed_at,omitempty"`
	ExpiresAt      string                                   `json:"expires_at,omitempty"`
	Gaps           []string                                 `json:"gaps,omitempty"`
	Evidence       []sourcecdk.CatalogCertificationEvidence `json:"evidence,omitempty"`
	LastObservedAt string                                   `json:"last_observed_at,omitempty"`
}

type AvailabilityPolicy struct {
	MinimumTier    Tier
	IncludePreview bool
}

type Availability struct {
	State          string `json:"state"`
	MinimumTier    Tier   `json:"minimum_tier"`
	MeetsMinimum   bool   `json:"meets_minimum"`
	Discoverable   bool   `json:"discoverable"`
	PreviewAllowed bool   `json:"preview_allowed,omitempty"`
	Reason         string `json:"reason,omitempty"`
}

func ParseAvailabilityPolicy(configured, requested, preview string) (AvailabilityPolicy, error) {
	value := strings.TrimSpace(requested)
	if value == "" {
		value = strings.TrimSpace(configured)
	}
	tier, err := ParseTier(value)
	if err != nil {
		return AvailabilityPolicy{}, err
	}
	includePreview := false
	if strings.TrimSpace(preview) != "" {
		includePreview, err = strconv.ParseBool(preview)
		if err != nil {
			return AvailabilityPolicy{}, fmt.Errorf("include_preview must be true or false")
		}
	}
	return AvailabilityPolicy{MinimumTier: tier, IncludePreview: includePreview}, nil
}

func RuntimeHealthy(runtime *cerebrov1.SourceRuntime) bool {
	if runtime == nil {
		return false
	}
	status := strings.TrimSpace(runtime.GetConfig()["__cerebro_runtime_status"])
	if status != "" {
		return status == "completed" || status == "healthy"
	}
	return runtime.GetLastSyncedAt() != nil
}

func RuntimeCounts(runtimes []*cerebrov1.SourceRuntime) map[string]RuntimeCount {
	counts := map[string]RuntimeCount{}
	for _, runtime := range runtimes {
		sourceID := strings.TrimSpace(runtime.GetSourceId())
		if sourceID == "" {
			continue
		}
		count := counts[sourceID]
		count.Total++
		if RuntimeHealthy(runtime) {
			count.Healthy++
		}
		counts[sourceID] = count
	}
	return counts
}

func RuntimeObservations(runtimes []*cerebrov1.SourceRuntime, now time.Time) map[string]RuntimeObservation {
	result := map[string]RuntimeObservation{}
	for _, runtime := range runtimes {
		if runtime == nil || strings.TrimSpace(runtime.GetSourceId()) == "" {
			continue
		}
		sourceID := strings.TrimSpace(runtime.GetSourceId())
		observation := result[sourceID]
		observation.Configured = true
		healthy := RuntimeHealthy(runtime)
		observation.Healthy = observation.Healthy || healthy
		if syncedAt := runtime.GetLastSyncedAt(); healthy && syncedAt != nil && syncedAt.AsTime().After(observation.LastObservedAt) {
			observation.LastObservedAt = syncedAt.AsTime().UTC()
		}
		result[sourceID] = observation
	}
	for sourceID, observation := range result {
		observation.Fresh = !observation.LastObservedAt.IsZero() && now.Sub(observation.LastObservedAt) <= DefaultRuntimeFreshness
		result[sourceID] = observation
	}
	return result
}

func ParseTier(value string) (Tier, error) {
	tier := Tier(strings.ToLower(strings.TrimSpace(value)))
	if tier == "" {
		return TierCataloged, nil
	}
	if tierRank(tier) < 0 {
		return "", fmt.Errorf("%w %q; expected cataloged, spec_verified, contract_tested, production_observed, or outcome_validated", ErrInvalidTier, value)
	}
	return tier, nil
}

func AtLeast(actual, minimum Tier) bool {
	return tierRank(actual) >= tierRank(minimum) && tierRank(minimum) >= 0
}

func Evaluate(input Input) Result {
	now := input.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	result := Result{
		SourceID:      strings.TrimSpace(input.SourceID),
		EffectiveTier: TierCataloged,
		StaticTier:    TierCataloged,
		DynamicTier:   TierCataloged,
	}
	if input.ProviderAPI.HasDisproof {
		result.Invalidated = true
		result.Gaps = normalizedGaps("provider_api_invalidated")
		return result
	}
	certification := input.Certification
	if certification == nil {
		result.Gaps = normalizedGaps("certification_proof_missing")
		return result
	}
	result.Owner = strings.TrimSpace(certification.Owner)
	reviewedAt, _ := time.Parse(time.RFC3339, certification.ReviewedAt)
	expiresAt, _ := time.Parse(time.RFC3339, certification.ExpiresAt)
	result.ReviewedAt = reviewedAt.UTC().Format(time.RFC3339)
	result.ExpiresAt = expiresAt.UTC().Format(time.RFC3339)
	result.Evidence = cloneEvidence(certification.Evidence)
	if expiresAt.IsZero() || !expiresAt.After(now) {
		result.Expired = true
		result.Gaps = normalizedGaps("certification_proof_expired")
		return result
	}
	hasProviderProof := input.ProviderAPI.HasProof && hasEvidence(result.Evidence,
		sourcecdk.CertificationEvidenceProviderSpec,
		sourcecdk.CertificationEvidenceProviderDocumentation,
	)
	if hasProviderProof {
		result.StaticTier = TierSpecVerified
	}
	if hasProviderProof && hasEvidence(result.Evidence, sourcecdk.CertificationEvidenceSandboxContract) {
		result.StaticTier = TierContractTested
	}
	result.DynamicTier = result.StaticTier
	result.EffectiveTier = result.StaticTier
	if AtLeast(result.StaticTier, TierContractTested) {
		switch {
		case !input.Runtime.Configured:
			result.Gaps = append(result.Gaps, "production_observation_missing")
		case !input.Runtime.Healthy:
			result.Gaps = append(result.Gaps, "runtime_unhealthy")
		case !input.Runtime.Fresh:
			result.Gaps = append(result.Gaps, "runtime_observation_stale")
		default:
			result.DynamicTier = TierProductionObserved
			result.EffectiveTier = TierProductionObserved
			result.LastObservedAt = input.Runtime.LastObservedAt.UTC().Format(time.RFC3339)
		}
	}
	if AtLeast(result.DynamicTier, TierProductionObserved) {
		if input.Outcome.Accepted && strings.TrimSpace(input.Outcome.Receipt) != "" && !input.Outcome.LastObservedAt.IsZero() {
			result.DynamicTier = TierOutcomeValidated
			result.EffectiveTier = TierOutcomeValidated
			if input.Outcome.LastObservedAt.After(input.Runtime.LastObservedAt) {
				result.LastObservedAt = input.Outcome.LastObservedAt.UTC().Format(time.RFC3339)
			}
		} else {
			result.Gaps = append(result.Gaps, "accepted_outcome_missing")
		}
	}
	if result.StaticTier == TierCataloged && !hasProviderProof {
		result.Gaps = append(result.Gaps, "provider_proof_missing")
	}
	result.Gaps = normalizedGaps(result.Gaps...)
	return result
}

// CatalogResult computes certification from loaded source-catalog proof and an
// optional live runtime observation. Outcome state remains absent until a
// durable outcome owner supplies it.
func CatalogResult(sourceID string, now time.Time, runtime RuntimeObservation) Result {
	certification, hasCertification := sourcecdk.CatalogCertificationForSource(sourceID)
	api, runtimeFamilies, hasAPI := sourcecdk.CatalogProviderAPIForSource(sourceID)
	input := Input{SourceID: sourceID, Runtime: runtime, Now: now}
	if hasCertification {
		input.Certification = &certification
	}
	if hasAPI {
		input.ProviderAPI = connectorcatalog.ProviderAPIDepthForSourceCatalog(api, runtimeFamilies)
	}
	return Evaluate(input)
}

func ApplyAvailability(result Result, configured bool, policy AvailabilityPolicy) Availability {
	minimum := policy.MinimumTier
	if tierRank(minimum) < 0 {
		minimum = TierCataloged
	}
	availability := Availability{MinimumTier: minimum, Discoverable: true}
	switch {
	case result.Invalidated:
		availability.State = AvailabilityInvalidated
		availability.Reason = "Static provider proof is invalidated. Review the disproof before enabling this connector."
	case AtLeast(result.EffectiveTier, minimum):
		availability.State = AvailabilityAvailable
		availability.MeetsMinimum = true
	case configured:
		availability.State = AvailabilityConfiguredBelowMinimum
		availability.Reason = "The configured runtime remains visible but its connector certification is below the required tier."
	case policy.IncludePreview:
		availability.State = AvailabilityPreview
		availability.PreviewAllowed = true
		availability.Reason = "The connector is below the required tier and is included for evaluation."
	default:
		availability.State = AvailabilityBelowMinimum
		availability.Reason = "The connector remains discoverable but is below the required certification tier."
	}
	return availability
}

func tierRank(tier Tier) int {
	switch tier {
	case TierCataloged:
		return 0
	case TierSpecVerified:
		return 1
	case TierContractTested:
		return 2
	case TierProductionObserved:
		return 3
	case TierOutcomeValidated:
		return 4
	default:
		return -1
	}
}

func hasEvidence(evidence []sourcecdk.CatalogCertificationEvidence, kinds ...string) bool {
	allowed := map[string]bool{}
	for _, kind := range kinds {
		allowed[kind] = true
	}
	for _, item := range evidence {
		if allowed[item.Kind] {
			return true
		}
	}
	return false
}

func cloneEvidence(evidence []sourcecdk.CatalogCertificationEvidence) []sourcecdk.CatalogCertificationEvidence {
	cloned := make([]sourcecdk.CatalogCertificationEvidence, len(evidence))
	for index, item := range evidence {
		cloned[index] = item
		cloned[index].Families = append([]string(nil), item.Families...)
	}
	return cloned
}

func normalizedGaps(values ...string) []string {
	seen := map[string]struct{}{}
	gaps := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		gaps = append(gaps, value)
	}
	sort.Strings(gaps)
	return gaps
}
