package complianceimpact

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/compliance"
	"github.com/writer/cerebro/internal/complianceintegration"
)

var (
	ErrInvalidAdapterRequest = errors.New("invalid compliance impact adapter request")
	ErrAdapterTenantBoundary = errors.New("compliance impact adapter tenant boundary violation")
	ErrAdapterLimit          = errors.New("compliance impact adapter limit exceeded")
)

const (
	maxAdapterMappings = 100000
	maxAdapterSources  = 100000
	maxAdapterTargets  = 50000
	maxAdapterActions  = 100000
	maxAdapterIssues   = 100000
)

var adapterIdentifierPattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)

// AdapterLimits bound the compatibility adapter's in-memory work. The adapter
// performs no external reads and never executes an action candidate.
type AdapterLimits struct {
	MaxMappings uint32 `json:"max_mappings"`
	MaxSources  uint32 `json:"max_sources"`
	MaxTargets  uint32 `json:"max_targets"`
	MaxActions  uint32 `json:"max_actions"`
	MaxIssues   uint32 `json:"max_issues"`
}

func DefaultAdapterLimits() AdapterLimits {
	return AdapterLimits{MaxMappings: 10000, MaxSources: 10000, MaxTargets: 10000, MaxActions: 25000, MaxIssues: 10000}
}

// CompatibilityTargetKind identifies an existing operator-facing domain. It
// is deliberately narrower than complianceintegration.FactKind: these are
// compatibility destinations, not new canonical fact owners.
type CompatibilityTargetKind string

const (
	TargetPolicy        CompatibilityTargetKind = "policy"
	TargetFinding       CompatibilityTargetKind = "finding"
	TargetVendor        CompatibilityTargetKind = "vendor"
	TargetQuestionnaire CompatibilityTargetKind = "questionnaire"
	TargetAccessReview  CompatibilityTargetKind = "access_review"
)

// AdapterReasonCode explains why a canonical impact could not be translated.
type AdapterReasonCode string

const (
	ReasonUnmappedTarget   AdapterReasonCode = "unmapped_target"
	ReasonAmbiguousTarget  AdapterReasonCode = "ambiguous_target"
	ReasonImpactIncomplete AdapterReasonCode = "impact_incomplete"
)

// RevisionProvenance is the transport-safe form of one exact immutable
// complianceintegration revision. ContentDigest is copied without alteration.
type RevisionProvenance struct {
	TenantID      string                         `json:"tenant_id"`
	Domain        string                         `json:"domain"`
	Kind          complianceintegration.FactKind `json:"kind"`
	ID            string                         `json:"id"`
	RevisionID    string                         `json:"revision_id"`
	Version       uint64                         `json:"version"`
	ContentDigest compliance.ContentDigest       `json:"content_digest"`
	LastModified  time.Time                      `json:"last_modified"`
}

// MappingSetRevision identifies the explicit mapping input used for a replay.
// It is provenance only; the adapter never fetches mapping data by this value.
type MappingSetRevision struct {
	RevisionID    string                   `json:"revision_id"`
	ContentDigest compliance.ContentDigest `json:"content_digest"`
}

// CompatibilityMapping translates one exact impact revision to one existing
// domain identifier. ActionIDs are candidates only and remain owned and
// validated for execution by the destination domain.
type CompatibilityMapping struct {
	TenantID   string                  `json:"tenant_id"`
	Source     RevisionProvenance      `json:"source"`
	TargetKind CompatibilityTargetKind `json:"target_kind"`
	TargetID   string                  `json:"target_id"`
	ActionIDs  []string                `json:"action_ids"`
}

// AdapterRequest contains every input needed for deterministic replay.
type AdapterRequest struct {
	TenantID   string                 `json:"tenant_id"`
	Impact     Result                 `json:"-"`
	MappingSet MappingSetRevision     `json:"mapping_set"`
	Mappings   []CompatibilityMapping `json:"mappings"`
	Limits     AdapterLimits          `json:"limits"`
}

// MappedImpactSource retains the exact revision and canonical impact reasons
// that caused one compatibility target to be proposed.
type MappedImpactSource struct {
	Revision  RevisionProvenance `json:"revision"`
	Reasons   []ReasonCode       `json:"reasons"`
	Relations []string           `json:"relations,omitempty"`
	Distance  uint32             `json:"distance"`
}

// ActionCandidate is a read-only domain action identifier. This package does
// not infer parameters, authorize execution, or mutate destination state.
type ActionCandidate struct {
	ActionID string       `json:"action_id"`
	Reasons  []ReasonCode `json:"reasons"`
}

// CompatibilityTarget groups all exact impact sources for one existing domain
// identifier and deduplicates the resulting action candidates.
type CompatibilityTarget struct {
	Kind    CompatibilityTargetKind `json:"kind"`
	ID      string                  `json:"id"`
	Sources []MappedImpactSource    `json:"sources"`
	Actions []ActionCandidate       `json:"actions"`
}

// AdapterIssue records explicit non-matches. CandidateIDs is populated only
// for ambiguity and is sorted so operators can repair the mapping set.
type AdapterIssue struct {
	Code         AdapterReasonCode       `json:"code"`
	Source       RevisionProvenance      `json:"source"`
	TargetKind   CompatibilityTargetKind `json:"target_kind,omitempty"`
	CandidateIDs []string                `json:"candidate_ids,omitempty"`
	ImpactReason ReasonCode              `json:"impact_reason,omitempty"`
}

// AdapterResult is deterministic, transport-safe, and contains no executable
// callbacks or copied domain payloads.
type AdapterResult struct {
	TenantID     string                `json:"tenant_id"`
	ImpactSource RevisionProvenance    `json:"impact_source"`
	MappingSet   MappingSetRevision    `json:"mapping_set"`
	Complete     bool                  `json:"complete"`
	Targets      []CompatibilityTarget `json:"targets"`
	Issues       []AdapterIssue        `json:"issues"`
}

// AdaptCompatibility translates canonical impact output through explicit,
// exact-revision mappings. It performs no external I/O and returns no partial
// output when request validation or a configured work limit fails.
func AdaptCompatibility(request AdapterRequest) (AdapterResult, error) {
	request.TenantID = strings.TrimSpace(request.TenantID)
	if err := validateAdapterRequest(request); err != nil {
		return AdapterResult{}, err
	}

	sources, err := collectImpactSources(request.TenantID, request.Impact)
	if err != nil {
		return AdapterResult{}, err
	}
	if uint64(len(sources)) > uint64(request.Limits.MaxSources) {
		return AdapterResult{}, fmt.Errorf("%w: sources %d exceed max_sources %d", ErrAdapterLimit, len(sources), request.Limits.MaxSources)
	}
	mappingsBySource := make(map[string][]CompatibilityMapping, len(request.Mappings))
	for _, mapping := range request.Mappings {
		normalized, err := normalizeMapping(mapping)
		if err != nil {
			return AdapterResult{}, fmt.Errorf("%w: mapping normalization: %w", ErrInvalidAdapterRequest, err)
		}
		key := provenanceKey(normalized.Source)
		mappingsBySource[key] = append(mappingsBySource[key], normalized)
	}
	for key := range mappingsBySource {
		mappingsBySource[key] = deduplicateMappings(mappingsBySource[key])
	}

	targetBuilders := map[string]*compatibilityTargetBuilder{}
	issues := make([]AdapterIssue, 0)
	for _, source := range sources {
		mappings := mappingsBySource[provenanceKey(source.Revision)]
		if len(mappings) == 0 {
			issues = append(issues, AdapterIssue{Code: ReasonUnmappedTarget, Source: source.Revision})
			continue
		}

		mapped := false
		byKind := mappingsByTargetKind(mappings)
		for _, kind := range orderedTargetKinds() {
			kindMappings := byKind[kind]
			if len(kindMappings) == 0 {
				continue
			}
			ids := distinctTargetIDs(kindMappings)
			if len(ids) != 1 {
				issues = append(issues, AdapterIssue{Code: ReasonAmbiguousTarget, Source: source.Revision, TargetKind: kind, CandidateIDs: ids})
				continue
			}
			mapped = true
			targetKey := string(kind) + "\x00" + ids[0]
			builder := targetBuilders[targetKey]
			if builder == nil {
				builder = &compatibilityTargetBuilder{kind: kind, id: ids[0], sources: map[string]MappedImpactSource{}, actions: map[string]map[ReasonCode]struct{}{}}
				targetBuilders[targetKey] = builder
			}
			builder.addSource(source)
			for _, mapping := range kindMappings {
				if mapping.TargetID != ids[0] {
					continue
				}
				for _, actionID := range mapping.ActionIDs {
					builder.addAction(actionID, source.Reasons)
				}
			}
		}
		if !mapped && !hasAmbiguityForSource(issues, source.Revision) {
			issues = append(issues, AdapterIssue{Code: ReasonUnmappedTarget, Source: source.Revision})
		}
	}
	for _, issue := range request.Impact.Issues {
		source := issue.Revision
		if source.ExactKey() == "" {
			source = request.Impact.Signal.Revision()
		}
		issues = append(issues, AdapterIssue{Code: ReasonImpactIncomplete, Source: provenance(source), ImpactReason: issue.Code})
	}
	if uint64(len(issues)) > uint64(request.Limits.MaxIssues) {
		return AdapterResult{}, fmt.Errorf("%w: issues %d exceed max_issues %d", ErrAdapterLimit, len(issues), request.Limits.MaxIssues)
	}

	if uint64(len(targetBuilders)) > uint64(request.Limits.MaxTargets) {
		return AdapterResult{}, fmt.Errorf("%w: targets %d exceed max_targets %d", ErrAdapterLimit, len(targetBuilders), request.Limits.MaxTargets)
	}
	targets := make([]CompatibilityTarget, 0, len(targetBuilders))
	actionCount := 0
	for _, builder := range targetBuilders {
		target := builder.build()
		actionCount += len(target.Actions)
		targets = append(targets, target)
	}
	if uint64(actionCount) > uint64(request.Limits.MaxActions) {
		return AdapterResult{}, fmt.Errorf("%w: actions %d exceed max_actions %d", ErrAdapterLimit, actionCount, request.Limits.MaxActions)
	}
	sort.Slice(targets, func(i, j int) bool {
		return string(targets[i].Kind)+"\x00"+targets[i].ID < string(targets[j].Kind)+"\x00"+targets[j].ID
	})
	issues = canonicalizeAdapterIssues(issues)
	result := AdapterResult{
		TenantID:     request.TenantID,
		ImpactSource: provenance(request.Impact.Signal.Revision()),
		MappingSet: MappingSetRevision{
			RevisionID:    strings.TrimSpace(request.MappingSet.RevisionID),
			ContentDigest: compliance.ContentDigest(strings.TrimSpace(string(request.MappingSet.ContentDigest))),
		},
		Complete: request.Impact.Complete && len(issues) == 0,
		Targets:  targets,
		Issues:   issues,
	}
	return result, nil
}

// CanonicalAdapterBytes provides stable replay bytes for an already adapted
// result. AdapterResult intentionally contains no maps.
func CanonicalAdapterBytes(result AdapterResult) ([]byte, error) {
	return json.Marshal(result)
}

func validateAdapterRequest(request AdapterRequest) error {
	tenantID := strings.TrimSpace(request.TenantID)
	if tenantID == "" || len(tenantID) > 255 || strings.ContainsRune(tenantID, '\x00') {
		return fmt.Errorf("%w: tenant_id is required and must be bounded", ErrInvalidAdapterRequest)
	}
	if request.Impact.TenantID != tenantID || request.Impact.Signal.Revision().TenantID() != tenantID {
		return fmt.Errorf("%w: impact tenant does not match request", ErrAdapterTenantBoundary)
	}
	if request.Impact.Signal.Revision().ExactKey() == "" {
		return fmt.Errorf("%w: impact source revision is required", ErrInvalidAdapterRequest)
	}
	if err := validateAdapterLimits(request.Limits); err != nil {
		return err
	}
	rawSources := 1 + len(request.Impact.Programs) + len(request.Impact.Plans) + len(request.Impact.Objectives) + len(request.Impact.Packages) + len(request.Impact.WorkItems) + len(request.Impact.Invalidations)
	if uint64(rawSources) > uint64(request.Limits.MaxSources) {
		return fmt.Errorf("%w: input sources %d exceed max_sources %d", ErrAdapterLimit, rawSources, request.Limits.MaxSources)
	}
	if uint64(len(request.Impact.Issues)) > uint64(request.Limits.MaxIssues) {
		return fmt.Errorf("%w: input issues %d exceed max_issues %d", ErrAdapterLimit, len(request.Impact.Issues), request.Limits.MaxIssues)
	}
	for index, issue := range request.Impact.Issues {
		for _, entry := range []struct {
			label string
			ref   complianceintegration.RevisionRef
		}{{label: "revision", ref: issue.Revision}, {label: "related", ref: issue.Related}} {
			if entry.ref.ExactKey() == "" {
				continue
			}
			if entry.ref.TenantID() != tenantID {
				return fmt.Errorf("%w: impact issue[%d] %s crosses tenant boundary", ErrAdapterTenantBoundary, index, entry.label)
			}
		}
	}
	if uint64(len(request.Mappings)) > uint64(request.Limits.MaxMappings) {
		return fmt.Errorf("%w: mappings %d exceed max_mappings %d", ErrAdapterLimit, len(request.Mappings), request.Limits.MaxMappings)
	}
	if !boundedValue(request.MappingSet.RevisionID, 512) {
		return fmt.Errorf("%w: mapping_set revision_id is required and must be bounded", ErrInvalidAdapterRequest)
	}
	if err := compliance.ValidateContentDigest(compliance.ContentDigest(strings.TrimSpace(string(request.MappingSet.ContentDigest)))); err != nil {
		return fmt.Errorf("%w: mapping_set content_digest: %w", ErrInvalidAdapterRequest, err)
	}
	inputActions := uint64(0)
	for index, mapping := range request.Mappings {
		if strings.TrimSpace(mapping.TenantID) != tenantID || strings.TrimSpace(mapping.Source.TenantID) != tenantID {
			return fmt.Errorf("%w: mapping[%d] crosses tenant boundary", ErrAdapterTenantBoundary, index)
		}
		if _, err := revisionFromProvenance(mapping.Source); err != nil {
			return fmt.Errorf("%w: mapping[%d] source: %w", ErrInvalidAdapterRequest, index, err)
		}
		if !validCompatibilityTargetKind(mapping.TargetKind) {
			return fmt.Errorf("%w: mapping[%d] target_kind %q", ErrInvalidAdapterRequest, index, mapping.TargetKind)
		}
		if !boundedValue(mapping.TargetID, 1024) {
			return fmt.Errorf("%w: mapping[%d] target_id is required and must be bounded", ErrInvalidAdapterRequest, index)
		}
		if len(mapping.ActionIDs) == 0 {
			return fmt.Errorf("%w: mapping[%d] requires at least one action_id", ErrInvalidAdapterRequest, index)
		}
		for actionIndex, actionID := range mapping.ActionIDs {
			if !adapterIdentifierPattern.MatchString(strings.ToLower(strings.TrimSpace(actionID))) {
				return fmt.Errorf("%w: mapping[%d] action_ids[%d] is invalid", ErrInvalidAdapterRequest, index, actionIndex)
			}
		}
		var ok bool
		inputActions, ok = addAdapterActionCount(inputActions, len(mapping.ActionIDs))
		if !ok {
			return fmt.Errorf("%w: input actions exceed uint64 capacity", ErrAdapterLimit)
		}
	}
	if adapterActionCountExceedsLimit(inputActions, request.Limits.MaxActions) {
		return fmt.Errorf("%w: input actions %d exceed max_actions %d", ErrAdapterLimit, inputActions, request.Limits.MaxActions)
	}
	return nil
}

func addAdapterActionCount(current uint64, additional int) (uint64, bool) {
	if additional < 0 {
		return current, false
	}
	added := uint64(additional)
	if current > ^uint64(0)-added {
		return current, false
	}
	return current + added, true
}

func adapterActionCountExceedsLimit(count uint64, limit uint32) bool {
	return count > uint64(limit)
}

func validateAdapterLimits(limits AdapterLimits) error {
	if limits.MaxMappings == 0 || limits.MaxSources == 0 || limits.MaxTargets == 0 || limits.MaxActions == 0 || limits.MaxIssues == 0 ||
		limits.MaxMappings > maxAdapterMappings || limits.MaxSources > maxAdapterSources || limits.MaxTargets > maxAdapterTargets ||
		limits.MaxActions > maxAdapterActions || limits.MaxIssues > maxAdapterIssues {
		return fmt.Errorf("%w: limits must be non-zero and within hard ceilings", ErrInvalidAdapterRequest)
	}
	return nil
}

func collectImpactSources(tenantID string, impact Result) ([]MappedImpactSource, error) {
	values := map[string]MappedImpactSource{}
	add := func(value MappedImpactSource) error {
		if value.Revision.TenantID != tenantID {
			return fmt.Errorf("%w: affected revision crosses tenant boundary", ErrAdapterTenantBoundary)
		}
		ref, err := revisionFromProvenance(value.Revision)
		if err != nil {
			return fmt.Errorf("%w: affected revision: %w", ErrInvalidAdapterRequest, err)
		}
		key := ref.ExactKey()
		value.Reasons = canonicalReasons(value.Reasons)
		value.Relations = canonicalStrings(value.Relations)
		if existing, ok := values[key]; ok {
			existing.Reasons = canonicalReasons(append(existing.Reasons, value.Reasons...))
			existing.Relations = canonicalStrings(append(existing.Relations, value.Relations...))
			if value.Distance < existing.Distance {
				existing.Distance = value.Distance
			}
			values[key] = existing
			return nil
		}
		values[key] = value
		return nil
	}
	root := impact.Signal.Revision()
	if err := add(MappedImpactSource{Revision: provenance(root), Reasons: []ReasonCode{adapterDirectReason(impact.Signal.Kind())}}); err != nil {
		return nil, err
	}
	for _, facts := range [][]AffectedFact{impact.Programs, impact.Plans, impact.Objectives, impact.Packages, impact.WorkItems} {
		for _, fact := range facts {
			if err := add(MappedImpactSource{Revision: provenance(fact.Revision), Reasons: fact.Reasons, Relations: fact.Relations, Distance: fact.Distance}); err != nil {
				return nil, err
			}
		}
	}
	for _, invalidation := range impact.Invalidations {
		if err := add(MappedImpactSource{Revision: provenance(invalidation.Revision), Reasons: []ReasonCode{invalidation.Reason}}); err != nil {
			return nil, err
		}
	}
	result := make([]MappedImpactSource, 0, len(values))
	for _, value := range values {
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool { return provenanceKey(result[i].Revision) < provenanceKey(result[j].Revision) })
	return result, nil
}

func adapterDirectReason(kind complianceintegration.ChangeKind) ReasonCode {
	switch kind {
	case complianceintegration.ChangeDeleted:
		return ReasonRevisionDeleted
	case complianceintegration.ChangeRevoked:
		return ReasonRevisionRevoked
	default:
		return ReasonRevisionChanged
	}
}

func provenance(ref complianceintegration.RevisionRef) RevisionProvenance {
	canonical := ref.Canonical()
	return RevisionProvenance{
		TenantID: ref.TenantID(), Domain: ref.Domain(), Kind: ref.Kind(), ID: canonical.ID,
		RevisionID: canonical.RevisionID, Version: canonical.Version, ContentDigest: canonical.ContentDigest,
		LastModified: canonical.LastModified,
	}
}

func revisionFromProvenance(value RevisionProvenance) (complianceintegration.RevisionRef, error) {
	return complianceintegration.AdaptRevisionRef(value.TenantID, value.Domain, value.Kind, compliance.RevisionRef{
		ID: value.ID, RevisionID: value.RevisionID, Version: value.Version,
		ContentDigest: value.ContentDigest, LastModified: value.LastModified,
	})
}

func provenanceKey(value RevisionProvenance) string {
	ref, err := revisionFromProvenance(value)
	if err != nil {
		return ""
	}
	return ref.ExactKey()
}

func normalizeMapping(value CompatibilityMapping) (CompatibilityMapping, error) {
	value.TenantID = strings.TrimSpace(value.TenantID)
	value.TargetKind = CompatibilityTargetKind(strings.ToLower(strings.TrimSpace(string(value.TargetKind))))
	value.TargetID = strings.TrimSpace(value.TargetID)
	value.ActionIDs = canonicalStringsLower(value.ActionIDs)
	ref, err := revisionFromProvenance(value.Source)
	if err != nil {
		return CompatibilityMapping{}, err
	}
	value.Source = provenance(ref)
	return value, nil
}

func deduplicateMappings(values []CompatibilityMapping) []CompatibilityMapping {
	sort.Slice(values, func(i, j int) bool { return mappingKey(values[i]) < mappingKey(values[j]) })
	result := make([]CompatibilityMapping, 0, len(values))
	for _, value := range values {
		if len(result) != 0 && mappingKey(result[len(result)-1]) == mappingKey(value) {
			continue
		}
		result = append(result, value)
	}
	return result
}

func mappingKey(value CompatibilityMapping) string {
	return provenanceKey(value.Source) + "\x00" + string(value.TargetKind) + "\x00" + value.TargetID + "\x00" + strings.Join(value.ActionIDs, "\x00")
}

func mappingsByTargetKind(values []CompatibilityMapping) map[CompatibilityTargetKind][]CompatibilityMapping {
	result := map[CompatibilityTargetKind][]CompatibilityMapping{}
	for _, value := range values {
		result[value.TargetKind] = append(result[value.TargetKind], value)
	}
	return result
}

func distinctTargetIDs(values []CompatibilityMapping) []string {
	ids := make([]string, 0, len(values))
	for _, value := range values {
		ids = append(ids, value.TargetID)
	}
	return canonicalStrings(ids)
}

func orderedTargetKinds() []CompatibilityTargetKind {
	return []CompatibilityTargetKind{TargetAccessReview, TargetFinding, TargetPolicy, TargetQuestionnaire, TargetVendor}
}

func validCompatibilityTargetKind(value CompatibilityTargetKind) bool {
	value = CompatibilityTargetKind(strings.ToLower(strings.TrimSpace(string(value))))
	for _, candidate := range orderedTargetKinds() {
		if value == candidate {
			return true
		}
	}
	return false
}

func boundedValue(value string, maximum int) bool {
	value = strings.TrimSpace(value)
	return value != "" && len(value) <= maximum && !strings.ContainsRune(value, '\x00')
}

func canonicalReasons(values []ReasonCode) []ReasonCode {
	seen := map[ReasonCode]struct{}{}
	for _, value := range values {
		if value != "" {
			seen[value] = struct{}{}
		}
	}
	result := make([]ReasonCode, 0, len(seen))
	for value := range seen {
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}

func canonicalStrings(values []string) []string {
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			seen[value] = struct{}{}
		}
	}
	result := make([]string, 0, len(seen))
	for value := range seen {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func canonicalStringsLower(values []string) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = strings.ToLower(strings.TrimSpace(value))
	}
	return canonicalStrings(result)
}

type compatibilityTargetBuilder struct {
	kind    CompatibilityTargetKind
	id      string
	sources map[string]MappedImpactSource
	actions map[string]map[ReasonCode]struct{}
}

func (b *compatibilityTargetBuilder) addSource(source MappedImpactSource) {
	b.sources[provenanceKey(source.Revision)] = source
}

func (b *compatibilityTargetBuilder) addAction(actionID string, reasons []ReasonCode) {
	actionID = strings.ToLower(strings.TrimSpace(actionID))
	values := b.actions[actionID]
	if values == nil {
		values = map[ReasonCode]struct{}{}
		b.actions[actionID] = values
	}
	for _, reason := range reasons {
		values[reason] = struct{}{}
	}
}

func (b *compatibilityTargetBuilder) build() CompatibilityTarget {
	result := CompatibilityTarget{Kind: b.kind, ID: b.id}
	for _, source := range b.sources {
		result.Sources = append(result.Sources, source)
	}
	sort.Slice(result.Sources, func(i, j int) bool {
		return provenanceKey(result.Sources[i].Revision) < provenanceKey(result.Sources[j].Revision)
	})
	for actionID, reasonSet := range b.actions {
		reasons := make([]ReasonCode, 0, len(reasonSet))
		for reason := range reasonSet {
			reasons = append(reasons, reason)
		}
		reasons = canonicalReasons(reasons)
		result.Actions = append(result.Actions, ActionCandidate{ActionID: actionID, Reasons: reasons})
	}
	sort.Slice(result.Actions, func(i, j int) bool { return result.Actions[i].ActionID < result.Actions[j].ActionID })
	return result
}

func hasAmbiguityForSource(issues []AdapterIssue, source RevisionProvenance) bool {
	key := provenanceKey(source)
	for _, issue := range issues {
		if issue.Code == ReasonAmbiguousTarget && provenanceKey(issue.Source) == key {
			return true
		}
	}
	return false
}

func canonicalizeAdapterIssues(values []AdapterIssue) []AdapterIssue {
	for index := range values {
		values[index].CandidateIDs = canonicalStrings(values[index].CandidateIDs)
	}
	sort.Slice(values, func(i, j int) bool { return adapterIssueKey(values[i]) < adapterIssueKey(values[j]) })
	write := 0
	for _, value := range values {
		if write != 0 && adapterIssueKey(values[write-1]) == adapterIssueKey(value) {
			continue
		}
		values[write] = value
		write++
	}
	for index := write; index < len(values); index++ {
		values[index] = AdapterIssue{}
	}
	return values[:write]
}

func adapterIssueKey(value AdapterIssue) string {
	return string(value.Code) + "\x00" + provenanceKey(value.Source) + "\x00" + string(value.TargetKind) + "\x00" + strings.Join(value.CandidateIDs, "\x00") + "\x00" + string(value.ImpactReason)
}
