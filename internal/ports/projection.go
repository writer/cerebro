package ports

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/projectionmeta"
	cerebrourn "github.com/writer/cerebro/internal/urn"
)

// ErrProjectedTenantScope indicates that a Cerebro-owned projection URN does
// not belong to the tenant receiving the projection.
var ErrProjectedTenantScope = errors.New("projected URN tenant scope mismatch")

// ErrApplicationWorkspaceConflict marks an attempt to move one tenant-global
// graph identity between application workspaces without an explicit migration.
var ErrApplicationWorkspaceConflict = errors.New("application workspace projection conflict")

const maxApplicationWorkspaceIDBytes = 128

// ProjectedTenantScopeError identifies the rejected projection field and both
// tenant scopes without requiring callers to parse an error string.
type ProjectedTenantScopeError struct {
	Field              string
	URN                string
	URNTenantID        string
	ProjectionTenantID string
}

func (err *ProjectedTenantScopeError) Error() string {
	return fmt.Sprintf(
		"%s %q is scoped to tenant %q, not projection tenant %q",
		err.Field, err.URN, err.URNTenantID, err.ProjectionTenantID,
	)
}

func (err *ProjectedTenantScopeError) Unwrap() error { return ErrProjectedTenantScope }

// ProjectedEntity is the normalized current-state and graph entity shape.
type ProjectedEntity struct {
	URN                    string
	TenantID               string
	ApplicationWorkspaceID string
	SourceID               string
	RuntimeID              string
	EntityType             string
	Label                  string
	Attributes             map[string]string
	// CreateOnly marks a minimal endpoint materialization, such as the
	// canonical principal a finding links to before that principal's
	// provider connector has projected it. A store creates the entity when
	// it is absent and otherwise changes nothing: the existing entity's
	// typed ownership, label, and attributes stay exactly as their owner
	// projected them. A page that also carries an ordinary upsert for the
	// same URN applies the ordinary upsert instead.
	CreateOnly bool
	// RetractedAttributes lists attribute keys this observation owns but no
	// longer carries, for example triage fields a source cleared on a newer
	// finding version. A store removes them only when it accepts the
	// observation: a stale strict-precedence observation changes nothing.
	// Keys the observation does carry are never listed.
	RetractedAttributes []string
}

// ProjectedLink is the normalized graph edge shape.
type ProjectedLink struct {
	TenantID               string
	ApplicationWorkspaceID string
	SourceID               string
	RuntimeID              string
	FromURN                string
	ToURN                  string
	Relation               string
	Attributes             map[string]string
}

// ProjectedLinkSet is the complete desired set of links between one owner
// entity and its counterparts for one relation, direction, and source
// runtime. A projector that holds the complete current state for that scope
// (for example, a cloud-identity principal's current Kubernetes service
// account consumers) emits this instead of plain links: the graph store
// applies it as a single guarded replacement rather than individual
// upserts, ordering the set's Observation against the last one it applied
// for the same scope so a stale or reordered observation can never retract
// or re-add links a newer observation already settled.
type ProjectedLinkSet struct {
	TenantID  string
	SourceID  string
	RuntimeID string
	OwnerURN  string
	Relation  string
	// Outgoing reports whether OwnerURN is each link's FromURN (true) or
	// ToURN (false).
	Outgoing bool
	// Links is the complete desired set for (OwnerURN, Relation, Outgoing,
	// RuntimeID). Every element's FromURN/ToURN/Relation/TenantID/SourceID/
	// RuntimeID must already match the set's own scope.
	Links []*ProjectedLink
	// Observation carries the owner observation attributes
	// (observation_precedence, observation_version, at), ordered through
	// projectionmeta.CompareObservations against the store's last applied
	// observation for this exact owner/relation/direction/runtime scope.
	Observation map[string]string
	// Incomplete marks an accepted owner observation whose link context was
	// unavailable or truncated, so it cannot describe the complete desired
	// set. A store advances the scope's observation guard when the
	// observation is not older than the stored one, so an older complete
	// set can no longer replace links once this newer observation is
	// accepted, but it neither retracts nor asserts links. Links must be
	// empty.
	Incomplete bool
	// Endpoints lists minimal CreateOnly materializations of counterpart
	// entities the set's Links name (never the owner). A store creates each
	// absent endpoint inside the same guarded operation that accepts the
	// set, before asserting Links, and creates nothing when it rejects the
	// set as stale; an Incomplete set carries none. An existing endpoint
	// stays exactly as its owner projected it. Projectors put counterpart
	// stubs here instead of the ordinary entity list so a stale or losing
	// observation can never materialize them.
	Endpoints []*ProjectedEntity
}

// ProjectionLinkSetStore replaces a projector's complete link set for one
// owner/relation/direction/runtime scope in one guarded store operation.
type ProjectionLinkSetStore interface {
	ReplaceProjectedLinkSets(context.Context, []*ProjectedLinkSet) error
}

// ErrProjectionLinkSetStoreUnsupported marks a configured state or graph
// store that cannot apply a guarded link set (Contract C9). Falling back
// to the plain link upsert path would silently reintroduce links a newer
// observation already retracted, so an event or page that actually carries
// link sets fails closed instead of writing around the guard; events and
// pages without link sets are completely unaffected.
var ErrProjectionLinkSetStoreUnsupported = errors.New("configured store does not support guarded link set replacement")

// ProjectedLinkSetOwnerKey identifies one (tenant, source, runtime, owner,
// relation, direction) link-set scope so callers can coalesce multiple
// link sets and test plain links for coverage against the same scope.
func ProjectedLinkSetOwnerKey(set *ProjectedLinkSet) string {
	if set == nil {
		return ""
	}
	direction := "0"
	if set.Outgoing {
		direction = "1"
	}
	return strings.Join([]string{set.TenantID, set.SourceID, set.RuntimeID, set.OwnerURN, set.Relation, direction}, "\x00")
}

// ProjectedLinkCoveredByLinkSets reports whether a plain link falls inside
// the owner/relation/direction/tenant/source/runtime scope of any of the
// given link sets. Covered links must never flow through the plain link
// upsert path: the link set is authoritative for that scope.
func ProjectedLinkCoveredByLinkSets(link *ProjectedLink, sets []*ProjectedLinkSet) bool {
	if link == nil || len(sets) == 0 {
		return false
	}
	for _, set := range sets {
		if set == nil {
			continue
		}
		if set.TenantID != link.TenantID || set.SourceID != link.SourceID || set.RuntimeID != link.RuntimeID || set.Relation != link.Relation {
			continue
		}
		owner := link.ToURN
		if set.Outgoing {
			owner = link.FromURN
		}
		if owner == set.OwnerURN {
			return true
		}
	}
	return false
}

// CoalesceProjectedLinkSet keeps only the winning observation for one owner
// key within a batch: projectionmeta orders every pair of observations the
// same way a store orders an incoming set against stored state, so the two
// can never disagree about which observation a single write reflects.
func CoalesceProjectedLinkSet(sets map[string]*ProjectedLinkSet, set *ProjectedLinkSet) {
	if set == nil {
		return
	}
	key := ProjectedLinkSetOwnerKey(set)
	if existing, ok := sets[key]; ok && projectionmeta.CompareObservations(existing.Observation, set.Observation) == projectionmeta.ObservationOlder {
		return
	}
	sets[key] = set
}

// ApplyRetractedAttributes deletes from attributes each key named by
// retracted that incoming does not carry, then returns attributes for
// convenient chaining. Contract G1 requires this check against the exact
// observation that named the key retracted (incoming), never against a
// merged or coalesced result: a key present in Attributes must never be
// removed. Callers apply it only for an accepted observation; a stale
// strict-precedence observation must skip calling this entirely.
func ApplyRetractedAttributes(attributes map[string]string, incoming map[string]string, retracted []string) map[string]string {
	for _, key := range retracted {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		if _, present := incoming[key]; present {
			continue
		}
		delete(attributes, key)
	}
	return attributes
}

// CoalesceRetractedAttributes unions two RetractedAttributes lists observed
// for the same URN within one page or batch, minus whichever keys the final
// coalesced attributes still carry (Contract G1's page/batch coalescing
// rule for two ordinary entities). Callers still delete each incoming
// observation's own retracted keys from the coalesced attributes through
// ApplyRetractedAttributes; this only recomputes the field to keep
// forwarding toward the store, which may hold an even earlier page's value
// for a key neither coalesced observation mentions.
func CoalesceRetractedAttributes(attributes map[string]string, first []string, second []string) []string {
	if len(first) == 0 && len(second) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(first)+len(second))
	collect := func(keys []string) {
		for _, key := range keys {
			key = strings.TrimSpace(key)
			if key == "" {
				continue
			}
			seen[key] = struct{}{}
		}
	}
	collect(first)
	collect(second)
	if len(seen) == 0 {
		return nil
	}
	merged := make([]string, 0, len(seen))
	for key := range seen {
		if _, present := attributes[key]; present {
			continue
		}
		merged = append(merged, key)
	}
	if len(merged) == 0 {
		return nil
	}
	sort.Strings(merged)
	return merged
}

// NormalizeApplicationWorkspaceID validates one opaque application workspace
// selector. Blank is the backward-compatible tenant-wide legacy scope.
func NormalizeApplicationWorkspaceID(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	if len(value) > maxApplicationWorkspaceIDBytes || !utf8.ValidString(value) || value == "*" || strings.Contains(value, ",") {
		return "", fmt.Errorf("invalid application workspace id")
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return "", fmt.Errorf("invalid application workspace id")
		}
	}
	return value, nil
}

// ValidateApplicationWorkspaceScope requires application workspaces to remain
// nested under an explicit tenant. The workspace ID is intentionally opaque;
// tenant qualification comes from this pair rather than provider payload data.
func ValidateApplicationWorkspaceScope(tenantID string, workspaceID string) (string, error) {
	workspaceID, err := NormalizeApplicationWorkspaceID(workspaceID)
	if err != nil {
		return "", err
	}
	if workspaceID != "" && strings.TrimSpace(tenantID) == "" {
		return "", fmt.Errorf("application workspace id requires tenant id")
	}
	return workspaceID, nil
}

// ValidateProjectedTenantScopes rejects Cerebro-owned projection URNs that do
// not belong to the projection tenant. Provider-native identifiers remain valid.
func ValidateProjectedTenantScopes(entities []*ProjectedEntity, links []*ProjectedLink) error {
	for _, entity := range entities {
		if err := ValidateProjectedEntityTenantScope(entity); err != nil {
			return err
		}
	}
	for _, link := range links {
		if err := ValidateProjectedLinkTenantScope(link); err != nil {
			return err
		}
	}
	return nil
}

// ValidateProjectedLinkSetTenantScope enforces that a Cerebro-owned link-set
// owner URN, and every link in the set, cannot be projected under a
// different tenant_id.
func ValidateProjectedLinkSetTenantScope(set *ProjectedLinkSet) error {
	if set == nil {
		return nil
	}
	if err := validateProjectedCerebroURNScope("projected link set owner urn", set.OwnerURN, set.TenantID); err != nil {
		return err
	}
	for _, link := range set.Links {
		if err := ValidateProjectedLinkTenantScope(link); err != nil {
			return err
		}
	}
	return nil
}

// ValidateProjectedLinkSetIncomplete rejects an Incomplete link-set
// observation that also carries links (Contract G1): Incomplete describes
// unknown or truncated link context, so it can never also assert a
// complete desired set. Every store that implements ProjectionLinkSetStore
// must reject this combination before applying the guard.
func ValidateProjectedLinkSetIncomplete(set *ProjectedLinkSet) error {
	if set == nil || !set.Incomplete || len(set.Links) == 0 {
		return nil
	}
	return fmt.Errorf("projected link set %q %q: incomplete observation must not carry links", set.OwnerURN, set.Relation)
}

// ValidateProjectedLinkSetEndpoints enforces the Endpoints contract: an
// Incomplete set carries none, and every endpoint is a tenant/source/
// runtime-scoped CreateOnly materialization of a counterpart some link in
// the set names. The source and runtime must equal the set's own, not
// merely the owner's: an endpoint carrying a blank or mismatched runtime
// would otherwise reach a store or compatibility delta without the
// provenance ordinary projected entities always carry. Every store that
// implements ProjectionLinkSetStore must reject a violation before
// applying the guard.
func ValidateProjectedLinkSetEndpoints(set *ProjectedLinkSet) error {
	if set == nil || len(set.Endpoints) == 0 {
		return nil
	}
	if set.Incomplete {
		return fmt.Errorf("projected link set %q %q: incomplete observation must not carry endpoints", set.OwnerURN, set.Relation)
	}
	counterparts := make(map[string]struct{}, len(set.Links))
	for _, link := range set.Links {
		if link == nil {
			continue
		}
		counterpart := link.FromURN
		if set.Outgoing {
			counterpart = link.ToURN
		}
		counterparts[strings.TrimSpace(counterpart)] = struct{}{}
	}
	for _, endpoint := range set.Endpoints {
		if endpoint == nil {
			return fmt.Errorf("projected link set %q %q: endpoint is required", set.OwnerURN, set.Relation)
		}
		if !endpoint.CreateOnly {
			return fmt.Errorf("projected link set %q %q: endpoint %q must be create-only", set.OwnerURN, set.Relation, endpoint.URN)
		}
		if strings.TrimSpace(endpoint.TenantID) != strings.TrimSpace(set.TenantID) {
			return fmt.Errorf("projected link set %q %q: endpoint %q tenant does not match the set", set.OwnerURN, set.Relation, endpoint.URN)
		}
		if strings.TrimSpace(endpoint.SourceID) != strings.TrimSpace(set.SourceID) {
			return fmt.Errorf("projected link set %q %q: endpoint %q source does not match the set", set.OwnerURN, set.Relation, endpoint.URN)
		}
		if strings.TrimSpace(endpoint.RuntimeID) != strings.TrimSpace(set.RuntimeID) {
			return fmt.Errorf("projected link set %q %q: endpoint %q runtime does not match the set", set.OwnerURN, set.Relation, endpoint.URN)
		}
		if err := ValidateProjectedEntityTenantScope(endpoint); err != nil {
			return err
		}
		if _, ok := counterparts[strings.TrimSpace(endpoint.URN)]; !ok {
			return fmt.Errorf("projected link set %q %q: endpoint %q is not a counterpart of any link in the set", set.OwnerURN, set.Relation, endpoint.URN)
		}
	}
	return nil
}

// ValidateProjectedLinkSetsTenantScopes validates every link set in a page.
func ValidateProjectedLinkSetsTenantScopes(sets []*ProjectedLinkSet) error {
	for _, set := range sets {
		if err := ValidateProjectedLinkSetTenantScope(set); err != nil {
			return err
		}
	}
	return nil
}

// ValidateProjectedEntityTenantScope enforces that a Cerebro-owned entity URN
// cannot be projected under a different tenant_id.
func ValidateProjectedEntityTenantScope(entity *ProjectedEntity) error {
	if entity == nil {
		return nil
	}
	if _, err := ValidateApplicationWorkspaceScope(entity.TenantID, entity.ApplicationWorkspaceID); err != nil {
		return err
	}
	return validateProjectedCerebroURNScope("projected entity urn", entity.URN, entity.TenantID)
}

// ValidateProjectedLinkTenantScope enforces that Cerebro-owned link endpoints
// cannot be projected under a different tenant_id.
func ValidateProjectedLinkTenantScope(link *ProjectedLink) error {
	if link == nil {
		return nil
	}
	if _, err := ValidateApplicationWorkspaceScope(link.TenantID, link.ApplicationWorkspaceID); err != nil {
		return err
	}
	if err := validateProjectedCerebroURNScope("projected link from urn", link.FromURN, link.TenantID); err != nil {
		return err
	}
	return validateProjectedCerebroURNScope("projected link to urn", link.ToURN, link.TenantID)
}

func validateProjectedCerebroURNScope(field string, rawURN string, rawTenantID string) error {
	urn := strings.TrimSpace(rawURN)
	tenantID := strings.TrimSpace(rawTenantID)
	if urn == "" || tenantID == "" || !strings.HasPrefix(urn, cerebrourn.Prefix) {
		return nil
	}
	parsed, err := cerebrourn.Parse(urn)
	if err != nil {
		return fmt.Errorf("%s %q is invalid: %w", field, urn, err)
	}
	if parsed.TenantID != tenantID {
		return &ProjectedTenantScopeError{
			Field: field, URN: urn, URNTenantID: parsed.TenantID, ProjectionTenantID: tenantID,
		}
	}
	return nil
}

// ProjectionResult reports how many workflow events, entities, and links were materialized or pruned.
type ProjectionResult struct {
	EventsProjected   uint32
	EntitiesProjected uint32
	LinksProjected    uint32
	EntitiesDeleted   uint32
	LinksDeleted      uint32
}

// SourceProjectionDelta preserves the exact normalized compatibility output
// produced for one append-log event while Rust assumes projection authority
// one source family at a time.
type SourceProjectionDelta struct {
	Entities          []*ProjectedEntity
	Links             []*ProjectedLink
	EntityRetractions []string
	LinkRetractions   []*ProjectedLink
	CleanupRequests   []ProjectionCleanupRequest
	// LinkSets are the guarded Contract C9 link sets applied for this
	// event, carried here so the legacy Rust parity delta reflects links
	// a plain-link-covered upsert would otherwise have hidden.
	LinkSets []*ProjectedLinkSet
}

// ProjectionCleanupRequest scopes opportunistic graph cleanup to one tenant/source/runtime boundary.
type ProjectionCleanupRequest struct {
	TenantID     string
	SourceID     string
	RuntimeID    string
	FindingID    string
	EntityTypes  []string
	URNPrefixes  []string
	OnlyIsolated bool
	Limit        uint32
	DryRun       bool
}

// ProjectionCleanupResult reports graph objects removed by one cleanup pass.
type ProjectionCleanupResult struct {
	EntitiesMatched uint32
	LinksMatched    uint32
	EntitiesDeleted uint32
	LinksDeleted    uint32
	// LinksMigrated counts legacy logical links the pass converted from
	// pre-assertion-model coverage (no entity_link_assertions/
	// RELATION_ASSERTION row at all) into a real assertion scoped to
	// their own already-recorded tenant/source/runtime, before deleting
	// this scope's assertions. It never includes a row the store already
	// flagged as having conflicting (quarantined) provenance from another
	// writer: those are reported as still matched-but-undeleted instead.
	LinksMigrated uint32
}

// ProjectionLinkCleanupRequest scopes a destructive projection-link cleanup pass.
type ProjectionLinkCleanupRequest struct {
	TenantID  string
	SourceID  string
	RuntimeID string
	Limit     uint32
	DryRun    bool
}

// ProjectionLinkCleanupResult reports links found/deleted by one cleanup pass.
type ProjectionLinkCleanupResult struct {
	LinksMatched uint32
	LinksDeleted uint32
}

// ProjectionRuntimeLinkReconciliationRequest removes material links that were
// not observed during one complete authoritative runtime collection.
type ProjectionRuntimeLinkReconciliationRequest struct {
	TenantID         string
	SourceID         string
	RuntimeID        string
	ReconciliationID string
	Relations        []string
	Limit            uint32
	DryRun           bool
}

// ProjectionAssertionMigrationRequest scopes an idempotent migration of
// legacy logical material links into source-runtime assertions.
type ProjectionAssertionMigrationRequest struct {
	TenantID  string
	Relations []string
	Limit     uint32
	DryRun    bool
}

// ProjectionAssertionMigrationResult reports legacy links considered,
// migrated, and quarantined because their recorded provenance is incomplete.
type ProjectionAssertionMigrationResult struct {
	LinksMatched     uint32
	LinksMigrated    uint32
	LinksQuarantined uint32
}

// ProjectionStateStore persists normalized current-state entities and links.
type ProjectionStateStore interface {
	StateStore
	UpsertProjectedEntity(context.Context, *ProjectedEntity) error
	UpsertProjectedLink(context.Context, *ProjectedLink) error
}

// ProjectionEntityReader reads normalized current-state entities when a projector
// needs to compare immutable identity fields before applying an update.
type ProjectionEntityReader interface {
	GetProjectedEntity(context.Context, string) (*ProjectedEntity, error)
}

// ProjectionRuntimeEvidenceReader reads runtime evidence by its stable source
// event identity before projection assigns or updates evidence-specific URNs.
type ProjectionRuntimeEvidenceReader interface {
	GetProjectedRuntimeEvidenceBySourceEvent(context.Context, string, string, string) (*ProjectedEntity, error)
}

// ProjectionGraphStore persists normalized entities and links into the graph.
type ProjectionGraphStore interface {
	GraphStore
	UpsertProjectedEntity(context.Context, *ProjectedEntity) error
	UpsertProjectedLink(context.Context, *ProjectedLink) error
}

// ProjectionGraphBatchStore upserts coalesced entities and links in batches,
// collapsing the per-element merge/load and version-checked update round-trips
// of ProjectionGraphStore into a handful of UNWIND transactions. Graph stores
// that implement it are preferred by the projection writer; callers fall back
// to the per-element ProjectionGraphStore methods when it is not implemented.
// Batch methods preserve the exact per-element semantics: tenant-scope
// validation, attribute deep-merge, typed-property derivation, monotonic
// attributes_version, and links materialized only when both endpoints exist.
type ProjectionGraphBatchStore interface {
	UpsertProjectedEntities(context.Context, []*ProjectedEntity) error
	UpsertProjectedLinks(context.Context, []*ProjectedLink) error
}

// ProjectionLinkDeleter removes normalized links from projection stores that support deletion.
type ProjectionLinkDeleter interface {
	DeleteProjectedLink(context.Context, *ProjectedLink) error
}

// ProjectionLinkBatchDeleter retracts normalized links in one bounded store operation.
type ProjectionLinkBatchDeleter interface {
	DeleteProjectedLinks(context.Context, []*ProjectedLink) error
}

// ProjectionEntityDeleter removes normalized entities from projection stores that support deletion.
type ProjectionEntityDeleter interface {
	DeleteProjectedEntity(context.Context, string) error
}

// ProjectionEntityBatchDeleter removes isolated normalized entities in one bounded store operation.
type ProjectionEntityBatchDeleter interface {
	DeleteProjectedEntities(context.Context, []string) error
}

// ProjectionCleaner removes stale or orphaned projection artifacts in scoped batches.
type ProjectionCleaner interface {
	CleanupProjectedEntities(context.Context, ProjectionCleanupRequest) (ProjectionCleanupResult, error)
}

// EndpointOwnerIDLinkCleaner removes stale endpoint owner_id/user_id canonical identity links.
type EndpointOwnerIDLinkCleaner interface {
	CleanupEndpointOwnerIDLinks(context.Context, ProjectionLinkCleanupRequest) (ProjectionLinkCleanupResult, error)
}

// ProjectionRuntimeLinkReconciler performs the mark-and-sweep step after a
// complete authoritative source-to-graph projection.
type ProjectionRuntimeLinkReconciler interface {
	CleanupProjectedRuntimeLinks(context.Context, ProjectionRuntimeLinkReconciliationRequest) (ProjectionLinkCleanupResult, error)
}

// ProjectionAssertionCoverageStore reports material logical links that have
// not yet been migrated to independent source-runtime assertions.
type ProjectionAssertionCoverageStore interface {
	CountProjectedLinksMissingAssertions(context.Context, string, []string) (uint32, error)
}

// ProjectionAssertionMigrator converges legacy material links onto independent
// source-runtime assertions without converting links whose provenance is incomplete.
type ProjectionAssertionMigrator interface {
	MigrateProjectedLinkAssertions(context.Context, ProjectionAssertionMigrationRequest) (ProjectionAssertionMigrationResult, error)
}

// ErrSourceProjectionRecordRejected marks a projection failure scoped to one
// source record: the projector refused exactly that record, and other records
// in the same page are unaffected. Transport failures, server errors, and
// cancellation must never match it.
var ErrSourceProjectionRecordRejected = errors.New("source projection rejected the record")

// AppendLogDeadLetterOperationSourceProjection marks dead letters for events
// that are already in the append log but whose projection was rejected. They
// are repaired by re-projecting, never by appending the event again.
const AppendLogDeadLetterOperationSourceProjection = "source_projection"

// SourceProjectionErrorCoder exposes the projector's bounded error code for a
// rejected record so recovery can categorize it without parsing messages.
type SourceProjectionErrorCoder interface {
	ProjectionErrorCode() string
}

// SourceProjector materializes source events into current-state and graph stores.
type SourceProjector interface {
	Project(context.Context, *cerebrov1.EventEnvelope) (ProjectionResult, error)
}

// SourceProjectorWithDelta returns the compatibility records written for an
// event. Callers use this optional interface to retain existing source coverage
// without teaching the Rust authority every Go projector at once.
type SourceProjectorWithDelta interface {
	SourceProjector
	ProjectWithDelta(context.Context, *cerebrov1.EventEnvelope) (ProjectionResult, SourceProjectionDelta, error)
}
