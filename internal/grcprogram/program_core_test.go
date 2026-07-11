package grcprogram

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/compliance"
	"github.com/writer/cerebro/internal/ports"
)

func TestBuildSubjectManifestDeterministicAndSeparatesResolutionOutcomes(t *testing.T) {
	t.Parallel()
	cutoff := time.Date(2026, time.July, 11, 16, 30, 0, 123456789, time.FixedZone("test", -7*60*60))
	selectors := []ProgramScopeSelector{
		testSelector("people-unresolved", "people", ScopeSelectorInclude),
		testSelector("asset-exclude", "asset", ScopeSelectorExclude),
		testSelector("vendor-zero", "vendor", ScopeSelectorInclude),
		testSelector("asset-include", "asset", ScopeSelectorInclude),
	}
	resolutions := []SelectorResolution{
		{SelectorID: "vendor-zero", State: SubjectResolutionResolved},
		{SelectorID: "people-unresolved", State: SubjectResolutionUnresolved, ReasonCode: SubjectUnresolvedSourceUnavailable},
		{SelectorID: "asset-exclude", State: SubjectResolutionResolved, Subjects: []compliance.SubjectRef{{Type: "asset", ID: "two"}}},
		{SelectorID: "asset-include", State: SubjectResolutionResolved, Subjects: []compliance.SubjectRef{
			{Type: "asset", ID: "two"}, {Type: "asset", ID: "one"}, {Type: "asset", ID: "one"},
		}},
	}
	first, err := BuildSubjectManifest(selectors, SubjectResolutionBatch{Watermark: " inventory:42 ", Cutoff: cutoff, Resolutions: resolutions})
	if err != nil {
		t.Fatalf("BuildSubjectManifest() error = %v", err)
	}
	reverse(selectors)
	reverse(resolutions)
	second, err := BuildSubjectManifest(selectors, SubjectResolutionBatch{Watermark: "inventory:42", Cutoff: cutoff, Resolutions: resolutions})
	if err != nil {
		t.Fatalf("BuildSubjectManifest() shuffled error = %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("manifest is not deterministic:\nfirst = %#v\nsecond = %#v", first, second)
	}
	if got, want := first.Subjects, []compliance.SubjectRef{{Type: "asset", ID: "one"}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Subjects = %#v, want %#v", got, want)
	}
	if got, want := first.ZeroMatchSelectorIDs, []string{"vendor-zero"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("ZeroMatchSelectorIDs = %#v, want %#v", got, want)
	}
	if got, want := first.UnresolvedSelectorIDs, []string{"people-unresolved"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("UnresolvedSelectorIDs = %#v, want %#v", got, want)
	}
	if err := compliance.ValidateContentDigest(first.ContentDigest); err != nil {
		t.Fatalf("manifest content digest is invalid: %v", err)
	}
}

func TestServiceTenantLookupIsOpaque(t *testing.T) {
	t.Parallel()
	store := newMemoryProgramStore()
	service := testService(store, staticResolver{})
	created, err := service.CreateProgram(context.Background(), CreateProgramRequest{
		TenantID: "tenant-one", Name: "Payments", OwnerTeam: "security",
	})
	if err != nil {
		t.Fatalf("CreateProgram() error = %v", err)
	}
	_, err = service.GetProgram(context.Background(), "tenant-two", created.ID)
	if !errors.Is(err, ports.ErrComplianceProgramNotFound) {
		t.Fatalf("GetProgram() error = %v, want non-disclosing sentinel", err)
	}
}

func TestScopeRevisionChainAndExpectedVersion(t *testing.T) {
	t.Parallel()
	store := newMemoryProgramStore()
	cutoff := testTime()
	resolver := staticResolver{batch: SubjectResolutionBatch{
		Watermark: "inventory:9", Cutoff: cutoff,
		Resolutions: []SelectorResolution{{SelectorID: "asset-include", State: SubjectResolutionResolved, Subjects: []compliance.SubjectRef{{Type: "asset", ID: "one"}}}},
	}}
	service := testService(store, resolver)
	program, err := service.CreateProgram(context.Background(), CreateProgramRequest{TenantID: "tenant-one", Name: "Payments", OwnerTeam: "security"})
	if err != nil {
		t.Fatalf("CreateProgram() error = %v", err)
	}
	request := RecordScopeRevisionRequest{
		TenantID: "tenant-one", ProgramID: program.ID, ExpectedProgramVersion: 1,
		State: ScopeRevisionActive, ChangeSummary: "Establish payment scope", CreatedBy: "owner@example.com", Cutoff: cutoff,
		Specification: testScopeSpecification(),
	}
	first, err := service.RecordScopeRevision(context.Background(), request)
	if err != nil {
		t.Fatalf("RecordScopeRevision() error = %v", err)
	}
	if first.Revision.Version.Version != 1 || first.Revision.Version.PredecessorID != "" || first.Program.AggregateVersion != 2 {
		t.Fatalf("first revision metadata = %#v, program version = %d", first.Revision.Version, first.Program.AggregateVersion)
	}
	request.Specification.Parameters = append(request.Specification.Parameters, ScopeParameter{Name: "tier", Value: "critical", Rationale: "Material payment systems"})
	if _, err := service.RecordScopeRevision(context.Background(), request); !errors.Is(err, ports.ErrComplianceProgramVersionConflict) {
		t.Fatalf("stale RecordScopeRevision() error = %v, want version conflict", err)
	}
	request.ExpectedProgramVersion = 2
	request.ChangeSummary = "Set materiality tier"
	second, err := service.RecordScopeRevision(context.Background(), request)
	if err != nil {
		t.Fatalf("second RecordScopeRevision() error = %v", err)
	}
	if second.Revision.Version.Version != 2 || second.Revision.Version.PredecessorID != first.Revision.Version.RevisionID || second.Program.AggregateVersion != 3 {
		t.Fatalf("second revision metadata = %#v, program version = %d", second.Revision.Version, second.Program.AggregateVersion)
	}
	if second.Revision.Version.ContentDigest == first.Revision.Version.ContentDigest {
		t.Fatal("semantic content change did not change revision digest")
	}
	request.ExpectedProgramVersion = 3
	request.ChangeSummary = "Duplicate content"
	if _, err := service.RecordScopeRevision(context.Background(), request); !errors.Is(err, ports.ErrProgramRevisionConflict) {
		t.Fatalf("duplicate RecordScopeRevision() error = %v, want revision conflict", err)
	}
	second.Revision.Specification.Parameters[0].Value = "mutated"
	stored, err := store.GetProgramScopeRevision(context.Background(), "tenant-one", program.ID, second.Revision.Version.RevisionID)
	if err != nil {
		t.Fatalf("GetProgramScopeRevision() error = %v", err)
	}
	if stored.Specification.Parameters[0].Value == "mutated" {
		t.Fatal("stored immutable revision was mutated through returned value")
	}
}

func TestImplementationRevisionPreservesMappingRelationships(t *testing.T) {
	t.Parallel()
	store := newMemoryProgramStore()
	cutoff := testTime()
	service := testService(store, staticResolver{batch: SubjectResolutionBatch{
		Watermark: "inventory:10", Cutoff: cutoff,
		Resolutions: []SelectorResolution{{SelectorID: "asset-include", State: SubjectResolutionResolved, Subjects: []compliance.SubjectRef{{Type: "asset", ID: "one"}}}},
	}})
	program, err := service.CreateProgram(context.Background(), CreateProgramRequest{TenantID: "tenant-one", Name: "Payments", OwnerTeam: "security"})
	if err != nil {
		t.Fatalf("CreateProgram() error = %v", err)
	}
	scope, err := service.RecordScopeRevision(context.Background(), RecordScopeRevisionRequest{
		TenantID: "tenant-one", ProgramID: program.ID, ExpectedProgramVersion: 1,
		State: ScopeRevisionActive, ChangeSummary: "Establish scope", CreatedBy: "owner@example.com", Cutoff: cutoff,
		Specification: testScopeSpecification(),
	})
	if err != nil {
		t.Fatalf("RecordScopeRevision() error = %v", err)
	}
	relationships := []compliance.MappingRelationship{
		compliance.MappingNone, compliance.MappingOverlap, compliance.MappingSuperset, compliance.MappingEquivalent, compliance.MappingSubset,
	}
	mappings := make([]ControlMappingRef, 0, len(relationships))
	for index, relationship := range relationships {
		mappings = append(mappings, testMappingRef(index+1, relationship))
	}
	upstream := compliance.SubjectRef{Type: "control_implementation", ID: "implementation-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	request := RecordImplementationRevisionRequest{
		TenantID: "tenant-one", ProgramID: program.ID, ExpectedProgramVersion: scope.Program.AggregateVersion,
		ChangeSummary: "Record inherited control", CreatedBy: "owner@example.com",
		Specification: ControlImplementationSpecification{
			ScopeRevisionID: scope.Revision.Version.RevisionID,
			ControlRef:      compliance.ControlRef{FrameworkID: "framework-one", ControlID: "AC-1"},
			Status:          ImplementationImplemented, Narrative: "Identity policy is enforced by the platform.", OwnerTeam: "identity",
			ReviewPolicy:     ImplementationReviewPolicy{Cadence: "P30D", EffectiveFrom: cutoff},
			ResponsibleRoles: []string{"operator"}, AccountableRoles: []string{"service-owner"},
			Responsibility: ResponsibilityInherited, UpstreamImplementation: &upstream, MappingRefs: mappings,
			SubjectRefs: []compliance.SubjectRef{{Type: "system", ID: "identity-platform"}},
		},
	}
	first, err := service.RecordImplementationRevision(context.Background(), request)
	if err != nil {
		t.Fatalf("RecordImplementationRevision() error = %v", err)
	}
	gotRelationships := make([]compliance.MappingRelationship, 0, len(first.Revision.Specification.MappingRefs))
	for _, mapping := range first.Revision.Specification.MappingRefs {
		gotRelationships = append(gotRelationships, mapping.Relationship)
	}
	wantRelationships := relationships
	if !reflect.DeepEqual(gotRelationships, wantRelationships) {
		t.Fatalf("mapping relationships = %v, want %v", gotRelationships, wantRelationships)
	}
	if _, err := service.GetImplementation(context.Background(), "tenant-two", program.ID, first.Implementation.ID); !errors.Is(err, ports.ErrControlImplementationNotFound) {
		t.Fatalf("foreign tenant implementation lookup error = %v, want opaque not found", err)
	}
	if _, err := service.GetImplementationRevision(context.Background(), "tenant-two", program.ID, first.Implementation.ID, first.Revision.Version.RevisionID); !errors.Is(err, ports.ErrControlImplementationNotFound) {
		t.Fatalf("foreign tenant revision lookup error = %v, want opaque not found", err)
	}
	request.ImplementationID = first.Implementation.ID
	request.ExpectedProgramVersion = first.Program.AggregateVersion
	request.ExpectedImplementationVersion = 0
	request.Specification.Narrative = "Identity policy is enforced and reviewed monthly."
	if _, err := service.RecordImplementationRevision(context.Background(), request); !errors.Is(err, ports.ErrComplianceProgramVersionConflict) {
		t.Fatalf("stale implementation update error = %v, want version conflict", err)
	}
	request.ExpectedImplementationVersion = 1
	second, err := service.RecordImplementationRevision(context.Background(), request)
	if err != nil {
		t.Fatalf("second RecordImplementationRevision() error = %v", err)
	}
	if second.Revision.Version.Version != 2 || second.Revision.Version.PredecessorID != first.Revision.Version.RevisionID {
		t.Fatalf("second implementation revision metadata = %#v", second.Revision.Version)
	}
	request.ExpectedProgramVersion = second.Program.AggregateVersion
	request.ExpectedImplementationVersion = second.Implementation.AggregateVersion
	request.Specification.Responsibility = ResponsibilityInherited
	request.Specification.UpstreamImplementation = nil
	if _, err := service.RecordImplementationRevision(context.Background(), request); !errors.Is(err, ErrInvalidProgramRequest) {
		t.Fatalf("inherited implementation without upstream error = %v, want invalid request", err)
	}
}

func TestResponsibilityModesRemainDistinctInRevisionContent(t *testing.T) {
	t.Parallel()
	modes := []string{
		ResponsibilityDirect, ResponsibilityProvided, ResponsibilityCustomerResponsibility,
		ResponsibilityShared, ResponsibilityInherited,
	}
	digests := map[compliance.ContentDigest]string{}
	for _, mode := range modes {
		specification := ControlImplementationSpecification{
			ScopeRevisionID: "scope-revision-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			ControlRef:      compliance.ControlRef{FrameworkID: "framework-one", ControlID: "AC-1"},
			Status:          ImplementationPlanned, Narrative: "Document the implementation boundary.", OwnerTeam: "security",
			ReviewPolicy:     ImplementationReviewPolicy{Cadence: "P90D", EffectiveFrom: testTime()},
			ResponsibleRoles: []string{"operator"}, AccountableRoles: []string{"owner"}, Responsibility: mode,
		}
		if mode == ResponsibilityShared || mode == ResponsibilityInherited {
			specification.UpstreamImplementation = &compliance.SubjectRef{Type: "control_implementation", ID: "implementation-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
		}
		specification = normalizeImplementationSpecification(specification)
		if err := validateImplementationSpecification(specification); err != nil {
			t.Fatalf("validateImplementationSpecification(%q) error = %v", mode, err)
		}
		digest, err := semanticDigest(specification)
		if err != nil {
			t.Fatalf("semanticDigest(%q) error = %v", mode, err)
		}
		if previous, exists := digests[digest]; exists {
			t.Fatalf("responsibility modes %q and %q share a digest", previous, mode)
		}
		digests[digest] = mode
	}
}

type staticResolver struct {
	batch SubjectResolutionBatch
	err   error
}

func (resolver staticResolver) ResolveProgramSubjects(context.Context, SubjectResolutionRequest) (SubjectResolutionBatch, error) {
	return cloneValue(resolver.batch), resolver.err
}

type memoryProgramStore struct {
	mu              sync.Mutex
	programs        map[string]ComplianceProgramRecord
	scopeRevisions  map[string]ProgramScopeRevisionRecord
	implementations map[string]ControlImplementationRecord
	implRevisions   map[string]ControlImplementationRevisionRecord
}

func newMemoryProgramStore() *memoryProgramStore {
	return &memoryProgramStore{
		programs: map[string]ComplianceProgramRecord{}, scopeRevisions: map[string]ProgramScopeRevisionRecord{},
		implementations: map[string]ControlImplementationRecord{}, implRevisions: map[string]ControlImplementationRevisionRecord{},
	}
}

func (store *memoryProgramStore) Ping(context.Context) error { return nil }

func (store *memoryProgramStore) CreateComplianceProgram(_ context.Context, record ComplianceProgramRecord) (*ComplianceProgramRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	key := storeKey(record.TenantID, record.ID)
	if _, exists := store.programs[key]; exists {
		return nil, ports.ErrComplianceProgramVersionConflict
	}
	store.programs[key] = cloneValue(record)
	result := cloneValue(record)
	return &result, nil
}

func (store *memoryProgramStore) GetComplianceProgram(_ context.Context, tenantID string, programID string) (*ComplianceProgramRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, exists := store.programs[storeKey(tenantID, programID)]
	if !exists {
		return nil, ports.ErrComplianceProgramNotFound
	}
	result := cloneValue(record)
	return &result, nil
}

func (store *memoryProgramStore) GetProgramScopeRevision(_ context.Context, tenantID string, programID string, revisionID string) (*ProgramScopeRevisionRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, exists := store.scopeRevisions[storeKey(tenantID, programID, revisionID)]
	if !exists {
		return nil, ports.ErrProgramRevisionConflict
	}
	result := cloneValue(record)
	return &result, nil
}

func (store *memoryProgramStore) AppendProgramScopeRevision(_ context.Context, request AppendProgramScopeRevisionRequest) (*ComplianceProgramRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	programKey := storeKey(request.TenantID, request.ProgramID)
	program, exists := store.programs[programKey]
	if !exists {
		return nil, ports.ErrComplianceProgramNotFound
	}
	if program.AggregateVersion != request.ExpectedProgramVersion {
		return nil, ports.ErrComplianceProgramVersionConflict
	}
	revisionKey := storeKey(request.TenantID, request.ProgramID, request.Revision.Version.RevisionID)
	if _, exists := store.scopeRevisions[revisionKey]; exists {
		return nil, ports.ErrProgramRevisionConflict
	}
	store.scopeRevisions[revisionKey] = cloneValue(request.Revision)
	program.ScopeID = request.Revision.Version.ID
	program.CurrentScopeRevisionID = request.Revision.Version.RevisionID
	program.AggregateVersion++
	program.UpdatedAt = request.Revision.Version.LastModified
	store.programs[programKey] = program
	result := cloneValue(program)
	return &result, nil
}

func (store *memoryProgramStore) GetControlImplementation(_ context.Context, tenantID string, programID string, implementationID string) (*ControlImplementationRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, exists := store.implementations[storeKey(tenantID, programID, implementationID)]
	if !exists {
		return nil, ports.ErrControlImplementationNotFound
	}
	result := cloneValue(record)
	return &result, nil
}

func (store *memoryProgramStore) GetControlImplementationRevision(_ context.Context, tenantID string, programID string, implementationID string, revisionID string) (*ControlImplementationRevisionRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, exists := store.implRevisions[storeKey(tenantID, programID, implementationID, revisionID)]
	if !exists {
		return nil, ports.ErrProgramRevisionConflict
	}
	result := cloneValue(record)
	return &result, nil
}

func (store *memoryProgramStore) AppendControlImplementationRevision(_ context.Context, request AppendControlImplementationRevisionRequest) (*ComplianceProgramRecord, *ControlImplementationRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	programKey := storeKey(request.TenantID, request.ProgramID)
	program, exists := store.programs[programKey]
	if !exists {
		return nil, nil, ports.ErrComplianceProgramNotFound
	}
	if program.AggregateVersion != request.ExpectedProgramVersion {
		return nil, nil, ports.ErrComplianceProgramVersionConflict
	}
	implementationKey := storeKey(request.TenantID, request.ProgramID, request.Implementation.ID)
	current, exists := store.implementations[implementationKey]
	if exists && current.AggregateVersion != request.ExpectedImplementationVersion {
		return nil, nil, ports.ErrComplianceProgramVersionConflict
	}
	if !exists && request.ExpectedImplementationVersion != 0 {
		return nil, nil, ports.ErrComplianceProgramVersionConflict
	}
	revisionKey := storeKey(request.TenantID, request.ProgramID, request.Implementation.ID, request.Revision.Version.RevisionID)
	if _, exists := store.implRevisions[revisionKey]; exists {
		return nil, nil, ports.ErrProgramRevisionConflict
	}
	implementation := cloneValue(request.Implementation)
	implementation.AggregateVersion = request.ExpectedImplementationVersion + 1
	store.implementations[implementationKey] = implementation
	store.implRevisions[revisionKey] = cloneValue(request.Revision)
	program.AggregateVersion++
	program.UpdatedAt = request.Revision.Version.LastModified
	store.programs[programKey] = program
	programResult := cloneValue(program)
	implementationResult := cloneValue(implementation)
	return &programResult, &implementationResult, nil
}

func testService(store ComplianceProgramStore, resolver ProgramSubjectResolver) *Service {
	service := NewService(store, resolver)
	service.now = func() time.Time { return testTime() }
	service.newID = func(kind compliance.IdentifierKind) (string, error) {
		return string(kind) + "-" + strings.Repeat("a", 32), nil
	}
	var revisionCounter byte
	service.newRevision = func(kind compliance.IdentifierKind) (string, error) {
		revisionCounter++
		return fmt.Sprintf("%s-revision-%032x", kind, revisionCounter), nil
	}
	return service
}

func testSelector(id string, kind string, mode string) ProgramScopeSelector {
	return ProgramScopeSelector{
		ID: id, Kind: kind, Mode: mode, Source: "inventory", Reason: "Program boundary", ApproverID: "owner@example.com",
		EffectiveFrom: testTime(), Criteria: []ScopeSelectorCriterion{{Field: "id", Operator: "prefix", Value: "prod-"}},
	}
}

func testScopeSpecification() ProgramScopeSpecification {
	return ProgramScopeSpecification{
		FrameworkRevisions: []compliance.RevisionRef{testRevisionRef("framework-one", "framework-revision-one")},
		ProfileRevisions:   []compliance.RevisionRef{testRevisionRef("profile-one", "profile-revision-one")},
		Selectors:          []ProgramScopeSelector{testSelector("asset-include", "asset", ScopeSelectorInclude)},
		Parameters:         []ScopeParameter{{Name: "region", Value: "us", Rationale: "Contract boundary"}},
	}
}

func testMappingRef(index int, relationship compliance.MappingRelationship) ControlMappingRef {
	hex := fmt.Sprintf("%032x", index)
	return ControlMappingRef{
		ID: "control-mapping-" + hex, RevisionID: "control-mapping-revision-" + hex,
		Relationship: relationship, Granularity: "control",
		Source: testRevisionRef(fmt.Sprintf("source-%d", index), fmt.Sprintf("source-revision-%d", index)),
		Target: testRevisionRef(fmt.Sprintf("target-%d", index), fmt.Sprintf("target-revision-%d", index)),
		Method: "manual_review", Rationale: "Reviewed control intent and evidence expectations.",
		CoverageBasisPoints: testMappingCoverage(relationship), Gaps: []string{"Residual operating test"},
		Provenance:    []compliance.SubjectRef{{Type: "mapping_review", ID: fmt.Sprintf("review-%d", index)}},
		DecisionState: compliance.MappingApproved, AuthorID: "mapper@example.com", ReviewerID: "reviewer@example.com",
	}
}

func testMappingCoverage(relationship compliance.MappingRelationship) uint16 {
	switch relationship {
	case compliance.MappingEquivalent:
		return 10000
	case compliance.MappingNone:
		return 0
	default:
		return 5000
	}
}

func testRevisionRef(id string, revisionID string) compliance.RevisionRef {
	return compliance.RevisionRef{
		ID: id, RevisionID: revisionID, Version: 1,
		ContentDigest: compliance.ContentDigest("sha256:" + strings.Repeat("1", 64)), LastModified: testTime(),
	}
}

func testTime() time.Time {
	return time.Date(2026, time.July, 11, 20, 0, 0, 0, time.UTC)
}

func storeKey(parts ...string) string { return strings.Join(parts, "\x00") }

func cloneValue[T any](value T) T {
	payload, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	var result T
	if err := json.Unmarshal(payload, &result); err != nil {
		panic(err)
	}
	return result
}

func reverse[T any](values []T) {
	for left, right := 0, len(values)-1; left < right; left, right = left+1, right-1 {
		values[left], values[right] = values[right], values[left]
	}
}
