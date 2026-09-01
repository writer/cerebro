package main

import (
	"testing"

	"github.com/writer/cerebro/internal/connectordefinitions"
	"github.com/writer/cerebro/internal/ports"
)

func TestProjectRecordEmitsCatalogContractFact(t *testing.T) {
	run := runEnvelope{
		TenantID:        "tenant-a",
		SourceRuntimeID: "dropbox-business-prod",
		SourceID:        "dropbox_business",
		FamilyID:        "content_assets",
	}
	record := recordWire{
		ObservationID: "observation-1",
		Family:        "content_assets",
		ProviderKind:  "dropbox_business.content_asset",
		ProviderID:    "asset-1",
		EventKind:     "dropbox_business.content_assets",
		EventAttributes: map[string]string{
			"resource_id":   "asset-1",
			"resource_name": "Architecture",
			"resource_type": "file",
			"resource_urn":  "urn:cerebro:tenant-a:runtime_file:asset-1",
		},
	}
	family := connectordefinitions.ResourceFamily{
		ID:         "content_assets",
		Projection: &connectordefinitions.ProjectionSpec{Template: "asset"},
	}
	facts, err := projectRecord(run, family, record)
	if err != nil {
		t.Fatal(err)
	}
	if len(facts) != 1 {
		t.Fatalf("fact count = %d, want 1", len(facts))
	}
	want := "entity\x1fprovider:dropbox-business-prod:dropbox_business.asset:asset-1\x1fresource\x1fArchitecture"
	if got := canonicalFact(facts[0]); got != want {
		t.Fatalf("fact = %q, want %q", got, want)
	}
}

func TestProjectRecordRejectsFamilyDrift(t *testing.T) {
	_, err := projectRecord(
		runEnvelope{SourceID: "dropbox_business", FamilyID: "content_assets"},
		connectordefinitions.ResourceFamily{},
		recordWire{ObservationID: "observation-1", Family: "users"},
	)
	if err == nil {
		t.Fatal("expected family mismatch")
	}
}

func TestProjectRecordPassesPayloadToLegacyProjector(t *testing.T) {
	run := runEnvelope{
		TenantID:        "tenant-a",
		SourceRuntimeID: "cosmo-prod",
		SourceID:        "cosmo",
		FamilyID:        "message",
	}
	record := recordWire{
		ObservationID: "observation-1",
		Family:        "message",
		ProviderKind:  "cosmo.message",
		ProviderID:    "message-1",
		Payload:       map[string]any{"id": "message-1"},
		EventKind:     "cosmo.message",
	}
	family := connectordefinitions.ResourceFamily{
		ID:         "message",
		Projection: &connectordefinitions.ProjectionSpec{Template: "message"},
	}
	facts, err := projectRecord(run, family, record)
	if err != nil {
		t.Fatal(err)
	}
	if len(facts) != 1 {
		t.Fatalf("fact count = %d, want 1", len(facts))
	}
	want := "entity\x1fprovider:cosmo-prod:cosmo.message:message-1\x1fresource\x1fmessage-1"
	if got := canonicalFact(facts[0]); got != want {
		t.Fatalf("fact = %q, want %q", got, want)
	}
}

func TestDeduplicateFactsPreservesSortedUniqueFacts(t *testing.T) {
	facts := []factWire{
		{Kind: "entity", Parts: []string{"b"}},
		{Kind: "entity", Parts: []string{"b"}},
		{Kind: "entity", Parts: []string{"c"}},
	}
	got := deduplicateFacts(facts)
	if len(got) != 2 {
		t.Fatalf("fact count = %d, want 2", len(got))
	}
}

func TestDopplerProjectionFactsPreserveLegacySemantics(t *testing.T) {
	run := runEnvelope{
		TenantID:        "tenant-a",
		SourceRuntimeID: "doppler-prod",
		SourceID:        "doppler",
	}
	tests := []struct {
		name      string
		family    string
		record    recordWire
		wantFacts []string
	}{
		{
			name:   "secrets",
			family: "secrets",
			record: recordWire{
				ObservationID: "observation-secret-1",
				Family:        "secrets",
				ProviderKind:  "doppler.secrets",
				ProviderID:    "secret-1",
				EventKind:     "doppler.secrets",
				EventAttributes: map[string]string{
					"secret_id":   "secret-1",
					"secret_name": "DATABASE_URL",
					"project_id":  "project-1",
					"evidence_id": "evidence-1",
				},
			},
			wantFacts: []string{
				"entity\x1fprovider:doppler-prod:doppler.secret:secret-1\x1fresource\x1fDATABASE_URL",
				"entity\x1fprovider:doppler-prod:doppler.project:project-1\x1fprovider:doppler.project\x1fproject-1",
				"entity\x1fprovider:doppler-prod:doppler.runtime_evidence:evidence-1\x1fevidence\x1fevidence-1",
				"relationship\x1fprovider:doppler-prod:doppler.secret:secret-1\x1fbelongs_to\x1fprovider:doppler-prod:doppler.project:project-1",
				"provenance\x1frelationship:provider:doppler-prod:doppler.secret:secret-1:belongs_to:provider:doppler-prod:doppler.project:project-1\x1fobservation-secret-1",
				"relationship\x1fprovider:doppler-prod:doppler.secret:secret-1\x1fhas_evidence\x1fprovider:doppler-prod:doppler.runtime_evidence:evidence-1",
				"provenance\x1frelationship:provider:doppler-prod:doppler.secret:secret-1:has_evidence:provider:doppler-prod:doppler.runtime_evidence:evidence-1\x1fobservation-secret-1",
			},
		},
		{
			name:   "projects",
			family: "projects",
			record: recordWire{
				ObservationID: "observation-project-1",
				Family:        "projects",
				ProviderKind:  "doppler.projects",
				ProviderID:    "project-1",
				EventKind:     "doppler.projects",
				EventAttributes: map[string]string{
					"resource_id":   "project-1",
					"resource_name": "Platform",
					"resource_type": "project",
					"evidence_id":   "evidence-1",
				},
			},
			wantFacts: []string{
				"entity\x1fprovider:doppler-prod:doppler.project:project-1\x1fprovider:doppler.project\x1fPlatform",
				"entity\x1fprovider:doppler-prod:doppler.runtime_evidence:evidence-1\x1fevidence\x1fevidence-1",
				"relationship\x1fprovider:doppler-prod:doppler.project:project-1\x1fhas_evidence\x1fprovider:doppler-prod:doppler.runtime_evidence:evidence-1",
				"provenance\x1frelationship:provider:doppler-prod:doppler.project:project-1:has_evidence:provider:doppler-prod:doppler.runtime_evidence:evidence-1\x1fobservation-project-1",
			},
		},
		{
			name:   "audit events",
			family: "audit_events",
			record: recordWire{
				ObservationID: "observation-audit-1",
				Family:        "audit_events",
				ProviderKind:  "doppler.audit_events",
				ProviderID:    "event-1",
				EventKind:     "doppler.audit_events",
				EventAttributes: map[string]string{
					"actor_email":   "ada@example.test",
					"actor_id":      "user-1",
					"actor_name":    "Ada",
					"event_type":    "user.login",
					"resource_id":   "application-1",
					"resource_name": "Console",
					"resource_type": "application",
				},
			},
			wantFacts: []string{
				"provider_identity\x1fprovider:doppler-prod:doppler.identity_user:user-1\x1fidentity\x1fAda",
				"entity\x1fprovider:doppler-prod:doppler.audit_resource:11:application13:application-1\x1fresource\x1fConsole",
				"relationship\x1fprovider:doppler-prod:doppler.identity_user:user-1\x1facted_on\x1fprovider:doppler-prod:doppler.audit_resource:11:application13:application-1",
				"provenance\x1frelationship:provider:doppler-prod:doppler.identity_user:user-1:acted_on:provider:doppler-prod:doppler.audit_resource:11:application13:application-1\x1fobservation-audit-1",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			run.FamilyID = test.family
			family, err := catalogFamily("doppler", test.family)
			if err != nil {
				t.Fatal(err)
			}
			facts, err := projectRecord(run, family, test.record)
			if err != nil {
				t.Fatal(err)
			}
			assertCanonicalFactSet(t, facts, test.wantFacts)
		})
	}
}

func TestMissingDeclaredRelationshipChangesSemanticFacts(t *testing.T) {
	run := runEnvelope{
		TenantID:        "tenant-a",
		SourceRuntimeID: "doppler-prod",
		SourceID:        "doppler",
		FamilyID:        "secrets",
	}
	record := recordWire{ObservationID: "observation-1", ProviderID: "secret-1"}
	attributes := map[string]string{
		"secret_id":   "secret-1",
		"secret_name": "DATABASE_URL",
		"project_id":  "project-1",
	}
	family, err := catalogFamily("doppler", "secrets")
	if err != nil {
		t.Fatal(err)
	}
	entities := []*ports.ProjectedEntity{
		{
			URN:        "urn:secret",
			EntityType: "secret",
			Label:      "DATABASE_URL",
			Attributes: map[string]string{"secret_id": "secret-1"},
		},
		{
			URN:        "urn:project",
			EntityType: "doppler.project",
			Label:      "project-1",
			Attributes: map[string]string{"project_id": "project-1"},
		},
	}
	primary, err := primarySemanticEntity(run, record, family, "secret", attributes, entities)
	if err != nil {
		t.Fatal(err)
	}
	withRelationship, err := declaredRelationshipFacts(
		run,
		record,
		family,
		attributes,
		entities,
		[]*ports.ProjectedLink{{FromURN: "urn:secret", Relation: "belongs_to", ToURN: "urn:project"}},
		primary,
	)
	if err != nil {
		t.Fatal(err)
	}
	withoutRelationship, err := declaredRelationshipFacts(
		run,
		record,
		family,
		attributes,
		entities,
		nil,
		primary,
	)
	if err != nil {
		t.Fatal(err)
	}
	if canonicalFactSetEqual(withRelationship, withoutRelationship) {
		t.Fatal("removing the legacy belongs_to edge did not change parity facts")
	}
	wantRelationship := "relationship\x1fprovider:doppler-prod:doppler.secret:secret-1\x1fbelongs_to\x1fprovider:doppler-prod:doppler.project:project-1"
	if !canonicalFactSetContains(withRelationship, wantRelationship) {
		t.Fatalf("facts with relationship do not contain %q: %#v", wantRelationship, withRelationship)
	}
	if canonicalFactSetContains(withoutRelationship, wantRelationship) {
		t.Fatalf("facts without relationship still contain %q: %#v", wantRelationship, withoutRelationship)
	}
}

func assertCanonicalFactSet(t *testing.T, got []factWire, want []string) {
	t.Helper()
	gotSet := make(map[string]struct{}, len(got))
	for _, fact := range got {
		gotSet[canonicalFact(fact)] = struct{}{}
	}
	wantSet := make(map[string]struct{}, len(want))
	for _, fact := range want {
		wantSet[fact] = struct{}{}
	}
	if len(gotSet) != len(wantSet) {
		t.Fatalf("fact count = %d, want %d; facts = %#v", len(gotSet), len(wantSet), gotSet)
	}
	for fact := range wantSet {
		if _, ok := gotSet[fact]; !ok {
			t.Errorf("missing fact %q; facts = %#v", fact, gotSet)
		}
	}
}

func canonicalFactSetEqual(left, right []factWire) bool {
	if len(left) != len(right) {
		return false
	}
	for _, fact := range left {
		if !canonicalFactSetContains(right, canonicalFact(fact)) {
			return false
		}
	}
	return true
}

func canonicalFactSetContains(facts []factWire, want string) bool {
	for _, fact := range facts {
		if canonicalFact(fact) == want {
			return true
		}
	}
	return false
}
