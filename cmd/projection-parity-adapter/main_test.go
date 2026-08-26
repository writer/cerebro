package main

import (
	"testing"

	"github.com/writer/cerebro/internal/connectordefinitions"
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
