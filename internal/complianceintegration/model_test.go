package complianceintegration

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/compliance"
)

func TestRevisionAndFactAdaptersNormalizeAndRemainImmutable(t *testing.T) {
	modified := time.Date(2026, 7, 11, 12, 0, 0, 987654321, time.FixedZone("offset", 3600))
	revision, err := AdaptRevisionRef(" tenant-a ", " GRC.Policy ", FactPolicy, compliance.RevisionRef{
		ID: " policy-1 ", RevisionID: " policy-r1 ", Version: 1,
		ContentDigest: compliance.ContentDigest("sha256:" + strings.Repeat("a", 64)), LastModified: modified,
	})
	if err != nil {
		t.Fatal(err)
	}
	if revision.TenantID() != "tenant-a" || revision.Domain() != "grc.policy" || revision.ID() != "policy-1" {
		t.Fatalf("unexpected normalized revision: tenant=%q domain=%q id=%q", revision.TenantID(), revision.Domain(), revision.ID())
	}
	if got := revision.Canonical().LastModified; got.Location() != time.UTC || got.Nanosecond() != 987000000 {
		t.Fatalf("last_modified not canonical: %v", got)
	}

	other := testRevision(t, "tenant-a", FactCatalog, "catalog-1", 1)
	depA, err := NewDependencyRef(revision, " Policy_Source ")
	if err != nil {
		t.Fatal(err)
	}
	depB, err := NewDependencyRef(other, "catalog_source")
	if err != nil {
		t.Fatal(err)
	}
	input := []DependencyRef{depA, depB, depA}
	fact, err := NewDomainFact(testRevision(t, "tenant-a", FactProgram, "program-1", 1), input)
	if err != nil {
		t.Fatal(err)
	}
	input[0] = DependencyRef{}
	first := fact.Dependencies()
	if len(first) != 2 {
		t.Fatalf("dependencies = %d, want deduplicated length 2", len(first))
	}
	first[0] = DependencyRef{}
	if len(fact.Dependencies()) != 2 || fact.Dependencies()[0].Relation() == "" {
		t.Fatal("dependencies accessor exposed mutable backing storage")
	}
}

func TestDomainFactRejectsCrossTenantDependency(t *testing.T) {
	owner := testRevision(t, "tenant-a", FactProgram, "program-1", 1)
	foreign := testRevision(t, "tenant-b", FactPolicy, "policy-1", 1)
	dependency, err := NewDependencyRef(foreign, "policy_source")
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewDomainFact(owner, []DependencyRef{dependency})
	if !errors.Is(err, ErrInvalidFact) {
		t.Fatalf("error = %v, want ErrInvalidFact", err)
	}
}

func TestChangeSignalRequiresExactRevisionSemantics(t *testing.T) {
	previous := testRevision(t, "tenant-a", FactPolicy, "policy-1", 1)
	replacement := testRevision(t, "tenant-a", FactPolicy, "policy-1", 2)
	changedAt := time.Date(2026, 7, 11, 1, 2, 3, 456789123, time.FixedZone("offset", -3600))
	signal, err := NewChangeSignal(ChangeKind(" UPDATED "), previous, &replacement, changedAt)
	if err != nil {
		t.Fatal(err)
	}
	if got := signal.ChangedAt(); got.Location() != time.UTC || got.Nanosecond() != 456000000 {
		t.Fatalf("changed_at not canonical: %v", got)
	}
	if signal.Kind() != ChangeUpdated {
		t.Fatalf("kind = %q, want normalized updated", signal.Kind())
	}
	gotReplacement, ok := signal.Replacement()
	if !ok || !gotReplacement.Equal(replacement) {
		t.Fatal("replacement revision not preserved")
	}

	if _, err := NewChangeSignal(ChangeUpdated, previous, nil, changedAt); !errors.Is(err, ErrInvalidChangeSignal) {
		t.Fatalf("missing replacement error = %v", err)
	}
	older := testRevision(t, "tenant-a", FactPolicy, "policy-1", 1)
	if _, err := NewChangeSignal(ChangeUpdated, previous, &older, changedAt); !errors.Is(err, ErrInvalidChangeSignal) {
		t.Fatalf("non-newer replacement error = %v", err)
	}
	foreignSubject := testRevision(t, "tenant-a", FactPolicy, "policy-2", 2)
	if _, err := NewChangeSignal(ChangeUpdated, previous, &foreignSubject, changedAt); !errors.Is(err, ErrInvalidChangeSignal) {
		t.Fatalf("different subject replacement error = %v", err)
	}
	if _, err := NewChangeSignal(ChangeDeleted, previous, &replacement, changedAt); !errors.Is(err, ErrInvalidChangeSignal) {
		t.Fatalf("deleted replacement error = %v", err)
	}
	if _, err := NewChangeSignal(ChangeDeleted, previous, nil, time.Time{}); !errors.Is(err, ErrInvalidChangeSignal) {
		t.Fatalf("missing time error = %v", err)
	}
}

func TestRevisionAdapterRejectsInvalidIdentity(t *testing.T) {
	valid := compliance.RevisionRef{ID: "id", RevisionID: "r1", Version: 1, ContentDigest: compliance.ContentDigest("sha256:" + strings.Repeat("a", 64)), LastModified: time.Unix(1, 0)}
	tests := []struct {
		name   string
		tenant string
		domain string
		kind   FactKind
		value  compliance.RevisionRef
	}{
		{name: "tenant", domain: "domain", kind: FactPolicy, value: valid},
		{name: "domain", tenant: "tenant", domain: "../domain", kind: FactPolicy, value: valid},
		{name: "kind", tenant: "tenant", domain: "domain", kind: "unknown", value: valid},
		{name: "revision", tenant: "tenant", domain: "domain", kind: FactPolicy, value: compliance.RevisionRef{}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := AdaptRevisionRef(test.tenant, test.domain, test.kind, test.value)
			if !errors.Is(err, ErrInvalidFact) {
				t.Fatalf("error = %v, want ErrInvalidFact", err)
			}
		})
	}
}

func testRevision(t *testing.T, tenant string, kind FactKind, id string, version uint64) RevisionRef {
	t.Helper()
	ref, err := AdaptRevisionRef(tenant, "test.domain", kind, compliance.RevisionRef{
		ID: id, RevisionID: id + "-r" + string(rune('0'+version)), Version: version,
		ContentDigest: compliance.ContentDigest("sha256:" + strings.Repeat("a", 64)), LastModified: time.Unix(int64(version), 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	return ref
}
