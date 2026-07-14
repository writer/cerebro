package assurancereliability

import (
	"errors"
	"testing"
	"time"
)

func TestBuildEvidenceDebtLedgerTracksAgeOwnershipAndBurnDown(t *testing.T) {
	input := debtLedgerFixture()
	ledger, err := BuildEvidenceDebtLedger(input)
	if err != nil {
		t.Fatalf("BuildEvidenceDebtLedger() error = %v", err)
	}
	metrics := ledger.Metrics
	if metrics.BeginningOpenCount != 2 || metrics.BeginningDebtPoints != 9 || metrics.NewDebtCount != 3 || metrics.NewDebtPoints != 8 {
		t.Fatalf("opening/new metrics = %#v", metrics)
	}
	if metrics.ResolvedDebtCount != 2 || metrics.BurnedDebtPoints != 5 || metrics.EndingOpenCount != 3 || metrics.EndingDebtPoints != 12 {
		t.Fatalf("burned/ending metrics = %#v", metrics)
	}
	if metrics.OverdueOpenCount != 1 || metrics.OverdueDebtPoints != 8 {
		t.Fatalf("overdue metrics = %#v", metrics)
	}
	if metrics.NetNewDebtCount != 1 || metrics.NetNewDebtPoints != 3 || metrics.CountBurnDownBPS != 4000 || metrics.PointBurnDownBPS != 2941 {
		t.Fatalf("net/burn-down metrics = %#v", metrics)
	}
	if len(ledger.OpenDebt) != 3 {
		t.Fatalf("open debt count = %d", len(ledger.OpenDebt))
	}
	oldest := ledger.OpenDebt[0]
	if oldest.EpisodeID != "episode-a" || oldest.AgeHours != 21*24 || !oldest.Overdue || oldest.SeverityPoints != 8 {
		t.Fatalf("oldest debt = %#v", oldest)
	}
	if got := findDebtBreakdown(ledger.Breakdowns, DebtBreakdownOwner, "owner-a"); got.OpenCount != 2 || got.OpenPoints != 10 {
		t.Fatalf("owner breakdown = %#v", got)
	}
	for _, kind := range []EvidenceDebtKind{EvidenceDebtMissing, EvidenceDebtStale, EvidenceDebtWeak, EvidenceDebtManual, EvidenceDebtUnreplayable, EvidenceDebtConflicted} {
		if !fixtureContainsDebtKind(input.Entries, kind) {
			t.Fatalf("fixture does not exercise debt kind %q", kind)
		}
	}
	if ledger.LedgerDigest == "" {
		t.Fatal("ledger digest is empty")
	}
}

func TestBuildEvidenceDebtLedgerIsDeterministicAcrossInputOrder(t *testing.T) {
	input := debtLedgerFixture()
	first, err := BuildEvidenceDebtLedger(input)
	if err != nil {
		t.Fatal(err)
	}
	input.Entries[0], input.Entries[4] = input.Entries[4], input.Entries[0]
	input.Entries[1].Kinds = []EvidenceDebtKind{EvidenceDebtManual, EvidenceDebtStale, EvidenceDebtManual}
	second, err := BuildEvidenceDebtLedger(input)
	if err != nil {
		t.Fatal(err)
	}
	if first.LedgerDigest != second.LedgerDigest {
		t.Fatalf("ledger digest changed with input order: %s != %s", first.LedgerDigest, second.LedgerDigest)
	}
}

func TestBuildEvidenceDebtLedgerRejectsCrossTenantAndUnknownDebt(t *testing.T) {
	input := debtLedgerFixture()
	input.Entries[0].TenantID = "tenant-b"
	if _, err := BuildEvidenceDebtLedger(input); !errors.Is(err, ErrInvalidReliabilityInput) {
		t.Fatalf("tenant mismatch error = %v", err)
	}
	input = debtLedgerFixture()
	input.Entries[0].Kinds = []EvidenceDebtKind{"future_kind"}
	if _, err := BuildEvidenceDebtLedger(input); !errors.Is(err, ErrInvalidReliabilityInput) {
		t.Fatalf("unknown kind error = %v", err)
	}
	input = debtLedgerFixture()
	input.Entries[1].EpisodeID = input.Entries[0].EpisodeID
	if _, err := BuildEvidenceDebtLedger(input); !errors.Is(err, ErrInvalidReliabilityInput) {
		t.Fatalf("duplicate episode error = %v", err)
	}
}

func debtLedgerFixture() EvidenceDebtLedgerInput {
	window := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	asOf := time.Date(2026, 7, 11, 0, 0, 0, 0, time.UTC)
	entry := func(episode, obligation, owner string, kinds []EvidenceDebtKind, severity EvidenceDebtSeverity, openedDay, deadlineDay int) EvidenceDebtEntry {
		return EvidenceDebtEntry{
			TenantID: "tenant-a", EpisodeID: episode, ObligationID: obligation, OwnerID: owner,
			Kinds: kinds, Severity: severity,
			OpenedAt: time.Date(2026, 6, openedDay, 0, 0, 0, 0, time.UTC),
			Deadline: time.Date(2026, 6, deadlineDay, 0, 0, 0, 0, time.UTC),
		}
	}
	critical := entry("episode-a", "obligation-a", "owner-a", []EvidenceDebtKind{EvidenceDebtMissing}, EvidenceDebtCritical, 20, 25)
	staleManual := EvidenceDebtEntry{
		TenantID: "tenant-a", EpisodeID: "episode-b", ObligationID: "obligation-b", OwnerID: "owner-b",
		Kinds: []EvidenceDebtKind{EvidenceDebtStale, EvidenceDebtManual}, Severity: EvidenceDebtHigh,
		OpenedAt: time.Date(2026, 7, 3, 0, 0, 0, 0, time.UTC), Deadline: time.Date(2026, 7, 8, 0, 0, 0, 0, time.UTC),
		ResolvedAt: time.Date(2026, 7, 9, 0, 0, 0, 0, time.UTC),
	}
	unreplayable := EvidenceDebtEntry{
		TenantID: "tenant-a", EpisodeID: "episode-c", ObligationID: "obligation-c", OwnerID: "owner-a",
		Kinds: []EvidenceDebtKind{EvidenceDebtUnreplayable}, Severity: EvidenceDebtMedium,
		OpenedAt: time.Date(2026, 7, 4, 0, 0, 0, 0, time.UTC), Deadline: time.Date(2026, 7, 20, 0, 0, 0, 0, time.UTC),
	}
	conflicted := entry("episode-d", "obligation-d", "owner-c", []EvidenceDebtKind{EvidenceDebtConflicted}, EvidenceDebtLow, 25, 30)
	conflicted.Deadline = time.Date(2026, 7, 5, 0, 0, 0, 0, time.UTC)
	conflicted.ResolvedAt = time.Date(2026, 7, 2, 0, 0, 0, 0, time.UTC)
	weak := EvidenceDebtEntry{
		TenantID: "tenant-a", EpisodeID: "episode-e", ObligationID: "obligation-e", OwnerID: "owner-d",
		Kinds: []EvidenceDebtKind{EvidenceDebtWeak}, Severity: EvidenceDebtMedium,
		OpenedAt: time.Date(2026, 7, 10, 0, 0, 0, 0, time.UTC), Deadline: time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC),
	}
	return EvidenceDebtLedgerInput{TenantID: "tenant-a", WindowStart: window, AsOf: asOf, Entries: []EvidenceDebtEntry{critical, staleManual, unreplayable, conflicted, weak}}
}

func findDebtBreakdown(values []EvidenceDebtBreakdown, dimension EvidenceDebtBreakdownDimension, key string) EvidenceDebtBreakdown {
	for _, value := range values {
		if value.Dimension == dimension && value.Key == key {
			return value
		}
	}
	return EvidenceDebtBreakdown{}
}

func fixtureContainsDebtKind(entries []EvidenceDebtEntry, expected EvidenceDebtKind) bool {
	for _, entry := range entries {
		for _, kind := range entry.Kinds {
			if kind == expected {
				return true
			}
		}
	}
	return false
}
