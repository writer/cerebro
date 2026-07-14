package assurancereliability

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/complianceassessment"
)

const EvidenceDebtLedgerVersion = "evidence-debt-ledger/v1"

type EvidenceDebtKind string

const (
	EvidenceDebtMissing      EvidenceDebtKind = "missing"
	EvidenceDebtStale        EvidenceDebtKind = "stale"
	EvidenceDebtWeak         EvidenceDebtKind = "weak"
	EvidenceDebtManual       EvidenceDebtKind = "manual"
	EvidenceDebtUnreplayable EvidenceDebtKind = "unreplayable"
	EvidenceDebtConflicted   EvidenceDebtKind = "conflicted"
)

type EvidenceDebtSeverity string

const (
	EvidenceDebtLow      EvidenceDebtSeverity = "low"
	EvidenceDebtMedium   EvidenceDebtSeverity = "medium"
	EvidenceDebtHigh     EvidenceDebtSeverity = "high"
	EvidenceDebtCritical EvidenceDebtSeverity = "critical"
)

type EvidenceDebtEntry struct {
	TenantID     string               `json:"tenant_id"`
	EpisodeID    string               `json:"episode_id"`
	ObligationID string               `json:"obligation_id"`
	Kinds        []EvidenceDebtKind   `json:"kinds"`
	Severity     EvidenceDebtSeverity `json:"severity"`
	OwnerID      string               `json:"owner_id"`
	OpenedAt     time.Time            `json:"opened_at"`
	Deadline     time.Time            `json:"deadline"`
	ResolvedAt   time.Time            `json:"resolved_at,omitempty"`
}

type EvidenceDebtLedgerInput struct {
	TenantID    string              `json:"tenant_id"`
	WindowStart time.Time           `json:"window_start"`
	AsOf        time.Time           `json:"as_of"`
	Entries     []EvidenceDebtEntry `json:"entries"`
}

type OpenEvidenceDebt struct {
	EpisodeID      string               `json:"episode_id"`
	ObligationID   string               `json:"obligation_id"`
	Kinds          []EvidenceDebtKind   `json:"kinds"`
	Severity       EvidenceDebtSeverity `json:"severity"`
	SeverityPoints uint64               `json:"severity_points"`
	OwnerID        string               `json:"owner_id"`
	OpenedAt       time.Time            `json:"opened_at"`
	AgeHours       int64                `json:"age_hours"`
	Deadline       time.Time            `json:"deadline"`
	Overdue        bool                 `json:"overdue"`
}

type EvidenceDebtBreakdownDimension string

const (
	DebtBreakdownKind     EvidenceDebtBreakdownDimension = "kind"
	DebtBreakdownSeverity EvidenceDebtBreakdownDimension = "severity"
	DebtBreakdownOwner    EvidenceDebtBreakdownDimension = "owner"
)

type EvidenceDebtBreakdown struct {
	Dimension  EvidenceDebtBreakdownDimension `json:"dimension"`
	Key        string                         `json:"key"`
	OpenCount  uint64                         `json:"open_count"`
	OpenPoints uint64                         `json:"open_points"`
}

type EvidenceDebtMetrics struct {
	BeginningOpenCount  uint64 `json:"beginning_open_count"`
	BeginningDebtPoints uint64 `json:"beginning_debt_points"`
	NewDebtCount        uint64 `json:"new_debt_count"`
	NewDebtPoints       uint64 `json:"new_debt_points"`
	ResolvedDebtCount   uint64 `json:"resolved_debt_count"`
	BurnedDebtPoints    uint64 `json:"burned_debt_points"`
	EndingOpenCount     uint64 `json:"ending_open_count"`
	EndingDebtPoints    uint64 `json:"ending_debt_points"`
	OverdueOpenCount    uint64 `json:"overdue_open_count"`
	OverdueDebtPoints   uint64 `json:"overdue_debt_points"`
	NetNewDebtCount     int64  `json:"net_new_debt_count"`
	NetNewDebtPoints    int64  `json:"net_new_debt_points"`
	CountBurnDownBPS    uint64 `json:"count_burn_down_bps"`
	PointBurnDownBPS    uint64 `json:"point_burn_down_bps"`
}

type EvidenceDebtLedger struct {
	Version      string                  `json:"version"`
	TenantID     string                  `json:"tenant_id"`
	WindowStart  time.Time               `json:"window_start"`
	AsOf         time.Time               `json:"as_of"`
	OpenDebt     []OpenEvidenceDebt      `json:"open_debt"`
	Breakdowns   []EvidenceDebtBreakdown `json:"breakdowns"`
	Metrics      EvidenceDebtMetrics     `json:"metrics"`
	LedgerDigest string                  `json:"ledger_digest"`
}

// BuildEvidenceDebtLedger derives an as-of ledger and window metrics from
// immutable debt episodes. Each episode counts once in burn-down metrics even
// when it carries multiple evidence-debt kinds.
func BuildEvidenceDebtLedger(input EvidenceDebtLedgerInput) (EvidenceDebtLedger, error) {
	input.TenantID = strings.TrimSpace(input.TenantID)
	input.WindowStart = complianceassessment.CanonicalTime(input.WindowStart)
	input.AsOf = complianceassessment.CanonicalTime(input.AsOf)
	if input.TenantID == "" || input.WindowStart.IsZero() || input.AsOf.IsZero() || !input.AsOf.After(input.WindowStart) {
		return EvidenceDebtLedger{}, fmt.Errorf("%w: tenant and ordered window are required", ErrInvalidReliabilityInput)
	}
	entries := append([]EvidenceDebtEntry(nil), input.Entries...)
	for index := range entries {
		entries[index] = normalizeDebtEntry(entries[index])
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].EpisodeID < entries[j].EpisodeID })
	ledger := EvidenceDebtLedger{Version: EvidenceDebtLedgerVersion, TenantID: input.TenantID, WindowStart: input.WindowStart, AsOf: input.AsOf}
	seen := map[string]struct{}{}
	breakdowns := map[EvidenceDebtBreakdownDimension]map[string]debtAggregate{}
	for index, entry := range entries {
		if err := validateDebtEntry(input, entry); err != nil {
			return EvidenceDebtLedger{}, fmt.Errorf("%w: entries[%d]: %w", ErrInvalidReliabilityInput, index, err)
		}
		if _, ok := seen[entry.EpisodeID]; ok {
			return EvidenceDebtLedger{}, fmt.Errorf("%w: duplicate episode %q", ErrInvalidReliabilityInput, entry.EpisodeID)
		}
		seen[entry.EpisodeID] = struct{}{}
		points := evidenceDebtSeverityPoints(entry.Severity)
		if debtOpenAt(entry, input.WindowStart) {
			if err := addDebtMetric(&ledger.Metrics.BeginningOpenCount, 1); err != nil {
				return EvidenceDebtLedger{}, err
			}
			if err := addDebtMetric(&ledger.Metrics.BeginningDebtPoints, points); err != nil {
				return EvidenceDebtLedger{}, err
			}
		}
		if entry.OpenedAt.After(input.WindowStart) && !entry.OpenedAt.After(input.AsOf) {
			if err := addDebtMetric(&ledger.Metrics.NewDebtCount, 1); err != nil {
				return EvidenceDebtLedger{}, err
			}
			if err := addDebtMetric(&ledger.Metrics.NewDebtPoints, points); err != nil {
				return EvidenceDebtLedger{}, err
			}
		}
		if !entry.ResolvedAt.IsZero() && entry.ResolvedAt.After(input.WindowStart) && !entry.ResolvedAt.After(input.AsOf) {
			if err := addDebtMetric(&ledger.Metrics.ResolvedDebtCount, 1); err != nil {
				return EvidenceDebtLedger{}, err
			}
			if err := addDebtMetric(&ledger.Metrics.BurnedDebtPoints, points); err != nil {
				return EvidenceDebtLedger{}, err
			}
		}
		if !debtOpenAt(entry, input.AsOf) {
			continue
		}
		if err := addDebtMetric(&ledger.Metrics.EndingOpenCount, 1); err != nil {
			return EvidenceDebtLedger{}, err
		}
		if err := addDebtMetric(&ledger.Metrics.EndingDebtPoints, points); err != nil {
			return EvidenceDebtLedger{}, err
		}
		age := input.AsOf.Sub(entry.OpenedAt)
		overdue := input.AsOf.After(entry.Deadline)
		ledger.OpenDebt = append(ledger.OpenDebt, OpenEvidenceDebt{
			EpisodeID: entry.EpisodeID, ObligationID: entry.ObligationID, Kinds: entry.Kinds,
			Severity: entry.Severity, SeverityPoints: points, OwnerID: entry.OwnerID,
			OpenedAt: entry.OpenedAt, AgeHours: int64(age / time.Hour), Deadline: entry.Deadline, Overdue: overdue,
		})
		if overdue {
			if err := addDebtMetric(&ledger.Metrics.OverdueOpenCount, 1); err != nil {
				return EvidenceDebtLedger{}, err
			}
			if err := addDebtMetric(&ledger.Metrics.OverdueDebtPoints, points); err != nil {
				return EvidenceDebtLedger{}, err
			}
		}
		for _, kind := range entry.Kinds {
			if err := addDebtBreakdown(breakdowns, DebtBreakdownKind, string(kind), points); err != nil {
				return EvidenceDebtLedger{}, err
			}
		}
		if err := addDebtBreakdown(breakdowns, DebtBreakdownSeverity, string(entry.Severity), points); err != nil {
			return EvidenceDebtLedger{}, err
		}
		if err := addDebtBreakdown(breakdowns, DebtBreakdownOwner, entry.OwnerID, points); err != nil {
			return EvidenceDebtLedger{}, err
		}
	}
	var err error
	ledger.Metrics.NetNewDebtCount, err = signedDelta(ledger.Metrics.NewDebtCount, ledger.Metrics.ResolvedDebtCount)
	if err != nil {
		return EvidenceDebtLedger{}, err
	}
	ledger.Metrics.NetNewDebtPoints, err = signedDelta(ledger.Metrics.NewDebtPoints, ledger.Metrics.BurnedDebtPoints)
	if err != nil {
		return EvidenceDebtLedger{}, err
	}
	availableCount, err := checkedAdd(ledger.Metrics.BeginningOpenCount, ledger.Metrics.NewDebtCount)
	if err != nil {
		return EvidenceDebtLedger{}, err
	}
	availablePoints, err := checkedAdd(ledger.Metrics.BeginningDebtPoints, ledger.Metrics.NewDebtPoints)
	if err != nil {
		return EvidenceDebtLedger{}, err
	}
	ledger.Metrics.CountBurnDownBPS = basisPoints(ledger.Metrics.ResolvedDebtCount, availableCount)
	ledger.Metrics.PointBurnDownBPS = basisPoints(ledger.Metrics.BurnedDebtPoints, availablePoints)
	ledger.Breakdowns = flattenDebtBreakdowns(breakdowns)
	sort.Slice(ledger.OpenDebt, func(i, j int) bool {
		left, right := ledger.OpenDebt[i], ledger.OpenDebt[j]
		if left.SeverityPoints != right.SeverityPoints {
			return left.SeverityPoints > right.SeverityPoints
		}
		if left.Overdue != right.Overdue {
			return left.Overdue
		}
		if left.AgeHours != right.AgeHours {
			return left.AgeHours > right.AgeHours
		}
		return left.EpisodeID < right.EpisodeID
	})
	digest, err := deterministicDigest(ledger)
	if err != nil {
		return EvidenceDebtLedger{}, err
	}
	ledger.LedgerDigest = digest
	return ledger, nil
}

type debtAggregate struct {
	count  uint64
	points uint64
}

func normalizeDebtEntry(entry EvidenceDebtEntry) EvidenceDebtEntry {
	entry.TenantID = strings.TrimSpace(entry.TenantID)
	entry.EpisodeID = strings.TrimSpace(entry.EpisodeID)
	entry.ObligationID = strings.TrimSpace(entry.ObligationID)
	entry.OwnerID = strings.TrimSpace(entry.OwnerID)
	entry.OpenedAt = complianceassessment.CanonicalTime(entry.OpenedAt)
	entry.Deadline = complianceassessment.CanonicalTime(entry.Deadline)
	entry.ResolvedAt = complianceassessment.CanonicalTime(entry.ResolvedAt)
	entry.Kinds = append([]EvidenceDebtKind(nil), entry.Kinds...)
	sort.Slice(entry.Kinds, func(i, j int) bool { return entry.Kinds[i] < entry.Kinds[j] })
	entry.Kinds = deduplicateDebtKinds(entry.Kinds)
	return entry
}

func validateDebtEntry(input EvidenceDebtLedgerInput, entry EvidenceDebtEntry) error {
	if entry.TenantID != input.TenantID {
		return errors.New("tenant does not match ledger tenant")
	}
	if entry.EpisodeID == "" || entry.ObligationID == "" || entry.OwnerID == "" || len(entry.Kinds) == 0 {
		return errors.New("episode, obligation, owner, and debt kinds are required")
	}
	if !knownDebtSeverity(entry.Severity) {
		return fmt.Errorf("unknown debt severity %q", entry.Severity)
	}
	for _, kind := range entry.Kinds {
		if !knownDebtKind(kind) {
			return fmt.Errorf("unknown evidence debt kind %q", kind)
		}
	}
	if entry.OpenedAt.IsZero() || entry.OpenedAt.After(input.AsOf) || entry.Deadline.Before(entry.OpenedAt) {
		return errors.New("opened_at and a deadline on or after opening are required")
	}
	if !entry.ResolvedAt.IsZero() && (entry.ResolvedAt.Before(entry.OpenedAt) || entry.ResolvedAt.After(input.AsOf)) {
		return errors.New("resolved_at must fall between opening and the ledger as-of time")
	}
	return nil
}

func knownDebtKind(value EvidenceDebtKind) bool {
	switch value {
	case EvidenceDebtMissing, EvidenceDebtStale, EvidenceDebtWeak, EvidenceDebtManual, EvidenceDebtUnreplayable, EvidenceDebtConflicted:
		return true
	default:
		return false
	}
}

func knownDebtSeverity(value EvidenceDebtSeverity) bool {
	switch value {
	case EvidenceDebtLow, EvidenceDebtMedium, EvidenceDebtHigh, EvidenceDebtCritical:
		return true
	default:
		return false
	}
}

// Evidence debt uses fixed severity points so new-debt and burn-down values are
// comparable across report windows: low=1, medium=2, high=4, critical=8.
func evidenceDebtSeverityPoints(value EvidenceDebtSeverity) uint64 {
	switch value {
	case EvidenceDebtCritical:
		return 8
	case EvidenceDebtHigh:
		return 4
	case EvidenceDebtMedium:
		return 2
	default:
		return 1
	}
}

func debtOpenAt(entry EvidenceDebtEntry, at time.Time) bool {
	return !entry.OpenedAt.After(at) && (entry.ResolvedAt.IsZero() || entry.ResolvedAt.After(at))
}

func deduplicateDebtKinds(values []EvidenceDebtKind) []EvidenceDebtKind {
	result := make([]EvidenceDebtKind, 0, len(values))
	for _, value := range values {
		if len(result) != 0 && result[len(result)-1] == value {
			continue
		}
		result = append(result, value)
	}
	return result
}

func addDebtMetric(value *uint64, add uint64) error {
	updated, err := checkedAdd(*value, add)
	if err != nil {
		return err
	}
	*value = updated
	return nil
}

func addDebtBreakdown(values map[EvidenceDebtBreakdownDimension]map[string]debtAggregate, dimension EvidenceDebtBreakdownDimension, key string, points uint64) error {
	if values[dimension] == nil {
		values[dimension] = map[string]debtAggregate{}
	}
	aggregate := values[dimension][key]
	var err error
	aggregate.count, err = checkedAdd(aggregate.count, 1)
	if err != nil {
		return err
	}
	aggregate.points, err = checkedAdd(aggregate.points, points)
	if err != nil {
		return err
	}
	values[dimension][key] = aggregate
	return nil
}

func flattenDebtBreakdowns(values map[EvidenceDebtBreakdownDimension]map[string]debtAggregate) []EvidenceDebtBreakdown {
	var result []EvidenceDebtBreakdown
	for dimension, entries := range values {
		for key, aggregate := range entries {
			result = append(result, EvidenceDebtBreakdown{Dimension: dimension, Key: key, OpenCount: aggregate.count, OpenPoints: aggregate.points})
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Dimension != result[j].Dimension {
			return result[i].Dimension < result[j].Dimension
		}
		if result[i].OpenPoints != result[j].OpenPoints {
			return result[i].OpenPoints > result[j].OpenPoints
		}
		return result[i].Key < result[j].Key
	})
	return result
}

func signedDelta(added, removed uint64) (int64, error) {
	if added > math.MaxInt64 || removed > math.MaxInt64 {
		return 0, fmt.Errorf("%w: debt delta exceeds signed range", ErrInvalidReliabilityInput)
	}
	return int64(added) - int64(removed), nil
}
