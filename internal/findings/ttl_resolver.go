package findings

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/workflowevents"
)

const ttlResolveLogEvent = "ttl.resolve"

const ttlResolutionReasonPrefix = workflowevents.FindingStatusReasonTTLExpired + ":"

const ttlResolverListLimit = uint32(500)

// ttlClock is the per-Service "now" boundary used by the TTL sweeper. Tests
// inject a fixed clock via Service.WithTTLClock so the sweeper can be exercised
// with a pinned now() without having to forge LastObservedAt across many
// candidates. Implemented as an interface (not a func var on Service) so the
// novarfunc lint allows it as a proper injected dependency.
type ttlClock interface {
	Now() time.Time
}

// ttlLogSink is the structured-log boundary the TTL sweeper writes ttl.resolve
// events to. Defaults to os.Stdout; tests inject a buffer via
// Service.WithTTLLogSink to capture the JSON lines emitted per resolved finding.
type ttlLogSink interface {
	io.Writer
}

type ttlSystemClock struct{}

func (ttlSystemClock) Now() time.Time { return time.Now().UTC() }

// WithTTLClock wires an explicit clock for the TTL sweeper.
func (s *Service) WithTTLClock(clock ttlClock) *Service {
	if s == nil {
		return nil
	}
	s.ttlClock = clock
	return s
}

// WithTTLLogSink wires an explicit structured-log sink for the TTL sweeper.
func (s *Service) WithTTLLogSink(sink ttlLogSink) *Service {
	if s == nil {
		return nil
	}
	s.ttlLogSink = sink
	return s
}

func (s *Service) ttlClockNow() time.Time {
	if s == nil || s.ttlClock == nil {
		return ttlSystemClock{}.Now()
	}
	return s.ttlClock.Now().UTC()
}

func (s *Service) ttlSink() io.Writer {
	if s == nil || s.ttlLogSink == nil {
		return os.Stdout
	}
	return s.ttlLogSink
}

// resolveTTLOpenFindings auto-resolves open findings for one ttl_evidence rule
// whose last_observed_at has aged past the rule's Lifecycle.TTL. Architecture
// component 7: generic TTL primitive.
//
// Semantics:
//   - no-op when the rule is not registered, is not a MetadataRule, or whose
//     Lifecycle.Kind is not LifecycleTTLEvidence (or whose TTL is non-positive);
//   - resolves only non-tombstoned open candidates whose last_observed_at is
//     strictly before now()-TTL; routes the write through updateFindingStatusAndRisk
//     so manual state (assignee/notes/tickets/risk) is preserved by the same
//     guard the manual-resolution path uses;
//   - sets resolution_reason = "ttl_expired:<TTL>" (compact label, e.g. "24h");
//   - emits a workflow.v1.finding.status_changed event with the TTL reason so
//     workflow replay and graph projection observe the resolution;
//   - emits exactly one structured JSON log line per resolved row containing
//     event=ttl.resolve and rule_id/finding_id/ttl/resolved_at;
//   - is idempotent: a second invocation with no fresh emits between produces
//     zero UPDATE calls because the resolved rows no longer match status='open';
//   - leaves the tombstone columns alone, so a non-tombstoned row reopens on
//     the next emit via the existing reopen-on-emit upsert path.
func (s *Service) resolveTTLOpenFindings(ctx context.Context, tenantID string, ruleID string) error {
	if s == nil || s.store == nil || s.rules == nil {
		return nil
	}
	tenantID = strings.TrimSpace(tenantID)
	id := strings.TrimSpace(ruleID)
	if id == "" {
		return nil
	}
	rule, ok := s.rules.Get(id)
	if !ok {
		return nil
	}
	metadataRule, ok := rule.(MetadataRule)
	if !ok {
		return nil
	}
	definition := metadataRule.RuleMetadata()
	if definition.Lifecycle.Kind != LifecycleTTLEvidence {
		return nil
	}
	ttl := definition.Lifecycle.TTL
	if ttl <= 0 {
		return nil
	}
	now := s.ttlClockNow()
	cutoff := now.Add(-ttl)
	ttlLabel := formatTTLDuration(ttl)
	reason := ttlResolutionReasonPrefix + ttlLabel
	sink := s.ttlSink()
	for {
		candidates, err := s.store.ListFindings(ctx, ports.ListFindingsRequest{
			TenantID:           tenantID,
			RuleID:             id,
			Status:             findingStatusOpen,
			LastObservedBefore: cutoff,
			Limit:              ttlResolverListLimit,
		})
		if err != nil {
			return fmt.Errorf("list ttl candidates for rule %q: %w", id, err)
		}
		if len(candidates) == 0 {
			return nil
		}
		for _, finding := range candidates {
			if finding == nil {
				continue
			}
			if finding.Tombstoned {
				continue
			}
			if !finding.LastObservedAt.Before(cutoff) {
				continue
			}
			updated, err := s.updateFindingStatusAndRisk(ctx, ports.FindingStatusUpdate{
				FindingID:          strings.TrimSpace(finding.ID),
				Status:             findingStatusResolved,
				Reason:             reason,
				UpdatedAt:          now,
				ExpectedStatus:     findingStatusOpen,
				LastObservedBefore: cutoff,
			})
			if errors.Is(err, ports.ErrFindingStatusPreconditionFailed) {
				continue
			}
			if err != nil {
				return fmt.Errorf("resolve ttl finding %q: %w", strings.TrimSpace(finding.ID), err)
			}
			if err := s.recordFindingStatusWorkflow(ctx, updated, workflowevents.FindingStatusSourceStaleEvaluation); err != nil {
				return fmt.Errorf("project ttl finding %q resolution: %w", strings.TrimSpace(finding.ID), err)
			}
			resolvedAt := updated.StatusUpdatedAt
			if resolvedAt.IsZero() {
				resolvedAt = now
			}
			writeTTLResolveLog(sink, id, strings.TrimSpace(updated.ID), ttlLabel, resolvedAt)
		}
		if len(candidates) < int(ttlResolverListLimit) {
			return nil
		}
	}
}

func writeTTLResolveLog(sink io.Writer, ruleID, findingID, ttlLabel string, resolvedAt time.Time) {
	encoded, err := json.Marshal(map[string]any{
		"event":       ttlResolveLogEvent,
		"rule_id":     ruleID,
		"finding_id":  findingID,
		"ttl":         ttlLabel,
		"resolved_at": resolvedAt.UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		return
	}
	_, _ = fmt.Fprintln(sink, string(encoded))
}

// formatTTLDuration renders a positive time.Duration as the compact label
// embedded in resolution_reason (e.g. 24h, 30m, 45s). Falling back to
// time.Duration.String() for sub-second or mixed-unit durations keeps the
// label round-trippable through time.ParseDuration.
func formatTTLDuration(d time.Duration) string {
	if d <= 0 {
		return d.String()
	}
	switch {
	case d%time.Hour == 0:
		return fmt.Sprintf("%dh", int64(d/time.Hour))
	case d%time.Minute == 0:
		return fmt.Sprintf("%dm", int64(d/time.Minute))
	case d%time.Second == 0:
		return fmt.Sprintf("%ds", int64(d/time.Second))
	default:
		return d.String()
	}
}
