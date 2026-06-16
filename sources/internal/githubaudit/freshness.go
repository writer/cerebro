package githubaudit

import (
	"context"
	"fmt"
	"strings"
	"time"

	gogithub "github.com/google/go-github/v66/github"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
)

const latestEventKind = "audit_log_latest_event"

// ListFunc fetches GitHub audit entries with caller-supplied options.
type ListFunc func(context.Context, *gogithub.GetAuditLogOptions) ([]*gogithub.AuditEntry, *gogithub.Response, error)

// Options builds GitHub audit-log list options.
func Options(include string, phrase string, order string, after string, perPage int) *gogithub.GetAuditLogOptions {
	opts := &gogithub.GetAuditLogOptions{
		Include: gogithub.String(include),
		Order:   gogithub.String(order),
		ListCursorOptions: gogithub.ListCursorOptions{
			After:   strings.TrimSpace(after),
			PerPage: perPage,
		},
	}
	if strings.TrimSpace(phrase) != "" {
		opts.Phrase = gogithub.String(strings.TrimSpace(phrase))
	}
	return opts
}

// LatestEventChangeProbe fetches the newest audit-log event and returns a
// heuristic family freshness ChangeProbe.
func LatestEventChangeProbe(ctx context.Context, owner string, include string, phrase string, checkpoint *cerebrov1.SourceCheckpoint, list ListFunc) (sourcecdk.ChangeProbe, error) {
	entries, _, err := list(ctx, Options(include, phrase, "desc", "", 1))
	if err != nil {
		return sourcecdk.ChangeProbe{}, err
	}
	return sourcecdk.FamilyFreshnessChangeProbe("github", "audit", checkpoint, latestEventProbe(owner, include, phrase, entries, time.Now().UTC())), nil
}

func latestEventProbe(owner string, include string, phrase string, entries []*gogithub.AuditEntry, observedAt time.Time) sourcecdk.FamilyFreshnessProbe {
	resourceID := "org:" + strings.TrimSpace(owner)
	updatedAt := time.Time{}
	hashParts := []string{latestEventKind, resourceID, "empty", include, phrase}
	if len(entries) > 0 && entries[0] != nil {
		entry := entries[0]
		updatedAt = occurredAt(entry)
		if eventID := eventID(entry, updatedAt); eventID != "" {
			resourceID = eventID
		}
		hashParts = []string{latestEventKind, resourceID, updatedAt.Format(time.RFC3339Nano), entry.GetAction(), entry.GetActor(), include, phrase}
	}
	return sourcecdk.FamilyFreshnessProbe{
		Kind:       latestEventKind,
		ResourceID: resourceID,
		ObservedAt: observedAt,
		UpdatedAt:  updatedAt,
		Hash:       sourcecdk.FamilyFreshnessHash(hashParts...),
		Confidence: sourcecdk.FamilyFreshnessConfidenceHeuristic,
	}
}

func eventID(entry *gogithub.AuditEntry, at time.Time) string {
	if documentID := strings.TrimSpace(entry.GetDocumentID()); documentID != "" {
		return "github-audit-" + documentID
	}
	if !at.IsZero() {
		return fmt.Sprintf("github-audit-%s-%d", strings.TrimSpace(entry.GetAction()), at.UnixMilli())
	}
	return strings.TrimSpace(entry.GetAction())
}

func occurredAt(entry *gogithub.AuditEntry) time.Time {
	if entry == nil {
		return time.Time{}
	}
	if stamp := entry.GetTimestamp(); !stamp.IsZero() {
		return stamp.UTC()
	}
	if stamp := entry.GetCreatedAt(); !stamp.IsZero() {
		return stamp.UTC()
	}
	return time.Time{}
}
