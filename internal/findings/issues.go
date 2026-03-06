package findings

import (
	"context"
	"errors"
	"time"
)

var (
	ErrIssueNotFound = errors.New("issue not found")
)

// IssueManager provides issue lifecycle management for findings
type IssueManager struct {
	store FindingStore
}

// NewIssueManager creates a new issue manager
func NewIssueManager(store FindingStore) *IssueManager {
	return &IssueManager{store: store}
}

func (m *IssueManager) updateIssue(issueID string, mutate func(*Finding, time.Time) error) error {
	return m.store.Update(issueID, func(f *Finding) error {
		now := time.Now()
		return mutate(f, now)
	})
}

// Assign assigns an issue to a user
func (m *IssueManager) Assign(issueID, assignee string) error {
	return m.updateIssue(issueID, func(f *Finding, now time.Time) error {
		f.AssigneeName = assignee
		f.UpdatedAt = now
		return nil
	})
}

// SetDueDate sets the due date for an issue
func (m *IssueManager) SetDueDate(issueID string, dueAt time.Time) error {
	return m.updateIssue(issueID, func(f *Finding, now time.Time) error {
		f.DueAt = &dueAt
		f.UpdatedAt = now
		return nil
	})
}

// AddNote adds a note to an issue
func (m *IssueManager) AddNote(issueID, note string) error {
	return m.updateIssue(issueID, func(f *Finding, now time.Time) error {
		if f.Notes != "" {
			f.Notes = f.Notes + "\n---\n" + note
		} else {
			f.Notes = note
		}
		f.UpdatedAt = now
		return nil
	})
}

// LinkTicket links a ticket to an issue
func (m *IssueManager) LinkTicket(issueID, ticketURL, ticketName, ticketExternalID string) error {
	return m.updateIssue(issueID, func(f *Finding, now time.Time) error {
		if ticketURL != "" {
			f.TicketURLs = append(f.TicketURLs, ticketURL)
		}
		if ticketName != "" {
			f.TicketNames = append(f.TicketNames, ticketName)
		}
		if ticketExternalID != "" {
			f.TicketExternalIDs = append(f.TicketExternalIDs, ticketExternalID)
		}
		f.UpdatedAt = now
		return nil
	})
}

// SetStatus changes the status of an issue
func (m *IssueManager) SetStatus(issueID, status string) error {
	return m.updateIssue(issueID, func(f *Finding, now time.Time) error {
		normalized := normalizeStatus(status)
		if normalized == "" {
			normalized = status
		}
		f.Status = normalized
		f.StatusChangedAt = &now
		f.UpdatedAt = now

		if normalized == "RESOLVED" {
			f.ResolvedAt = &now
		} else {
			f.ResolvedAt = nil
		}
		return nil
	})
}

// Resolve marks an issue as resolved with a resolution reason
func (m *IssueManager) Resolve(issueID, resolution string) error {
	return m.updateIssue(issueID, func(f *Finding, now time.Time) error {
		f.Status = "RESOLVED"
		f.Resolution = resolution
		f.ResolvedAt = &now
		f.StatusChangedAt = &now
		f.UpdatedAt = now
		return nil
	})
}

// Suppress marks an issue as suppressed (accepted risk)
func (m *IssueManager) Suppress(issueID, reason string) error {
	return m.updateIssue(issueID, func(f *Finding, now time.Time) error {
		f.Status = "SUPPRESSED"
		f.Resolution = reason
		f.StatusChangedAt = &now
		f.UpdatedAt = now
		return nil
	})
}

// Reopen reopens a resolved or suppressed issue
func (m *IssueManager) Reopen(issueID string) error {
	return m.updateIssue(issueID, func(f *Finding, now time.Time) error {
		f.Status = "OPEN"
		f.Resolution = ""
		f.ResolvedAt = nil
		f.StatusChangedAt = &now
		f.UpdatedAt = now
		return nil
	})
}

// SetInProgress marks an issue as in progress
func (m *IssueManager) SetInProgress(issueID string) error {
	return m.updateIssue(issueID, func(f *Finding, now time.Time) error {
		f.Status = "IN_PROGRESS"
		f.StatusChangedAt = &now
		f.UpdatedAt = now
		return nil
	})
}

// BulkAssign assigns multiple issues to a user
func (m *IssueManager) BulkAssign(issueIDs []string, assignee string) (int, error) {
	count := 0
	for _, id := range issueIDs {
		if err := m.Assign(id, assignee); err == nil {
			count++
		}
	}
	return count, nil
}

// BulkResolve resolves multiple issues
func (m *IssueManager) BulkResolve(issueIDs []string, resolution string) (int, error) {
	count := 0
	for _, id := range issueIDs {
		if err := m.Resolve(id, resolution); err == nil {
			count++
		}
	}
	return count, nil
}

// BulkSuppress suppresses multiple issues
func (m *IssueManager) BulkSuppress(issueIDs []string, reason string) (int, error) {
	count := 0
	for _, id := range issueIDs {
		if err := m.Suppress(id, reason); err == nil {
			count++
		}
	}
	return count, nil
}

// Sync persists all changes to the underlying store
func (m *IssueManager) Sync(ctx context.Context) error {
	return m.store.Sync(ctx)
}
