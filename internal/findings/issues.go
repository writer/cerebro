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

// Assign assigns an issue to a user
func (m *IssueManager) Assign(issueID, assignee string) error {
	f, ok := m.store.Get(issueID)
	if !ok {
		return ErrIssueNotFound
	}
	f.AssigneeName = assignee
	now := time.Now()
	f.UpdatedAt = now
	return nil
}

// SetDueDate sets the due date for an issue
func (m *IssueManager) SetDueDate(issueID string, dueAt time.Time) error {
	f, ok := m.store.Get(issueID)
	if !ok {
		return ErrIssueNotFound
	}
	f.DueAt = &dueAt
	f.UpdatedAt = time.Now()
	return nil
}

// AddNote adds a note to an issue
func (m *IssueManager) AddNote(issueID, note string) error {
	f, ok := m.store.Get(issueID)
	if !ok {
		return ErrIssueNotFound
	}
	if f.Notes != "" {
		f.Notes = f.Notes + "\n---\n" + note
	} else {
		f.Notes = note
	}
	f.UpdatedAt = time.Now()
	return nil
}

// LinkTicket links a ticket to an issue
func (m *IssueManager) LinkTicket(issueID, ticketURL, ticketName, ticketExternalID string) error {
	f, ok := m.store.Get(issueID)
	if !ok {
		return ErrIssueNotFound
	}

	if ticketURL != "" {
		f.TicketURLs = append(f.TicketURLs, ticketURL)
	}
	if ticketName != "" {
		f.TicketNames = append(f.TicketNames, ticketName)
	}
	if ticketExternalID != "" {
		f.TicketExternalIDs = append(f.TicketExternalIDs, ticketExternalID)
	}
	f.UpdatedAt = time.Now()
	return nil
}

// SetStatus changes the status of an issue
func (m *IssueManager) SetStatus(issueID, status string) error {
	f, ok := m.store.Get(issueID)
	if !ok {
		return ErrIssueNotFound
	}

	now := time.Now()
	normalized := normalizeStatus(status)
	if normalized == "" {
		normalized = status
	}
	f.Status = normalized
	f.StatusChangedAt = &now
	f.UpdatedAt = now

	if normalizeStatus(status) == "RESOLVED" {
		f.ResolvedAt = &now
	}

	return nil
}

// Resolve marks an issue as resolved with a resolution reason
func (m *IssueManager) Resolve(issueID, resolution string) error {
	f, ok := m.store.Get(issueID)
	if !ok {
		return ErrIssueNotFound
	}

	now := time.Now()
	f.Status = "RESOLVED"
	f.Resolution = resolution
	f.ResolvedAt = &now
	f.StatusChangedAt = &now
	f.UpdatedAt = now
	return nil
}

// Suppress marks an issue as suppressed (accepted risk)
func (m *IssueManager) Suppress(issueID, reason string) error {
	f, ok := m.store.Get(issueID)
	if !ok {
		return ErrIssueNotFound
	}

	now := time.Now()
	f.Status = "SUPPRESSED"
	f.Resolution = reason
	f.StatusChangedAt = &now
	f.UpdatedAt = now
	return nil
}

// Reopen reopens a resolved or suppressed issue
func (m *IssueManager) Reopen(issueID string) error {
	f, ok := m.store.Get(issueID)
	if !ok {
		return ErrIssueNotFound
	}

	now := time.Now()
	f.Status = "OPEN"
	f.Resolution = ""
	f.ResolvedAt = nil
	f.StatusChangedAt = &now
	f.UpdatedAt = now
	return nil
}

// SetInProgress marks an issue as in progress
func (m *IssueManager) SetInProgress(issueID string) error {
	f, ok := m.store.Get(issueID)
	if !ok {
		return ErrIssueNotFound
	}

	now := time.Now()
	f.Status = "IN_PROGRESS"
	f.StatusChangedAt = &now
	f.UpdatedAt = now
	return nil
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
