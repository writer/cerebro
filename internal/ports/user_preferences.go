package ports

import (
	"context"
	"errors"
	"time"
)

// ErrUserPreferencesNotFound indicates that no preference row exists for the
// requested tenant/user pair.
var ErrUserPreferencesNotFound = errors.New("user preferences not found")

// UserPreferences stores one user's UI preference document for one tenant.
type UserPreferences struct {
	TenantID        string
	UserID          string
	PreferencesJSON string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// UserPreferenceKey identifies one user's preferences inside one tenant.
type UserPreferenceKey struct {
	TenantID string
	UserID   string
}

// UserPreferenceStore persists user-level console preferences in the state
// store. State stores implement it as an optional capability discovered via type
// assertion.
type UserPreferenceStore interface {
	PutUserPreferences(context.Context, *UserPreferences) error
	GetUserPreferences(context.Context, UserPreferenceKey) (*UserPreferences, error)
}
