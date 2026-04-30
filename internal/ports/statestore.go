package ports

import "context"

// StateStore is the future Postgres-backed current-state boundary.
type StateStore interface {
	Ping(context.Context) error
}
