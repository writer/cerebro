package ports

import "context"

// GraphStore is the future graph projection boundary.
type GraphStore interface {
	Ping(context.Context) error
}
