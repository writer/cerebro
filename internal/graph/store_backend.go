package graph

import "strings"

// StoreBackend identifies the persistence implementation that serves the
// GraphStore contract.
type StoreBackend string

const (
	StoreBackendNeptune StoreBackend = "neptune"
)

func ParseStoreBackend(value string) StoreBackend {
	switch StoreBackend(strings.ToLower(strings.TrimSpace(value))) {
	case "", StoreBackendNeptune:
		return StoreBackendNeptune
	default:
		return StoreBackend(strings.ToLower(strings.TrimSpace(value)))
	}
}

func (b StoreBackend) Valid() bool {
	return b == StoreBackendNeptune
}
