package graph

import "strings"

// StoreBackend identifies the persistence implementation that serves the
// GraphStore contract.
type StoreBackend string

const (
	StoreBackendMemory  StoreBackend = "memory"
	StoreBackendNeptune StoreBackend = "neptune"
	StoreBackendSpanner StoreBackend = "spanner"
)

func ParseStoreBackend(value string) StoreBackend {
	switch StoreBackend(strings.ToLower(strings.TrimSpace(value))) {
	case "", StoreBackendMemory:
		return StoreBackendMemory
	case StoreBackendNeptune:
		return StoreBackendNeptune
	case StoreBackendSpanner:
		return StoreBackendSpanner
	default:
		return StoreBackend(strings.ToLower(strings.TrimSpace(value)))
	}
}

func (b StoreBackend) Valid() bool {
	switch b {
	case StoreBackendMemory, StoreBackendNeptune, StoreBackendSpanner:
		return true
	default:
		return false
	}
}
