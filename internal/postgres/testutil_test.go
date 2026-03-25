package postgres

import "time"

// fixedTime returns a deterministic time for test comparisons.
func fixedTime() time.Time {
	return time.Date(2025, 1, 15, 12, 0, 0, 0, time.UTC)
}
