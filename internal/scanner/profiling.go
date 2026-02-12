package scanner

import (
	"sort"
	"time"
)

type TableScanProfile struct {
	Table         string
	Duration      time.Duration
	Scanned       int64
	Violations    int64
	CacheSkipped  int64
	Batches       int
	RetryAttempts int
	FetchErrors   int
	ScanErrors    int
	TimedOut      bool
}

type ScanProfileSummary struct {
	Tables          []TableScanProfile
	TotalScanned    int64
	TotalViolations int64
	TotalSkipped    int64
	TotalDuration   time.Duration
}

func SummarizeTableProfiles(profiles []TableScanProfile, duration time.Duration) ScanProfileSummary {
	summary := ScanProfileSummary{
		Tables:        profiles,
		TotalDuration: duration,
	}
	for _, profile := range profiles {
		summary.TotalScanned += profile.Scanned
		summary.TotalViolations += profile.Violations
		summary.TotalSkipped += profile.CacheSkipped
	}
	return summary
}

func SortTableProfilesByDuration(profiles []TableScanProfile) []TableScanProfile {
	if len(profiles) == 0 {
		return nil
	}
	sorted := make([]TableScanProfile, len(profiles))
	copy(sorted, profiles)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Duration > sorted[j].Duration
	})
	return sorted
}

func FilterSlowTables(profiles []TableScanProfile, threshold time.Duration) []TableScanProfile {
	if threshold <= 0 {
		return nil
	}
	var slow []TableScanProfile
	for _, profile := range profiles {
		if profile.Duration >= threshold {
			slow = append(slow, profile)
		}
	}
	return slow
}
