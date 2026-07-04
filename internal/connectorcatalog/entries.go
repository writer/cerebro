package connectorcatalog

import "strings"

func EntriesBySourceID(entries []Entry) map[string]Entry {
	out := make(map[string]Entry, len(entries))
	for _, entry := range entries {
		sourceID := strings.TrimSpace(entry.Definition.SourceID)
		if sourceID == "" {
			continue
		}
		out[sourceID] = entry
	}
	return out
}
