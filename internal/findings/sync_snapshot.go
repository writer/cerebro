package findings

import "encoding/json"

func cloneFindingForSync(f *Finding) (*Finding, error) {
	if f == nil {
		return nil, nil
	}

	raw, err := json.Marshal(f)
	if err != nil {
		return nil, err
	}

	var clone Finding
	if err := json.Unmarshal(raw, &clone); err != nil {
		return nil, err
	}
	clone.resourceJSONRaw = cloneBytes(f.resourceJSONRaw)
	return &clone, nil
}

func snapshotDirtyFindings(cache map[string]*Finding, dirty map[string]bool) ([]*Finding, error) {
	if len(dirty) == 0 {
		return nil, nil
	}

	findings := make([]*Finding, 0, len(dirty))
	for id := range dirty {
		finding, ok := cache[id]
		if !ok || finding == nil {
			continue
		}

		clone, err := cloneFindingForSync(finding)
		if err != nil {
			return nil, err
		}
		findings = append(findings, clone)
	}
	return findings, nil
}
