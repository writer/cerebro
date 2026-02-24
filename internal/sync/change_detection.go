package sync

func buildRowHashes(rows []map[string]interface{}, hashFn func(map[string]interface{}) string) map[string]string {
	result := make(map[string]string, len(rows))
	for _, row := range rows {
		id, ok := row["_cq_id"].(string)
		if !ok || id == "" {
			continue
		}
		result[id] = hashFn(row)
	}
	return result
}

func detectRowChanges(existing map[string]string, newRows map[string]string, incremental bool) *ChangeSet {
	changes := &ChangeSet{}

	if incremental {
		for id, newHash := range newRows {
			if oldHash, exists := existing[id]; !exists {
				changes.Added = append(changes.Added, id)
			} else if newHash != oldHash {
				changes.Modified = append(changes.Modified, id)
			}
		}
		return changes
	}

	for id, oldHash := range existing {
		if newHash, exists := newRows[id]; !exists {
			changes.Removed = append(changes.Removed, id)
		} else if newHash != oldHash {
			changes.Modified = append(changes.Modified, id)
		}
	}

	for id := range newRows {
		if _, exists := existing[id]; !exists {
			changes.Added = append(changes.Added, id)
		}
	}

	return changes
}
