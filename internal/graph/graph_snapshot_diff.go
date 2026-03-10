package graph

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

// GraphSnapshotReference is the lightweight snapshot handle embedded in ancestry and diff resources.
type GraphSnapshotReference struct {
	ID               string     `json:"id"`
	ParentSnapshotID string     `json:"parent_snapshot_id,omitempty"`
	BuiltAt          *time.Time `json:"built_at,omitempty"`
	CapturedAt       *time.Time `json:"captured_at,omitempty"`
	Current          bool       `json:"current,omitempty"`
	Diffable         bool       `json:"diffable,omitempty"`
}

// GraphSnapshotAncestry captures the ordered neighborhood of one graph snapshot.
type GraphSnapshotAncestry struct {
	SnapshotID  string                   `json:"snapshot_id"`
	Position    int                      `json:"position"`
	Count       int                      `json:"count"`
	Parent      *GraphSnapshotReference  `json:"parent,omitempty"`
	Children    []GraphSnapshotReference `json:"children,omitempty"`
	Previous    *GraphSnapshotReference  `json:"previous,omitempty"`
	Next        *GraphSnapshotReference  `json:"next,omitempty"`
	Ancestors   []GraphSnapshotReference `json:"ancestors,omitempty"`
	Descendants []GraphSnapshotReference `json:"descendants,omitempty"`
}

// GraphSnapshotDiffSummary captures the high-level shape of one structural graph diff.
type GraphSnapshotDiffSummary struct {
	NodesAdded    int `json:"nodes_added"`
	NodesRemoved  int `json:"nodes_removed"`
	NodesModified int `json:"nodes_modified"`
	EdgesAdded    int `json:"edges_added"`
	EdgesRemoved  int `json:"edges_removed"`
}

// GraphSnapshotDiffRecord is the typed diff resource between two graph snapshots.
type GraphSnapshotDiffRecord struct {
	ID            string                   `json:"id"`
	GeneratedAt   time.Time                `json:"generated_at"`
	StoredAt      *time.Time               `json:"stored_at,omitempty"`
	Materialized  bool                     `json:"materialized,omitempty"`
	StorageClass  string                   `json:"storage_class,omitempty"`
	ByteSize      int64                    `json:"byte_size,omitempty"`
	IntegrityHash string                   `json:"integrity_hash,omitempty"`
	JobID         string                   `json:"job_id,omitempty"`
	From          GraphSnapshotReference   `json:"from"`
	To            GraphSnapshotReference   `json:"to"`
	Summary       GraphSnapshotDiffSummary `json:"summary"`
	Diff          GraphDiff                `json:"diff"`
}

// GraphSnapshotAncestryFromCollection derives ordered ancestry metadata from a snapshot collection.
func GraphSnapshotAncestryFromCollection(collection GraphSnapshotCollection, snapshotID string) (*GraphSnapshotAncestry, bool) {
	snapshotID = strings.TrimSpace(snapshotID)
	if snapshotID == "" {
		return nil, false
	}
	ordered := append([]GraphSnapshotRecord(nil), collection.Snapshots...)
	sort.Slice(ordered, func(i, j int) bool {
		left := graphSnapshotSortTime(ordered[i])
		right := graphSnapshotSortTime(ordered[j])
		if !left.Equal(right) {
			return left.Before(right)
		}
		return ordered[i].ID < ordered[j].ID
	})
	index := -1
	for i := range ordered {
		if strings.TrimSpace(ordered[i].ID) == snapshotID {
			index = i
			break
		}
	}
	if index == -1 {
		return nil, false
	}
	recordByID := make(map[string]GraphSnapshotRecord, len(ordered))
	childrenByParent := make(map[string][]GraphSnapshotRecord)
	for _, record := range ordered {
		recordByID[strings.TrimSpace(record.ID)] = record
		parentID := strings.TrimSpace(record.ParentSnapshotID)
		if parentID != "" {
			childrenByParent[parentID] = append(childrenByParent[parentID], record)
		}
	}
	ancestry := &GraphSnapshotAncestry{
		SnapshotID: snapshotID,
		Position:   index + 1,
		Count:      len(ordered),
	}
	if record, ok := recordByID[snapshotID]; ok {
		if parentID := strings.TrimSpace(record.ParentSnapshotID); parentID != "" {
			if parent, ok := recordByID[parentID]; ok {
				parentRef := graphSnapshotReference(parent)
				ancestry.Parent = &parentRef
			}
		}
		if children := append([]GraphSnapshotRecord(nil), childrenByParent[snapshotID]...); len(children) > 0 {
			sort.Slice(children, func(i, j int) bool {
				left := graphSnapshotSortTime(children[i])
				right := graphSnapshotSortTime(children[j])
				if !left.Equal(right) {
					return left.Before(right)
				}
				return children[i].ID < children[j].ID
			})
			ancestry.Children = make([]GraphSnapshotReference, 0, len(children))
			for _, child := range children {
				ancestry.Children = append(ancestry.Children, graphSnapshotReference(child))
			}
			ancestry.Descendants = collectGraphSnapshotDescendants(snapshotID, childrenByParent)
		}
		ancestry.Ancestors = collectGraphSnapshotAncestors(snapshotID, recordByID)
	}
	if index > 0 {
		prev := graphSnapshotReference(ordered[index-1])
		ancestry.Previous = &prev
		if len(ancestry.Ancestors) == 0 {
			ancestry.Ancestors = make([]GraphSnapshotReference, 0, index)
			for i := index - 1; i >= 0; i-- {
				ancestry.Ancestors = append(ancestry.Ancestors, graphSnapshotReference(ordered[i]))
			}
		}
	}
	if index+1 < len(ordered) {
		next := graphSnapshotReference(ordered[index+1])
		ancestry.Next = &next
		if len(ancestry.Descendants) == 0 {
			ancestry.Descendants = make([]GraphSnapshotReference, 0, len(ordered)-index-1)
			for i := index + 1; i < len(ordered); i++ {
				ancestry.Descendants = append(ancestry.Descendants, graphSnapshotReference(ordered[i]))
			}
		}
	}
	return ancestry, true
}

// BuildGraphSnapshotDiffRecord constructs a typed diff resource between two snapshots.
func BuildGraphSnapshotDiffRecord(from, to GraphSnapshotRecord, diff *GraphDiff, now time.Time) *GraphSnapshotDiffRecord {
	if diff == nil {
		return nil
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	record := &GraphSnapshotDiffRecord{
		ID:          graphSnapshotDiffID(from.ID, to.ID),
		GeneratedAt: now.UTC(),
		From:        graphSnapshotReference(from),
		To:          graphSnapshotReference(to),
		Summary: GraphSnapshotDiffSummary{
			NodesAdded:    len(diff.NodesAdded),
			NodesRemoved:  len(diff.NodesRemoved),
			NodesModified: len(diff.NodesModified),
			EdgesAdded:    len(diff.EdgesAdded),
			EdgesRemoved:  len(diff.EdgesRemoved),
		},
		Diff: *diff,
	}
	return record
}

func graphSnapshotReference(record GraphSnapshotRecord) GraphSnapshotReference {
	return GraphSnapshotReference{
		ID:               strings.TrimSpace(record.ID),
		ParentSnapshotID: strings.TrimSpace(record.ParentSnapshotID),
		BuiltAt:          cloneTimePtr(record.BuiltAt),
		CapturedAt:       cloneTimePtr(record.CapturedAt),
		Current:          record.Current,
		Diffable:         record.Diffable,
	}
}

func graphSnapshotDiffID(fromSnapshotID, toSnapshotID string) string {
	payload := fmt.Sprintf("%s|%s", strings.TrimSpace(fromSnapshotID), strings.TrimSpace(toSnapshotID))
	sum := sha256.Sum256([]byte(payload))
	return "graph_snapshot_diff:" + hex.EncodeToString(sum[:12])
}

func collectGraphSnapshotAncestors(snapshotID string, recordByID map[string]GraphSnapshotRecord) []GraphSnapshotReference {
	ancestors := make([]GraphSnapshotReference, 0)
	seen := map[string]struct{}{}
	currentID := strings.TrimSpace(recordByID[snapshotID].ParentSnapshotID)
	for currentID != "" {
		if _, ok := seen[currentID]; ok {
			break
		}
		seen[currentID] = struct{}{}
		record, ok := recordByID[currentID]
		if !ok {
			break
		}
		ancestors = append(ancestors, graphSnapshotReference(record))
		currentID = strings.TrimSpace(record.ParentSnapshotID)
	}
	return ancestors
}

func collectGraphSnapshotDescendants(snapshotID string, childrenByParent map[string][]GraphSnapshotRecord) []GraphSnapshotReference {
	queue := append([]GraphSnapshotRecord(nil), childrenByParent[snapshotID]...)
	if len(queue) == 0 {
		return nil
	}
	sort.Slice(queue, func(i, j int) bool {
		left := graphSnapshotSortTime(queue[i])
		right := graphSnapshotSortTime(queue[j])
		if !left.Equal(right) {
			return left.Before(right)
		}
		return queue[i].ID < queue[j].ID
	})
	descendants := make([]GraphSnapshotReference, 0)
	seen := map[string]struct{}{}
	for len(queue) > 0 {
		record := queue[0]
		queue = queue[1:]
		recordID := strings.TrimSpace(record.ID)
		if _, ok := seen[recordID]; ok {
			continue
		}
		seen[recordID] = struct{}{}
		descendants = append(descendants, graphSnapshotReference(record))
		children := append([]GraphSnapshotRecord(nil), childrenByParent[recordID]...)
		sort.Slice(children, func(i, j int) bool {
			left := graphSnapshotSortTime(children[i])
			right := graphSnapshotSortTime(children[j])
			if !left.Equal(right) {
				return left.Before(right)
			}
			return children[i].ID < children[j].ID
		})
		queue = append(queue, children...)
	}
	return descendants
}
