package decisionpacket

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
	"time"
)

func DetectContradictions(observations []ClaimObservation) []Contradiction {
	normalized := normalizeObservations(observations)
	result := []Contradiction{}
	for leftIndex := 0; leftIndex < len(normalized); leftIndex++ {
		for rightIndex := leftIndex + 1; rightIndex < len(normalized); rightIndex++ {
			left, right := normalized[leftIndex], normalized[rightIndex]
			if !sameClaimKey(left, right) || left.Value == right.Value || !validityOverlaps(left, right) {
				continue
			}
			if cleanlySuperseded(left, right) {
				continue
			}
			idInput := strings.Join([]string{left.TenantID, left.SubjectURN, left.Predicate, left.Evidence.ID, right.Evidence.ID}, "\x00")
			digest := sha256.Sum256([]byte(idInput))
			result = append(result, Contradiction{
				ID: fmt.Sprintf("con_%x", digest[:16]), SubjectURN: left.SubjectURN, Predicate: left.Predicate,
				Left: left.Evidence, Right: right.Evidence, ResolutionState: ContradictionUnresolved,
				PrimaryClaim: left.PrimaryClaim || right.PrimaryClaim,
			})
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}

func normalizeObservations(values []ClaimObservation) []ClaimObservation {
	result := make([]ClaimObservation, 0, len(values))
	for _, value := range values {
		value.TenantID = strings.TrimSpace(value.TenantID)
		value.SubjectURN = strings.TrimSpace(value.SubjectURN)
		value.Predicate = strings.ToLower(strings.TrimSpace(value.Predicate))
		value.Value = strings.ToLower(strings.TrimSpace(value.Value))
		value.SourceID = strings.TrimSpace(value.SourceID)
		value.ValidFrom = value.ValidFrom.UTC()
		value.ValidTo = value.ValidTo.UTC()
		value.ObservedAt = value.ObservedAt.UTC()
		value.Evidence = normalizeEvidenceReference(value.Evidence)
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool {
		left, right := result[i], result[j]
		return observationKey(left) < observationKey(right)
	})
	return result
}

func sameClaimKey(left, right ClaimObservation) bool {
	return left.TenantID == right.TenantID && left.SubjectURN == right.SubjectURN && left.Predicate == right.Predicate
}

func validityOverlaps(left, right ClaimObservation) bool {
	leftEnd, rightEnd := left.ValidTo, right.ValidTo
	if leftEnd.IsZero() {
		leftEnd = time.Date(9999, 12, 31, 0, 0, 0, 0, time.UTC)
	}
	if rightEnd.IsZero() {
		rightEnd = time.Date(9999, 12, 31, 0, 0, 0, 0, time.UTC)
	}
	return !leftEnd.Before(right.ValidFrom) && !rightEnd.Before(left.ValidFrom)
}

func cleanlySuperseded(left, right ClaimObservation) bool {
	if left.SourceID == "" || left.SourceID != right.SourceID || left.ObservedAt.Equal(right.ObservedAt) {
		return false
	}
	older, newer := left, right
	if newer.ObservedAt.Before(older.ObservedAt) {
		older, newer = newer, older
	}
	return !older.ValidTo.IsZero() && !older.ValidTo.After(newer.ValidFrom)
}

func observationKey(value ClaimObservation) string {
	return strings.Join([]string{value.TenantID, value.SubjectURN, value.Predicate, value.Value, value.ValidFrom.Format(time.RFC3339Nano), value.Evidence.ID}, "\x00")
}
