package grcprogram

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/writer/cerebro/internal/compliance"
)

func semanticDigest(value any) (compliance.ContentDigest, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("marshal canonical program revision: %w", err)
	}
	digest := sha256.Sum256(payload)
	return compliance.ContentDigest("sha256:" + hex.EncodeToString(digest[:])), nil
}

func normalizeRevisionRefs(values []compliance.RevisionRef) []compliance.RevisionRef {
	result := append([]compliance.RevisionRef(nil), values...)
	for index := range result {
		result[index] = compliance.NormalizeRevisionRef(result[index])
	}
	sort.Slice(result, func(i, j int) bool {
		left, right := result[i], result[j]
		return left.ID+"\x00"+left.RevisionID < right.ID+"\x00"+right.RevisionID
	})
	return deduplicateRevisionRefs(result)
}

func deduplicateRevisionRefs(values []compliance.RevisionRef) []compliance.RevisionRef {
	result := make([]compliance.RevisionRef, 0, len(values))
	for _, value := range values {
		if len(result) != 0 {
			previous := result[len(result)-1]
			if previous.ID == value.ID && previous.RevisionID == value.RevisionID {
				continue
			}
		}
		result = append(result, value)
	}
	return result
}

func normalizeSubjectRefs(values []compliance.SubjectRef) []compliance.SubjectRef {
	result := append([]compliance.SubjectRef(nil), values...)
	for index := range result {
		result[index].Type = strings.TrimSpace(result[index].Type)
		result[index].ID = strings.TrimSpace(result[index].ID)
	}
	sort.Slice(result, func(i, j int) bool {
		return subjectKey(result[i]) < subjectKey(result[j])
	})
	return deduplicateSubjectRefs(result)
}

func deduplicateSubjectRefs(values []compliance.SubjectRef) []compliance.SubjectRef {
	result := make([]compliance.SubjectRef, 0, len(values))
	for _, value := range values {
		if len(result) != 0 && result[len(result)-1] == value {
			continue
		}
		result = append(result, value)
	}
	return result
}

func subjectKey(value compliance.SubjectRef) string {
	return value.Type + "\x00" + value.ID
}

func normalizeParameters(values []ScopeParameter) []ScopeParameter {
	result := append([]ScopeParameter(nil), values...)
	for index := range result {
		result[index].Name = strings.TrimSpace(result[index].Name)
		result[index].Value = strings.TrimSpace(result[index].Value)
		result[index].Rationale = strings.TrimSpace(result[index].Rationale)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Name+"\x00"+result[i].Value < result[j].Name+"\x00"+result[j].Value
	})
	return result
}

func normalizedStrings(values []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
