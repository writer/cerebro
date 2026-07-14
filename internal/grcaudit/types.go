// Package grcaudit defines the transport- and storage-independent contracts for
// audit engagements, requests, samples, and immutable package manifests.
package grcaudit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

var (
	// ErrInvalidRequest indicates that an audit-domain command is malformed.
	ErrInvalidRequest = errors.New("invalid audit request")
	// ErrVersionConflict indicates that an optimistic concurrency precondition failed.
	ErrVersionConflict = errors.New("audit aggregate version conflict")
	// ErrEngagementNotFound is deliberately non-disclosing for missing or inaccessible engagements.
	ErrEngagementNotFound = errors.New("audit engagement not found")
	// ErrEvidenceRequestNotFound is deliberately non-disclosing for missing or inaccessible requests.
	ErrEvidenceRequestNotFound = errors.New("audit evidence request not found")
	// ErrPackageNotFound is deliberately non-disclosing for missing or inaccessible packages.
	ErrPackageNotFound = errors.New("audit package not found")
)

func canonicalDigest(value any) (string, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return DigestBytes(payload), nil
}

// DigestBytes returns a lowercase SHA-256 digest with an explicit algorithm prefix.
func DigestBytes(payload []byte) string {
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func digestID(prefix, digest string) string {
	digest = strings.TrimPrefix(strings.TrimSpace(digest), "sha256:")
	if len(digest) > 20 {
		digest = digest[:20]
	}
	return strings.TrimSpace(prefix) + digest
}

func normalizedStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func required(value, field string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("%w: %s is required", ErrInvalidRequest, field)
	}
	return value, nil
}
