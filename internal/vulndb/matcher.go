package vulndb

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// Matcher evaluates installed package inventory against the advisory store.
type Matcher struct {
	store Store
}

// NewMatcher constructs a package vulnerability matcher.
func NewMatcher(store Store) (*Matcher, error) {
	if store == nil {
		return nil, fmt.Errorf("vulnerability store is required")
	}
	return &Matcher{store: store}, nil
}

// MatchPackage returns non-withdrawn vulnerability matches for an installed package.
func (m *Matcher) MatchPackage(ctx context.Context, query PackageQuery) ([]Match, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	query.Ecosystem = normalizeEcosystem(query.Ecosystem)
	query.Name = strings.TrimSpace(query.Name)
	query.Version = strings.TrimSpace(query.Version)
	if query.Ecosystem == "" || query.Name == "" || query.Version == "" {
		return nil, nil
	}
	candidates, err := m.store.CandidateAffectedPackages(ctx, query)
	if err != nil {
		return nil, err
	}
	matches := make([]Match, 0, len(candidates))
	for _, candidate := range candidates {
		if !affectsVersion(query, candidate) {
			continue
		}
		vulnerability, ok, err := m.store.FindVulnerability(ctx, candidate.VulnerabilityID)
		if err != nil {
			return nil, err
		}
		if !ok || !vulnerability.WithdrawnAt.IsZero() {
			continue
		}
		matches = append(matches, Match{
			Vulnerability:   vulnerability,
			AffectedPackage: candidate,
		})
	}
	return matches, nil
}

func affectsVersion(query PackageQuery, affected AffectedPackage) bool {
	version := strings.TrimSpace(query.Version)
	if version == "" {
		return false
	}
	if exact := strings.TrimSpace(affected.VulnerableVersion); exact != "" {
		return normalizeVersion(version) == normalizeVersion(exact)
	}
	if fixed := strings.TrimSpace(affected.Fixed); fixed != "" {
		cmp, ok := compareVersion(version, fixed)
		if !ok || cmp >= 0 {
			return false
		}
	}
	if introduced := strings.TrimSpace(affected.Introduced); introduced != "" {
		cmp, ok := compareVersion(version, introduced)
		if !ok || cmp < 0 {
			return false
		}
	}
	if lastAffected := strings.TrimSpace(affected.LastAffected); lastAffected != "" {
		cmp, ok := compareVersion(version, lastAffected)
		if !ok || cmp > 0 {
			return false
		}
	}
	return strings.TrimSpace(affected.Fixed) != "" ||
		strings.TrimSpace(affected.Introduced) != "" ||
		strings.TrimSpace(affected.LastAffected) != ""
}

func compareVersion(left string, right string) (int, bool) {
	leftParts, ok := numericVersionParts(left)
	if !ok {
		return 0, false
	}
	rightParts, ok := numericVersionParts(right)
	if !ok {
		return 0, false
	}
	maxParts := len(leftParts)
	if len(rightParts) > maxParts {
		maxParts = len(rightParts)
	}
	for i := 0; i < maxParts; i++ {
		leftPart := 0
		if i < len(leftParts) {
			leftPart = leftParts[i]
		}
		rightPart := 0
		if i < len(rightParts) {
			rightPart = rightParts[i]
		}
		if leftPart < rightPart {
			return -1, true
		}
		if leftPart > rightPart {
			return 1, true
		}
	}
	return 0, true
}

func numericVersionParts(version string) ([]int, bool) {
	version = normalizeVersion(version)
	version = strings.TrimPrefix(version, "v")
	if version == "" {
		return nil, false
	}
	fields := strings.FieldsFunc(version, func(r rune) bool {
		return r == '.' || r == '-' || r == '_' || r == '+'
	})
	parts := make([]int, 0, len(fields))
	for _, field := range fields {
		if field == "" {
			continue
		}
		value, err := strconv.Atoi(field)
		if err != nil {
			break
		}
		parts = append(parts, value)
	}
	return parts, len(parts) > 0
}

func normalizeVersion(version string) string {
	return strings.ToLower(strings.TrimSpace(version))
}
