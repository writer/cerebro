package vulndb

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"unicode"
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
	if introducedExclusive := strings.TrimSpace(affected.IntroducedExclusive); introducedExclusive != "" {
		cmp, ok := compareVersion(version, introducedExclusive)
		if !ok || cmp <= 0 {
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
		strings.TrimSpace(affected.IntroducedExclusive) != "" ||
		strings.TrimSpace(affected.LastAffected) != ""
}

func compareVersion(left string, right string) (int, bool) {
	leftParts, ok := versionParts(left)
	if !ok {
		return 0, false
	}
	rightParts, ok := versionParts(right)
	if !ok {
		return 0, false
	}
	for len(leftParts) > 0 && leftParts[len(leftParts)-1].numeric && leftParts[len(leftParts)-1].number == 0 {
		leftParts = leftParts[:len(leftParts)-1]
	}
	for len(rightParts) > 0 && rightParts[len(rightParts)-1].numeric && rightParts[len(rightParts)-1].number == 0 {
		rightParts = rightParts[:len(rightParts)-1]
	}
	if equalVersionCore(leftParts, rightParts) {
		leftPrerelease := hasPrerelease(left)
		rightPrerelease := hasPrerelease(right)
		if leftPrerelease != rightPrerelease {
			if leftPrerelease {
				return -1, true
			}
			return 1, true
		}
	}
	maxParts := maxInt(len(leftParts), len(rightParts))
	for i := 0; i < maxParts; i++ {
		if i >= len(leftParts) {
			if rightParts[i].numeric && rightParts[i].number == 0 {
				continue
			}
			return -1, true
		}
		if i >= len(rightParts) {
			if leftParts[i].numeric && leftParts[i].number == 0 {
				continue
			}
			return 1, true
		}
		cmp := compareVersionPart(leftParts[i], rightParts[i])
		if cmp != 0 {
			return cmp, true
		}
	}
	return 0, true
}

func equalVersionCore(leftParts []versionPart, rightParts []versionPart) bool {
	leftCore := versionCoreParts(leftParts)
	rightCore := versionCoreParts(rightParts)
	return compareVersionParts(leftCore, rightCore) == 0
}

func versionCoreParts(parts []versionPart) []versionPart {
	for i, part := range parts {
		if !part.numeric {
			return parts[:i]
		}
	}
	return parts
}

func hasPrerelease(version string) bool {
	version = strings.TrimPrefix(normalizeVersion(version), "v")
	if plus := strings.Index(version, "+"); plus >= 0 {
		version = version[:plus]
	}
	if strings.Contains(version, "-") {
		return true
	}
	parts, ok := versionParts(version)
	if !ok {
		return false
	}
	for _, part := range parts {
		if !part.numeric && isPrereleaseToken(part.text) {
			return true
		}
	}
	return false
}

func isPrereleaseToken(token string) bool {
	switch token {
	case "a", "alpha", "b", "beta", "c", "pre", "preview", "rc", "dev":
		return true
	default:
		return false
	}
}

func compareVersionParts(leftParts []versionPart, rightParts []versionPart) int {
	maxParts := maxInt(len(leftParts), len(rightParts))
	for i := 0; i < maxParts; i++ {
		if i >= len(leftParts) {
			if rightParts[i].numeric && rightParts[i].number == 0 {
				continue
			}
			return -1
		}
		if i >= len(rightParts) {
			if leftParts[i].numeric && leftParts[i].number == 0 {
				continue
			}
			return 1
		}
		cmp := compareVersionPart(leftParts[i], rightParts[i])
		if cmp != 0 {
			return cmp
		}
	}
	return 0
}

type versionPart struct {
	numeric bool
	number  int
	text    string
}

func compareVersionPart(left versionPart, right versionPart) int {
	if left.numeric && right.numeric {
		if left.number < right.number {
			return -1
		}
		if left.number > right.number {
			return 1
		}
		return 0
	}
	if left.numeric != right.numeric {
		if left.numeric {
			return -1
		}
		return 1
	}
	return strings.Compare(left.text, right.text)
}

func versionParts(version string) ([]versionPart, bool) {
	version = normalizeVersion(version)
	version = strings.TrimPrefix(version, "v")
	if version == "" {
		return nil, false
	}
	parts := []versionPart{}
	var current strings.Builder
	currentNumeric := false
	hasCurrent := false
	flush := func() {
		if !hasCurrent {
			return
		}
		text := current.String()
		if currentNumeric {
			value, err := strconv.Atoi(text)
			if err == nil {
				parts = append(parts, versionPart{numeric: true, number: value})
			}
		} else {
			parts = append(parts, versionPart{text: text})
		}
		current.Reset()
		hasCurrent = false
	}
	for _, r := range version {
		if r == '.' || r == '-' || r == '_' || r == '+' {
			flush()
			continue
		}
		numeric := unicode.IsDigit(r)
		if hasCurrent && numeric != currentNumeric {
			flush()
		}
		currentNumeric = numeric
		hasCurrent = true
		current.WriteRune(r)
	}
	flush()
	return parts, len(parts) > 0
}

func normalizeVersion(version string) string {
	return strings.ToLower(strings.TrimSpace(version))
}
