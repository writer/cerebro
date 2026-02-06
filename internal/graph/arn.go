package graph

import (
	"fmt"
	"regexp"
	"strings"
)

// ARN represents a parsed AWS ARN
type ARN struct {
	Partition string
	Service   string
	Region    string
	Account   string
	Resource  string
}

// ParseARN parses an ARN string into its components
func ParseARN(arn string) (*ARN, error) {
	if arn == "*" {
		return &ARN{
			Partition: "*",
			Service:   "*",
			Region:    "*",
			Account:   "*",
			Resource:  "*",
		}, nil
	}

	parts := strings.SplitN(arn, ":", 6)
	if len(parts) < 6 || parts[0] != "arn" {
		return nil, fmt.Errorf("invalid ARN format: %s", arn)
	}

	return &ARN{
		Partition: parts[1],
		Service:   parts[2],
		Region:    parts[3],
		Account:   parts[4],
		Resource:  parts[5],
	}, nil
}

// String returns the ARN as a string
func (a *ARN) String() string {
	return fmt.Sprintf("arn:%s:%s:%s:%s:%s", a.Partition, a.Service, a.Region, a.Account, a.Resource)
}

// ResourcePrefix returns "service:resourceType" for indexing.
// For resource "role/my-role" this returns "iam:role".
func (a *ARN) ResourcePrefix() string {
	resType := a.Resource
	if i := strings.IndexAny(resType, "/:"); i > 0 {
		resType = resType[:i]
	}
	return a.Service + ":" + resType
}

// MatchesPattern checks if this ARN matches a pattern ARN (with wildcards)
func (a *ARN) MatchesPattern(pattern *ARN) bool {
	return matchComponent(a.Partition, pattern.Partition) &&
		matchComponent(a.Service, pattern.Service) &&
		matchComponent(a.Region, pattern.Region) &&
		matchComponent(a.Account, pattern.Account) &&
		matchComponent(a.Resource, pattern.Resource)
}

// matchComponent handles AWS wildcard matching
// Supports: * (match all), ? (match single char)
func matchComponent(value, pattern string) bool {
	if pattern == "*" || pattern == "" {
		return true
	}
	if value == pattern {
		return true
	}

	// Convert AWS wildcard pattern to regex
	regexPattern := "^" + regexp.QuoteMeta(pattern) + "$"
	regexPattern = strings.ReplaceAll(regexPattern, `\*`, ".*")
	regexPattern = strings.ReplaceAll(regexPattern, `\?`, ".")

	matched, err := regexp.MatchString(regexPattern, value)
	if err != nil {
		return false
	}
	return matched
}

// ExtractAccountFromARN extracts the account ID from an ARN string
func ExtractAccountFromARN(arn string) string {
	parsed, err := ParseARN(arn)
	if err != nil {
		return ""
	}
	return parsed.Account
}

// ARNMatcher provides efficient ARN pattern matching against a set of nodes
type ARNMatcher struct {
	patterns []*ARN
}

// NewARNMatcher creates a new ARN matcher from a list of pattern strings
func NewARNMatcher(patterns []string) *ARNMatcher {
	m := &ARNMatcher{
		patterns: make([]*ARN, 0, len(patterns)),
	}
	for _, p := range patterns {
		if parsed, err := ParseARN(p); err == nil {
			m.patterns = append(m.patterns, parsed)
		}
	}
	return m
}

// MatchesAny returns true if the given ARN matches any pattern
func (m *ARNMatcher) MatchesAny(arn string) bool {
	parsed, err := ParseARN(arn)
	if err != nil {
		return false
	}
	for _, pattern := range m.patterns {
		if parsed.MatchesPattern(pattern) {
			return true
		}
	}
	return false
}

// FindMatchingNodes returns all nodes whose IDs match the pattern.
// Uses the ARN prefix index when available for O(bucket) instead of O(all nodes).
func FindMatchingNodes(g *Graph, pattern string) []*Node {
	patternARN, err := ParseARN(pattern)
	if err != nil {
		return nil
	}

	// Special case: * matches all resource nodes
	if pattern == "*" {
		return g.GetNodesByKind(NodeKindBucket, NodeKindInstance, NodeKindDatabase, NodeKindSecret, NodeKindFunction)
	}

	// Use ARN prefix index if available and pattern has a concrete service + resource type
	prefix := patternARN.ResourcePrefix()
	if g.IsIndexBuilt() && patternARN.Service != "*" && !strings.Contains(prefix, "*") {
		candidates := g.GetResourceNodesByARNPrefix(prefix)
		if candidates != nil {
			var matches []*Node
			for _, node := range candidates {
				nodeARN, err := ParseARN(node.ID)
				if err != nil {
					continue
				}
				if nodeARN.MatchesPattern(patternARN) {
					matches = append(matches, node)
				}
			}
			return matches
		}
	}

	// Fallback: full scan
	var matches []*Node
	for _, node := range g.GetAllNodes() {
		if !node.IsResource() {
			continue
		}
		nodeARN, err := ParseARN(node.ID)
		if err != nil {
			continue
		}
		if nodeARN.MatchesPattern(patternARN) {
			matches = append(matches, node)
		}
	}
	return matches
}
