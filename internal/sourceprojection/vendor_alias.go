package sourceprojection

import (
	"strings"
	"unicode"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func addVendorAliasLink(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, fromURN string, rawAlias string, matchType string, confidence string) {
	alias := strings.TrimSpace(rawAlias)
	aliasKey := vendorAliasKey(alias)
	if aliasKey == "" || strings.TrimSpace(fromURN) == "" {
		return
	}
	aliasURN := projectionURN(tenantID, "vendor_alias", aliasKey)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        aliasURN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: "vendor.alias",
		Label:      alias,
		Attributes: map[string]string{
			"alias":     alias,
			"alias_key": aliasKey,
		},
	})
	addLink(links, projectedLink(tenantID, sourceID, fromURN, aliasURN, relationHasIdentifier, map[string]string{
		"alias":      alias,
		"alias_key":  aliasKey,
		"confidence": confidence,
		"event_id":   event.GetId(),
		"match_type": matchType,
	}))
}

func vendorAliasKey(value string) string {
	var builder strings.Builder
	lastSeparator := false
	for _, r := range strings.ToLower(strings.TrimSpace(value)) {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			builder.WriteRune(r)
			lastSeparator = false
		case !lastSeparator && builder.Len() != 0:
			builder.WriteByte('-')
			lastSeparator = true
		}
	}
	return strings.Trim(builder.String(), "-")
}

func containsAnyNormalizedToken(value string, markers ...string) bool {
	markerSet := map[string]struct{}{}
	for _, marker := range markers {
		normalized := strings.ToLower(strings.TrimSpace(marker))
		if normalized != "" {
			markerSet[normalized] = struct{}{}
		}
	}
	if len(markerSet) == 0 {
		return false
	}
	for _, token := range normalizedTokens(value) {
		if _, ok := markerSet[token]; ok {
			return true
		}
	}
	return false
}

func normalizedTokens(value string) []string {
	var tokens []string
	var builder strings.Builder
	flush := func() {
		if builder.Len() == 0 {
			return
		}
		tokens = append(tokens, builder.String())
		builder.Reset()
	}
	for _, r := range strings.ToLower(strings.TrimSpace(value)) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			builder.WriteRune(r)
			continue
		}
		flush()
	}
	flush()
	return tokens
}
