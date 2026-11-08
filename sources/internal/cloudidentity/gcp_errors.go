package cloudidentitysource

import (
	"regexp"
	"strings"

	ci "github.com/writer/cerebro/internal/cloudidentity"
)

// gcpGapsToCore converts internal transport/decode gaps into core Gaps scoped
// to the resource or identifier that produced them.
func gcpGapsToCore(scope string, raws []gcpGap) []ci.Gap {
	gaps := make([]ci.Gap, 0, len(raws))
	for _, raw := range raws {
		gaps = append(gaps, ci.Gap{Code: raw.Code, Scope: scope, Message: raw.Message})
	}
	return gaps
}

// gcpProjectIDPattern matches a syntactically valid GCP project id:
// https://cloud.google.com/resource-manager/docs/creating-managing-projects#before_you_begin
var gcpProjectIDPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)

// gcpPlaceholderProjectTokens are literal values that sometimes leak through
// from unresolved IaC/manifest templating. Treating them as unresolved
// instead of querying GCP with them avoids both wasted calls and, more
// importantly, ever silently assuming a default/fallback project scope.
var gcpPlaceholderProjectTokens = map[string]bool{
	"project_id": true, "project-id": true, "your-project-id": true,
	"example": true, "example-project": true, "changeme": true,
	"todo": true, "unknown": true, "placeholder": true,
}

// gcpResolvableProjectID reports whether value is a concrete GCP project id
// this reader may safely query live APIs with, rather than an unresolved
// placeholder or template remnant.
func gcpResolvableProjectID(value string) bool {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return false
	}
	if strings.ContainsAny(trimmed, "${}<>%") {
		return false
	}
	if gcpPlaceholderProjectTokens[strings.ToLower(trimmed)] {
		return false
	}
	return gcpProjectIDPattern.MatchString(trimmed)
}
