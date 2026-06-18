package findings

import (
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourceconfig"
)

func runtimeMayEmitEventKind(runtime *cerebrov1.SourceRuntime, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	kind := runtimeConfiguredEventKind(runtime)
	if kind == "" {
		return true
	}
	return identityKindAllowed(kind, allowed)
}

func runtimeConfiguredEventKind(runtime *cerebrov1.SourceRuntime) string {
	if runtime == nil {
		return ""
	}
	sourceID := strings.TrimSpace(runtime.GetSourceId())
	family := strings.TrimSpace(runtime.GetConfig()["family"])
	if sourceID == "" {
		return ""
	}
	if sourceconfig.IsSecretReference(family) {
		return ""
	}
	if family == "" {
		family = defaultRuntimeFamily(sourceID)
	}
	if family == "" {
		return ""
	}
	return sourceID + "." + family
}

func defaultRuntimeFamily(sourceID string) string {
	switch strings.ToLower(strings.TrimSpace(sourceID)) {
	case "aws":
		return "cloudtrail"
	case "azure":
		return "directory_audit"
	case "gcp":
		return "audit"
	case "github":
		return "pull_request"
	case "google_workspace":
		return "user"
	case "okta":
		return "audit"
	case "panopticon":
		return "case"
	case "sentinelone":
		return "threat"
	case "security_reviewer":
		return "finding"
	default:
		return ""
	}
}
