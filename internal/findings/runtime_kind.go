package findings

import (
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
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
	if sourceID == "" || family == "" {
		return ""
	}
	return sourceID + "." + family
}
