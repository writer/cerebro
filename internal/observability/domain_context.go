package observability

import (
	"strings"

	"github.com/writer/cerebro/internal/telemetry"
)

// SourceRuntimeDiagnosticContext carries high-cardinality identifiers for
// trace and wide-event drill-down. Keep these out of metric dimensions.
type SourceRuntimeDiagnosticContext struct {
	RuntimeID string
	SourceID  string
	TenantID  string
}

// SourceProjectionDiagnosticContext carries high-cardinality projection
// identifiers for trace and wide-event drill-down.
type SourceProjectionDiagnosticContext struct {
	RuntimeID string
	SourceID  string
	TenantID  string
	EventKind string
}

func SourceRuntimeDiagnosticAttributes(ctx SourceRuntimeDiagnosticContext) telemetry.Attributes {
	return telemetry.Attrs(
		diagnosticField("runtime_id", ctx.RuntimeID),
		diagnosticField("source_id", ctx.SourceID),
		diagnosticField("tenant_id", ctx.TenantID),
		diagnosticField("source_runtime.id", ctx.RuntimeID),
		diagnosticField("source_runtime.source_id", ctx.SourceID),
		diagnosticField("source_runtime.tenant_id", ctx.TenantID),
	)
}

func SourceProjectionDiagnosticAttributes(ctx SourceProjectionDiagnosticContext) telemetry.Attributes {
	return telemetry.Attrs(
		diagnosticField("runtime_id", ctx.RuntimeID),
		diagnosticField("source_id", ctx.SourceID),
		diagnosticField("tenant_id", ctx.TenantID),
		diagnosticField("event_kind", ctx.EventKind),
		diagnosticField("source_projection.runtime_id", ctx.RuntimeID),
		diagnosticField("source_projection.source_id", ctx.SourceID),
		diagnosticField("source_projection.tenant_id", ctx.TenantID),
		diagnosticField("source_projection.event_kind", ctx.EventKind),
	)
}

func diagnosticField(key string, value string) telemetry.Field {
	return telemetry.Field{Key: key, Value: strings.TrimSpace(value)}
}
