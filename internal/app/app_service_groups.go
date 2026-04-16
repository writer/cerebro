package app

import (
	"github.com/writer/cerebro/internal/agents"
	"github.com/writer/cerebro/internal/attackpath"
	"github.com/writer/cerebro/internal/auth"
	"github.com/writer/cerebro/internal/cache"
	"github.com/writer/cerebro/internal/compliance"
	"github.com/writer/cerebro/internal/dspm"
	"github.com/writer/cerebro/internal/events"
	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/graph/builders"
	"github.com/writer/cerebro/internal/health"
	"github.com/writer/cerebro/internal/identity"
	"github.com/writer/cerebro/internal/lineage"
	"github.com/writer/cerebro/internal/notifications"
	"github.com/writer/cerebro/internal/policy"
	"github.com/writer/cerebro/internal/providers"
	"github.com/writer/cerebro/internal/remediation"
	"github.com/writer/cerebro/internal/runtime"
	"github.com/writer/cerebro/internal/scanner"
	"github.com/writer/cerebro/internal/scheduler"
	"github.com/writer/cerebro/internal/snowflake"
	"github.com/writer/cerebro/internal/threatintel"
	"github.com/writer/cerebro/internal/ticketing"
	"github.com/writer/cerebro/internal/warehouse"
	"github.com/writer/cerebro/internal/webhooks"
)

// CoreServices groups policy evaluation and scanning primitives.
type CoreServices struct {
	Snowflake     *snowflake.Client
	Warehouse     warehouse.DataWarehouse
	Policy        *policy.Engine
	Findings      findings.FindingStore
	Scanner       *scanner.Scanner
	DSPM          *dspm.Scanner
	Cache         *cache.PolicyCache
	ScanWatermark *scanner.WatermarkStore
}

// FeatureServices groups optional product integrations and orchestrators.
type FeatureServices struct {
	Agents        *agents.AgentRegistry
	Ticketing     *ticketing.Service
	Identity      *identity.Service
	AttackPath    *attackpath.Graph
	Providers     *providers.Registry
	Webhooks      *webhooks.Service
	TapConsumer   *events.Consumer
	RemoteTools   *agents.RemoteToolProvider
	ToolPublisher *agents.ToolPublisher
	Notifications *notifications.Manager
	Scheduler     *scheduler.Scheduler
}

// SecurityServices groups access control, runtime, remediation, and graph intelligence.
type SecurityServices struct {
	RBAC                *auth.RBAC
	ThreatIntel         *threatintel.ThreatIntelService
	Compliance          *compliance.ComplianceReport
	Health              *health.Registry
	Lineage             *lineage.LineageMapper
	Remediation         *remediation.Engine
	RemediationExecutor *remediation.Executor
	RuntimeDetect       *runtime.DetectionEngine
	RuntimeIngest       runtime.IngestStore
	RuntimeRespond      *runtime.ResponseEngine
	SecurityGraph       *graph.Graph
	GraphBuilder        *builders.Builder
	Propagation         *graph.PropagationEngine
}

// StorageServices groups data repositories and durable stores.
type StorageServices struct {
	Findings            findings.FindingStore
	AuditRepo           auditRepository
	PolicyHistoryRepo   policyHistoryRepository
	RiskEngineStateRepo riskEngineStateRepository
	RetentionRepo       retentionCleaner
}

func (a *App) CoreServices() CoreServices {
	return CoreServices{
		Snowflake:     a.Snowflake,
		Warehouse:     a.Warehouse,
		Policy:        a.Policy,
		Findings:      a.Findings,
		Scanner:       a.Scanner,
		DSPM:          a.DSPM,
		Cache:         a.Cache,
		ScanWatermark: a.ScanWatermarks,
	}
}

func (a *App) FeatureServices() FeatureServices {
	return FeatureServices{
		Agents:        a.Agents,
		Ticketing:     a.Ticketing,
		Identity:      a.Identity,
		AttackPath:    a.AttackPath,
		Providers:     a.Providers,
		Webhooks:      a.Webhooks,
		TapConsumer:   a.currentTapConsumer(),
		RemoteTools:   a.RemoteTools,
		ToolPublisher: a.ToolPublisher,
		Notifications: a.Notifications,
		Scheduler:     a.Scheduler,
	}
}

func (a *App) SecurityServices() SecurityServices {
	return SecurityServices{
		RBAC:                a.RBAC,
		ThreatIntel:         a.ThreatIntel,
		Compliance:          a.Compliance,
		Health:              a.Health,
		Lineage:             a.Lineage,
		Remediation:         a.Remediation,
		RemediationExecutor: a.RemediationExecutor,
		RuntimeDetect:       a.RuntimeDetect,
		RuntimeIngest:       a.RuntimeIngest,
		RuntimeRespond:      a.RuntimeRespond,
		SecurityGraph:       a.CurrentSecurityGraph(),
		GraphBuilder:        a.SecurityGraphBuilder,
		Propagation:         a.Propagation,
	}
}

func (a *App) StorageServices() StorageServices {
	return StorageServices{
		Findings:            a.Findings,
		AuditRepo:           a.AuditRepo,
		PolicyHistoryRepo:   a.PolicyHistoryRepo,
		RiskEngineStateRepo: a.RiskEngineStateRepo,
		RetentionRepo:       a.RetentionRepo,
	}
}
