package app

import (
	"github.com/evalops/cerebro/internal/agents"
	"github.com/evalops/cerebro/internal/attackpath"
	"github.com/evalops/cerebro/internal/auth"
	"github.com/evalops/cerebro/internal/cache"
	"github.com/evalops/cerebro/internal/compliance"
	"github.com/evalops/cerebro/internal/dspm"
	"github.com/evalops/cerebro/internal/events"
	"github.com/evalops/cerebro/internal/findings"
	"github.com/evalops/cerebro/internal/graph"
	"github.com/evalops/cerebro/internal/health"
	"github.com/evalops/cerebro/internal/identity"
	"github.com/evalops/cerebro/internal/lineage"
	"github.com/evalops/cerebro/internal/notifications"
	"github.com/evalops/cerebro/internal/policy"
	"github.com/evalops/cerebro/internal/providers"
	"github.com/evalops/cerebro/internal/remediation"
	"github.com/evalops/cerebro/internal/runtime"
	"github.com/evalops/cerebro/internal/scanner"
	"github.com/evalops/cerebro/internal/scheduler"
	"github.com/evalops/cerebro/internal/snowflake"
	"github.com/evalops/cerebro/internal/threatintel"
	"github.com/evalops/cerebro/internal/ticketing"
	"github.com/evalops/cerebro/internal/warehouse"
	"github.com/evalops/cerebro/internal/webhooks"
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
	RuntimeRespond      *runtime.ResponseEngine
	SecurityGraph       *graph.Graph
	GraphBuilder        *graph.Builder
	Propagation         *graph.PropagationEngine
}

// StorageServices groups data repositories and durable stores.
type StorageServices struct {
	FindingsRepo        *snowflake.FindingRepository
	TicketsRepo         *snowflake.TicketRepository
	AuditRepo           *snowflake.AuditRepository
	PolicyHistoryRepo   *snowflake.PolicyHistoryRepository
	RiskEngineStateRepo *snowflake.RiskEngineStateRepository
	RetentionRepo       retentionCleaner
	SnowflakeFindings   *findings.SnowflakeStore
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
		TapConsumer:   a.TapConsumer,
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
		RuntimeRespond:      a.RuntimeRespond,
		SecurityGraph:       a.SecurityGraph,
		GraphBuilder:        a.SecurityGraphBuilder,
		Propagation:         a.Propagation,
	}
}

func (a *App) StorageServices() StorageServices {
	return StorageServices{
		FindingsRepo:        a.FindingsRepo,
		TicketsRepo:         a.TicketsRepo,
		AuditRepo:           a.AuditRepo,
		PolicyHistoryRepo:   a.PolicyHistoryRepo,
		RiskEngineStateRepo: a.RiskEngineStateRepo,
		RetentionRepo:       a.RetentionRepo,
		SnowflakeFindings:   a.SnowflakeFindings,
	}
}
