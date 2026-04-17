package app

import "context"

func (a *App) phase2aInitSubsystems() []lifecycleSubsystem {
	return []lifecycleSubsystem{
		initOnlySubsystem("cache", func(context.Context) { a.initCache() }),
		initOnlySubsystem("ticketing", func(taskCtx context.Context) { a.initTicketing(taskCtx) }),
		initOnlySubsystem("identity", func(context.Context) { a.initIdentity() }),
		initOnlySubsystem("attackpath", func(context.Context) { a.initAttackPath() }),
		initOnlySubsystem("webhooks", func(context.Context) { a.initWebhooks() }),
		initOnlySubsystem("notifications", func(context.Context) { a.initNotifications() }),
		initOnlySubsystem("rbac", func(context.Context) { a.initRBAC() }),
		initOnlySubsystem("compliance", func(context.Context) { a.initCompliance() }),
		initOnlySubsystem("health", func(context.Context) { a.initHealth() }),
		initOnlySubsystem("lineage", func(context.Context) { a.initLineage() }),
		wrapInitSubsystem(a.runtimeSubsystem()),
		initOnlySubsystem("findings", func(context.Context) { a.initFindings() }),
		initOnlySubsystem("providers", func(taskCtx context.Context) { a.initProviders(taskCtx) }),
		initOnlySubsystemWithDeps("snowflake_findings", []string{"findings"}, func(taskCtx context.Context) {
			a.initSnowflakeFindings(taskCtx)
		}),
		initOnlySubsystem("scan_watermarks", func(taskCtx context.Context) { a.initScanWatermarks(taskCtx) }),
		initOnlySubsystemWithDeps("threatintel", []string{"webhooks"}, func(taskCtx context.Context) {
			a.initThreatIntel(taskCtx)
		}),
		initOnlySubsystem("available_tables", func(taskCtx context.Context) { a.initAvailableTables(taskCtx) }),
		initOnlySubsystemWithDeps("scheduler", []string{"appstate", "available_tables", "findings", "health", "notifications", "scan_watermarks"}, func(taskCtx context.Context) {
			a.initScheduler(taskCtx)
		}),
	}
}

func (a *App) phase2bInitSubsystems() []lifecycleSubsystem {
	return []lifecycleSubsystem{
		wrapInitSubsystem(a.remediationSubsystem(), "findings", "notifications", "runtime", "ticketing", "webhooks"),
		wrapInitSubsystem(a.agentsSubsystem(), "remediation", "runtime"),
	}
}

func (a *App) phase2bStartSubsystems() []lifecycleSubsystem {
	return []lifecycleSubsystem{
		wrapStartSubsystem(a.remediationSubsystem()),
		wrapStartSubsystem(a.eventsSubsystem(), "remediation"),
	}
}
