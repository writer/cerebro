package app

import (
	"context"
	"log/slog"

	appboot "github.com/writer/cerebro/internal/app/boot"
)

func (a *App) bootRuntime() *appboot.Runtime {
	if a == nil {
		return nil
	}
	if a.Boot == nil {
		a.Boot = a.newBootRuntime()
	}
	return a.Boot
}

func (a *App) newBootRuntime() *appboot.Runtime {
	if a == nil {
		return nil
	}
	return appboot.NewRuntime(appboot.Dependencies{
		Logger: func() *slog.Logger {
			if a == nil {
				return nil
			}
			return a.Logger
		},
		Config: func() *appboot.InitConfig {
			return a.bootInitConfig()
		},
		InitTelemetry: func(ctx context.Context) error {
			if a == nil {
				return nil
			}
			return a.initTelemetry(ctx)
		},
		InitWarehouse: func(ctx context.Context) error {
			if a == nil {
				return nil
			}
			return a.initWarehouse(ctx)
		},
		SnowflakeInitialized: func() bool {
			return a != nil && a.Snowflake != nil
		},
		InitPolicy: func() error {
			if a == nil {
				return nil
			}
			return a.initPolicy()
		},
		InitExecutionStore: func() {
			if a != nil {
				a.initExecutionStore()
			}
		},
		AppStateSubsystem: func() appboot.InitStartSubsystem {
			if a == nil {
				return nil
			}
			return a.appStateSubsystem()
		},
		GraphSubsystem: func() appboot.InitStartSubsystem {
			if a == nil {
				return nil
			}
			return a.graphSubsystem()
		},
		InitLegacySnowflake: func(ctx context.Context) error {
			if a == nil {
				return nil
			}
			return a.initLegacySnowflake(ctx)
		},
		RequiresLegacySnowflakeSource: func(ctx context.Context) (bool, error) {
			if a == nil {
				return false, nil
			}
			return a.requiresLegacySnowflakeSource(ctx)
		},
		LegacySnowflakeSourceInitialized: func() bool {
			return a != nil && a.appStateMigrationSnowflake() != nil
		},
		Phase2aInitSubsystems: func() []appboot.LifecycleSubsystem {
			if a == nil {
				return nil
			}
			return toBootLifecycleSubsystems(a.phase2aInitSubsystems())
		},
		Phase2bInitSubsystems: func() []appboot.LifecycleSubsystem {
			if a == nil {
				return nil
			}
			return toBootLifecycleSubsystems(a.phase2bInitSubsystems())
		},
		Phase2bStartSubsystems: func() []appboot.LifecycleSubsystem {
			if a == nil {
				return nil
			}
			return toBootLifecycleSubsystems(a.phase2bStartSubsystems())
		},
		InitScanner: func() {
			if a != nil {
				a.initScanner()
			}
		},
		ValidateRequiredServices: func() error {
			if a == nil {
				return nil
			}
			return a.validateRequiredServices()
		},
		ValidatePolicyCoverage: func(ctx context.Context) error {
			if a == nil {
				return nil
			}
			return a.validatePolicyCoverage(ctx)
		},
	})
}

func (a *App) bootInitConfig() *appboot.InitConfig {
	if a == nil || a.Config == nil {
		return nil
	}
	return &appboot.InitConfig{
		WarehouseBackend: a.Config.WarehouseBackend,
	}
}
