package boot

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
)

type ConcurrentInitTask struct {
	Name string
	Run  func(context.Context)
}

type Dependencies struct {
	Logger                   func() *slog.Logger
	Config                   func() *InitConfig
	InitTelemetry            func(context.Context) error
	InitWarehouse            func(context.Context) error
	SnowflakeInitialized     func() bool
	InitPolicy               func() error
	InitExecutionStore       func()
	AppStateSubsystem        func() InitStartSubsystem
	GraphSubsystem           func() InitStartSubsystem
	InitLegacySnowflake      func(context.Context) error
	Phase2aInitSubsystems    func() []LifecycleSubsystem
	Phase2bInitSubsystems    func() []LifecycleSubsystem
	Phase2bStartSubsystems   func() []LifecycleSubsystem
	InitScanner              func()
	ValidateRequiredServices func() error
	ValidatePolicyCoverage   func(context.Context) error
}

type Runtime struct {
	deps Dependencies
}

func NewRuntime(deps Dependencies) *Runtime {
	return &Runtime{deps: deps}
}

func (r *Runtime) logger() *slog.Logger {
	if r == nil || r.deps.Logger == nil {
		return slog.Default()
	}
	if logger := r.deps.Logger(); logger != nil {
		return logger
	}
	return slog.Default()
}

func (r *Runtime) config() *InitConfig {
	if r == nil || r.deps.Config == nil {
		return nil
	}
	return r.deps.Config()
}

func (r *Runtime) initTelemetry(ctx context.Context) error {
	if r == nil || r.deps.InitTelemetry == nil {
		return nil
	}
	return r.deps.InitTelemetry(ctx)
}

func (r *Runtime) initWarehouse(ctx context.Context) error {
	if r == nil || r.deps.InitWarehouse == nil {
		return nil
	}
	return r.deps.InitWarehouse(ctx)
}

func (r *Runtime) snowflakeInitialized() bool {
	if r == nil || r.deps.SnowflakeInitialized == nil {
		return false
	}
	return r.deps.SnowflakeInitialized()
}

func (r *Runtime) initPolicy() error {
	if r == nil || r.deps.InitPolicy == nil {
		return nil
	}
	return r.deps.InitPolicy()
}

func (r *Runtime) initExecutionStore() {
	if r == nil || r.deps.InitExecutionStore == nil {
		return
	}
	r.deps.InitExecutionStore()
}

func (r *Runtime) appStateSubsystem() InitStartSubsystem {
	if r == nil || r.deps.AppStateSubsystem == nil {
		return nil
	}
	return r.deps.AppStateSubsystem()
}

func (r *Runtime) graphSubsystem() InitStartSubsystem {
	if r == nil || r.deps.GraphSubsystem == nil {
		return nil
	}
	return r.deps.GraphSubsystem()
}

func (r *Runtime) initLegacySnowflake(ctx context.Context) error {
	if r == nil || r.deps.InitLegacySnowflake == nil {
		return nil
	}
	return r.deps.InitLegacySnowflake(ctx)
}

func (r *Runtime) phase2aInitSubsystems() []LifecycleSubsystem {
	if r == nil || r.deps.Phase2aInitSubsystems == nil {
		return nil
	}
	subsystems := r.deps.Phase2aInitSubsystems()
	if len(subsystems) == 0 {
		return nil
	}
	return append([]LifecycleSubsystem(nil), subsystems...)
}

func (r *Runtime) phase2bInitSubsystems() []LifecycleSubsystem {
	if r == nil || r.deps.Phase2bInitSubsystems == nil {
		return nil
	}
	subsystems := r.deps.Phase2bInitSubsystems()
	if len(subsystems) == 0 {
		return nil
	}
	return append([]LifecycleSubsystem(nil), subsystems...)
}

func (r *Runtime) phase2bStartSubsystems() []LifecycleSubsystem {
	if r == nil || r.deps.Phase2bStartSubsystems == nil {
		return nil
	}
	subsystems := r.deps.Phase2bStartSubsystems()
	if len(subsystems) == 0 {
		return nil
	}
	return append([]LifecycleSubsystem(nil), subsystems...)
}

func (r *Runtime) initScanner() {
	if r == nil || r.deps.InitScanner == nil {
		return
	}
	r.deps.InitScanner()
}

func (r *Runtime) validateRequiredServices() error {
	if r == nil || r.deps.ValidateRequiredServices == nil {
		return nil
	}
	return r.deps.ValidateRequiredServices()
}

func (r *Runtime) validatePolicyCoverage(ctx context.Context) error {
	if r == nil || r.deps.ValidatePolicyCoverage == nil {
		return nil
	}
	return r.deps.ValidatePolicyCoverage(ctx)
}

func (r *Runtime) Initialize(ctx context.Context) error {
	logger := r.logger()
	if err := RunInitErrorStep("telemetry", func() error { return r.initTelemetry(ctx) }); err != nil {
		logger.Warn("telemetry initialization failed", "error", err)
	}

	if err := r.InitPhase1(ctx); err != nil {
		return err
	}
	if err := r.InitPhase2a(ctx); err != nil {
		return err
	}
	if err := r.InitPhase2b(ctx); err != nil {
		return err
	}

	r.InitPhase3()
	if err := r.validateRequiredServices(); err != nil {
		return err
	}

	if err := r.InitPhase4(ctx); err != nil {
		logger.Warn("policy coverage validation failed", "error", err)
		if os.Getenv("CI") != "" {
			return err
		}
	}

	return nil
}

func (r *Runtime) InitPhase1(ctx context.Context) error {
	cfg := r.config()
	warehouseBackend := ""
	if cfg != nil {
		warehouseBackend = strings.ToLower(strings.TrimSpace(cfg.WarehouseBackend))
	}

	if err := RunInitErrorStep("warehouse", func() error { return r.initWarehouse(ctx) }); err != nil {
		if warehouseBackend == "snowflake" {
			return fmt.Errorf("warehouse initialization failed for backend %s: %w", warehouseBackend, err)
		}
		r.logger().Warn("warehouse initialization failed", "error", err, "backend", warehouseBackend)
	}
	if warehouseBackend == "snowflake" && !r.snowflakeInitialized() {
		return fmt.Errorf("warehouse initialization failed for backend %s: snowflake client was not initialized", warehouseBackend)
	}
	if err := RunInitErrorStep("policy", r.initPolicy); err != nil {
		return err
	}
	return nil
}

func (r *Runtime) InitPhase2a(ctx context.Context) error {
	appState := r.appStateSubsystem()
	graphSubsystem := r.graphSubsystem()

	r.initExecutionStore()
	if appState != nil {
		if err := appState.Init(ctx); err != nil {
			return err
		}
	}
	if err := RunInitErrorStep("legacy_snowflake", func() error { return r.initLegacySnowflake(ctx) }); err != nil {
		r.logger().Warn("legacy snowflake initialization failed", "error", err)
	}
	if graphSubsystem != nil {
		if err := graphSubsystem.Init(ctx); err != nil {
			return err
		}
	}
	if appState != nil {
		if err := appState.Start(ctx); err != nil {
			return err
		}
	}
	if _, err := ExecuteLifecycleStages(ctx, r.logger(), LifecycleStage{
		Phase:        "phase2a.init",
		Action:       LifecycleActionInit,
		PreSatisfied: []string{"appstate", "graph"},
		Subsystems:   r.phase2aInitSubsystems(),
	}); err != nil {
		return fmt.Errorf("phase 2a init failed: %w", err)
	}
	return nil
}

func (r *Runtime) InitPhase2b(ctx context.Context) error {
	if _, err := ExecuteLifecycleStages(ctx, r.logger(),
		LifecycleStage{
			Phase:        "phase2b.init",
			Action:       LifecycleActionInit,
			PreSatisfied: []string{"findings", "notifications", "runtime", "ticketing", "webhooks"},
			Subsystems:   r.phase2bInitSubsystems(),
		},
		LifecycleStage{
			Phase:        "phase2b.start",
			Action:       LifecycleActionStart,
			PreSatisfied: []string{"graph", "webhooks"},
			Subsystems:   r.phase2bStartSubsystems(),
		},
	); err != nil {
		return fmt.Errorf("phase 2b lifecycle failed: %w", err)
	}
	return nil
}

func (r *Runtime) InitPhase3() {
	r.initScanner()
}

func (r *Runtime) InitPhase4(ctx context.Context) error {
	graphSubsystem := r.graphSubsystem()
	if graphSubsystem != nil {
		if err := RunSubsystemStartSequentially(ctx, graphSubsystem); err != nil {
			return err
		}
	}
	return r.validatePolicyCoverage(ctx)
}

func RunInitTasksConcurrently(ctx context.Context, tasks []ConcurrentInitTask) error {
	subsystems := make([]InitSubsystem, 0, len(tasks))
	for _, task := range tasks {
		task := task
		subsystems = append(subsystems, LifecycleSubsystem{
			SubsystemName: task.Name,
			InitFunc: func(runCtx context.Context) error {
				if task.Run != nil {
					task.Run(runCtx)
				}
				return nil
			},
		})
	}
	return RunSubsystemInitConcurrently(ctx, subsystems...)
}
