package app

import (
	"context"
	"log/slog"
	"strings"

	appboot "github.com/writer/cerebro/internal/app/boot"
)

type SubsystemConfig = appboot.SubsystemConfig

type AgentConfig = appboot.AgentConfig

type RuntimeConfig = appboot.RuntimeConfig

type GraphConfig = appboot.GraphConfig

type AppStateConfig = appboot.AppStateConfig

type EventConfig = appboot.EventConfig

type lifecycleAction = appboot.LifecycleAction

const (
	lifecycleActionInit  = appboot.LifecycleActionInit
	lifecycleActionStart = appboot.LifecycleActionStart
)

type lifecycleExecutionReport = appboot.LifecycleExecutionReport

type namedSubsystem interface {
	Name() string
}

type initSubsystem interface {
	namedSubsystem
	Init(context.Context) error
}

type startSubsystem interface {
	namedSubsystem
	Start(context.Context) error
}

type closeSubsystem interface {
	namedSubsystem
	Close(context.Context) error
}

type concurrentInitTask struct {
	name string
	run  func(context.Context)
}

type lifecycleSubsystem struct {
	name     string
	requires []string
	init     func(context.Context) error
	start    func(context.Context) error
	close    func(context.Context) error
}

type lifecycleStage struct {
	phase        string
	action       lifecycleAction
	subsystems   []lifecycleSubsystem
	preSatisfied []string
}

func (s lifecycleSubsystem) Name() string {
	name := strings.TrimSpace(s.name)
	if name == "" {
		return "subsystem"
	}
	return name
}

func (s lifecycleSubsystem) Requires() []string {
	if len(s.requires) == 0 {
		return nil
	}
	return append([]string(nil), s.requires...)
}

func (s lifecycleSubsystem) Init(ctx context.Context) error {
	if s.init == nil {
		return nil
	}
	return s.init(ctx)
}

func (s lifecycleSubsystem) Start(ctx context.Context) error {
	if s.start == nil {
		return nil
	}
	return s.start(ctx)
}

func (s lifecycleSubsystem) Close(ctx context.Context) error {
	if s.close == nil {
		return nil
	}
	return s.close(ctx)
}

func (c *Config) BuildSubsystemConfig() SubsystemConfig {
	if c == nil {
		return SubsystemConfig{}
	}

	return SubsystemConfig{
		Agents: AgentConfig{
			AnthropicAPIKey: c.AnthropicAPIKey,
			OpenAIAPIKey:    c.OpenAIAPIKey,
			GitHubToken:     c.GitHubToken,
			GitLabToken:     c.GitLabToken,
			GitLabBaseURL:   c.GitLabBaseURL,
			RemoteTools:     remoteToolProviderConfigFromConfig(c),
			ToolPublisher:   toolPublisherConfigFromConfig(c),
		},
		Runtime: RuntimeConfig{
			ExecutionStoreFile: c.ExecutionStoreFile,
		},
		Graph: GraphConfig{
			SnapshotPath:                 c.GraphSnapshotPath,
			SnapshotMaxRetained:          c.GraphSnapshotMaxRetained,
			StoreBackend:                 c.graphStoreBackend(),
			SearchBackend:                c.graphSearchBackend(),
			SchemaValidationMode:         c.GraphSchemaValidationMode,
			PropertyHistoryMaxEntries:    c.GraphPropertyHistoryMaxEntries,
			PropertyHistoryTTL:           c.GraphPropertyHistoryTTL,
			WriterLeaseEnabled:           c.GraphWriterLeaseEnabled,
			WriterLeaseName:              c.GraphWriterLeaseName,
			WriterLeaseOwnerID:           c.GraphWriterLeaseOwnerID,
			WriterLeaseTTL:               c.GraphWriterLeaseTTL,
			WriterLeaseHeartbeat:         c.GraphWriterLeaseHeartbeat,
			MigrateLegacyActivityOnStart: c.GraphMigrateLegacyActivityOnStart,
		},
		AppState: AppStateConfig{
			WarehouseBackend:     c.WarehouseBackend,
			WarehousePostgresDSN: c.WarehousePostgresDSN,
		},
		Events: EventConfig{
			NATSJetStreamEnabled:     c.NATSJetStreamEnabled,
			NATSConsumerEnabled:      c.NATSConsumerEnabled,
			NATSConsumerSubjects:     append([]string(nil), c.NATSConsumerSubjects...),
			NATSConsumerDurable:      c.NATSConsumerDurable,
			NATSConsumerDrainTimeout: c.NATSConsumerDrainTimeout,
			AlertRouterEnabled:       c.AlertRouterEnabled,
			AlertRouterConfigPath:    c.AlertRouterConfigPath,
			AlertRouterNotifyPrefix:  c.AlertRouterNotifyPrefix,
		},
	}
}

func (a *App) subsystemConfig() SubsystemConfig {
	if a == nil || a.Config == nil {
		return SubsystemConfig{}
	}
	return a.Config.BuildSubsystemConfig()
}

func (a *App) initialize(ctx context.Context) error {
	if runtime := a.bootRuntime(); runtime != nil {
		return runtime.Initialize(ctx)
	}
	return nil
}

func (a *App) initPhase1(ctx context.Context) error {
	if runtime := a.bootRuntime(); runtime != nil {
		return runtime.InitPhase1(ctx)
	}
	return nil
}

func (a *App) initPhase2b(ctx context.Context) error {
	if runtime := a.bootRuntime(); runtime != nil {
		return runtime.InitPhase2b(ctx)
	}
	return nil
}

func (a *App) initPhase3() {
	if runtime := a.bootRuntime(); runtime != nil {
		runtime.InitPhase3()
	}
}

func runInitTasksConcurrently(ctx context.Context, tasks []concurrentInitTask) error {
	bootTasks := make([]appboot.ConcurrentInitTask, 0, len(tasks))
	for _, task := range tasks {
		bootTasks = append(bootTasks, appboot.ConcurrentInitTask{Name: task.name, Run: task.run})
	}
	return appboot.RunInitTasksConcurrently(ctx, bootTasks)
}

func runInitStep(name string, fn func()) error {
	return appboot.RunInitStep(name, fn)
}

func runInitErrorStep(name string, fn func() error) error {
	return appboot.RunInitErrorStep(name, fn)
}

func (a *App) validateRequiredServices() error {
	if a == nil {
		return appboot.ValidateRequiredServices(nil)
	}
	return appboot.ValidateRequiredServices(map[string]bool{
		"policy_engine":   a.Policy != nil,
		"findings_store":  a.Findings != nil,
		"scanner":         a.Scanner != nil,
		"cache":           a.Cache != nil,
		"agent_registry":  a.Agents != nil,
		"ticketing":       a.Ticketing != nil,
		"identity":        a.Identity != nil,
		"attackpath":      a.AttackPath != nil,
		"providers":       a.Providers != nil,
		"webhooks":        a.Webhooks != nil,
		"notifications":   a.Notifications != nil,
		"scheduler":       a.Scheduler != nil,
		"rbac":            a.RBAC != nil,
		"threatintel":     a.ThreatIntel != nil,
		"health":          a.Health != nil,
		"lineage":         a.Lineage != nil,
		"remediation":     a.Remediation != nil,
		"runtime_detect":  a.RuntimeDetect != nil,
		"runtime_respond": a.RuntimeRespond != nil,
	})
}

func buildSubsystemWaves(subsystems []lifecycleSubsystem, preSatisfied ...string) ([][]lifecycleSubsystem, error) {
	waves, err := appboot.BuildSubsystemWaves(toBootLifecycleSubsystems(subsystems), preSatisfied...)
	if err != nil {
		return nil, err
	}
	return fromBootLifecycleSubsystemWaves(waves), nil
}

func executeLifecycleStages(ctx context.Context, logger *slog.Logger, stages ...lifecycleStage) (lifecycleExecutionReport, error) {
	bootStages := make([]appboot.LifecycleStage, 0, len(stages))
	for _, stage := range stages {
		bootStages = append(bootStages, toBootLifecycleStage(stage))
	}
	return appboot.ExecuteLifecycleStages(ctx, logger, bootStages...)
}

func runSubsystemInitConcurrently(ctx context.Context, subsystems ...initSubsystem) error {
	bootSubsystems := make([]appboot.InitSubsystem, 0, len(subsystems))
	for _, subsystem := range subsystems {
		if subsystem == nil {
			continue
		}
		bootSubsystems = append(bootSubsystems, subsystem)
	}
	return appboot.RunSubsystemInitConcurrently(ctx, bootSubsystems...)
}

func runSubsystemInitSequentially(ctx context.Context, subsystems ...initSubsystem) error {
	for _, subsystem := range subsystems {
		if subsystem == nil {
			continue
		}
		if err := appboot.RunInitErrorStep(subsystem.Name(), func() error {
			return subsystem.Init(ctx)
		}); err != nil {
			return err
		}
	}
	return nil
}

func runSubsystemStartSequentially(ctx context.Context, subsystems ...startSubsystem) error {
	bootSubsystems := make([]appboot.StartSubsystem, 0, len(subsystems))
	for _, subsystem := range subsystems {
		if subsystem == nil {
			continue
		}
		bootSubsystems = append(bootSubsystems, subsystem)
	}
	return appboot.RunSubsystemStartSequentially(ctx, bootSubsystems...)
}

func runSubsystemCloseSequentially(ctx context.Context, subsystems ...closeSubsystem) []error {
	bootSubsystems := make([]appboot.CloseSubsystem, 0, len(subsystems))
	for _, subsystem := range subsystems {
		if subsystem == nil {
			continue
		}
		bootSubsystems = append(bootSubsystems, subsystem)
	}
	return appboot.RunSubsystemCloseSequentially(ctx, bootSubsystems...)
}

func initOnlySubsystem(name string, init func(context.Context)) lifecycleSubsystem {
	return lifecycleSubsystem{
		name: name,
		init: func(ctx context.Context) error {
			if init != nil {
				init(ctx)
			}
			return nil
		},
	}
}

func initOnlySubsystemWithDeps(name string, requires []string, init func(context.Context)) lifecycleSubsystem {
	subsystem := initOnlySubsystem(name, init)
	subsystem.requires = normalizeLifecycleDependencies(requires)
	return subsystem
}

func wrapInitSubsystem(subsystem initSubsystem, requires ...string) lifecycleSubsystem {
	if subsystem == nil {
		return lifecycleSubsystem{}
	}
	return lifecycleSubsystem{
		name:     subsystem.Name(),
		requires: normalizeLifecycleDependencies(requires),
		init:     subsystem.Init,
	}
}

func wrapStartSubsystem(subsystem startSubsystem, requires ...string) lifecycleSubsystem {
	if subsystem == nil {
		return lifecycleSubsystem{}
	}
	return lifecycleSubsystem{
		name:     subsystem.Name(),
		requires: normalizeLifecycleDependencies(requires),
		start:    subsystem.Start,
	}
}

func subsystemWaveNames(waves [][]lifecycleSubsystem) [][]string {
	if len(waves) == 0 {
		return nil
	}
	result := make([][]string, 0, len(waves))
	for _, wave := range waves {
		names := make([]string, 0, len(wave))
		for _, subsystem := range wave {
			names = append(names, subsystem.Name())
		}
		result = append(result, names)
	}
	return result
}

func normalizeLifecycleDependencies(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}
	return normalized
}

func toBootLifecycleSubsystems(subsystems []lifecycleSubsystem) []appboot.LifecycleSubsystem {
	if len(subsystems) == 0 {
		return nil
	}
	result := make([]appboot.LifecycleSubsystem, 0, len(subsystems))
	for _, subsystem := range subsystems {
		result = append(result, toBootLifecycleSubsystem(subsystem))
	}
	return result
}

func toBootLifecycleSubsystem(subsystem lifecycleSubsystem) appboot.LifecycleSubsystem {
	return appboot.LifecycleSubsystem{
		SubsystemName: subsystem.name,
		Dependencies:  append([]string(nil), subsystem.requires...),
		InitFunc:      subsystem.init,
		StartFunc:     subsystem.start,
		CloseFunc:     subsystem.close,
	}
}

func fromBootLifecycleSubsystemWaves(waves [][]appboot.LifecycleSubsystem) [][]lifecycleSubsystem {
	if len(waves) == 0 {
		return nil
	}
	result := make([][]lifecycleSubsystem, 0, len(waves))
	for _, wave := range waves {
		converted := make([]lifecycleSubsystem, 0, len(wave))
		for _, subsystem := range wave {
			converted = append(converted, fromBootLifecycleSubsystem(subsystem))
		}
		result = append(result, converted)
	}
	return result
}

func fromBootLifecycleSubsystem(subsystem appboot.LifecycleSubsystem) lifecycleSubsystem {
	return lifecycleSubsystem{
		name:     subsystem.SubsystemName,
		requires: append([]string(nil), subsystem.Dependencies...),
		init:     subsystem.InitFunc,
		start:    subsystem.StartFunc,
		close:    subsystem.CloseFunc,
	}
}

func toBootLifecycleStage(stage lifecycleStage) appboot.LifecycleStage {
	return appboot.LifecycleStage{
		Phase:        stage.phase,
		Action:       stage.action,
		Subsystems:   toBootLifecycleSubsystems(stage.subsystems),
		PreSatisfied: append([]string(nil), stage.preSatisfied...),
	}
}
