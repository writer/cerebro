package app

import "context"

type appStateLifecycle struct {
	app *App
	cfg AppStateConfig
}

func (a *App) appStateSubsystem() appStateLifecycle {
	return appStateLifecycle{
		app: a,
		cfg: a.subsystemConfig().AppState,
	}
}

func (s appStateLifecycle) Name() string {
	return "appstate"
}

func (s appStateLifecycle) Init(ctx context.Context) error {
	if s.app == nil || s.cfg.DatabaseURL() == "" {
		return nil
	}
	return runInitErrorStep("app_state_db", func() error {
		return s.app.initAppStateDB(ctx)
	})
}

func (s appStateLifecycle) Start(ctx context.Context) error {
	if s.app == nil {
		return nil
	}
	s.app.initRepositories()
	if s.cfg.DatabaseURL() == "" {
		return nil
	}
	return runInitErrorStep("app_state_migration", func() error {
		return s.app.migrateAppState(ctx)
	})
}

type agentsLifecycle struct {
	app *App
	cfg AgentConfig
}

func (a *App) agentsSubsystem() agentsLifecycle {
	return agentsLifecycle{
		app: a,
		cfg: a.subsystemConfig().Agents,
	}
}

func (s agentsLifecycle) Name() string {
	return "agents"
}

func (s agentsLifecycle) Init(ctx context.Context) error {
	if s.app == nil {
		return nil
	}
	s.app.initAgents(ctx)
	return nil
}

type runtimeLifecycle struct {
	app *App
	cfg RuntimeConfig
}

func (a *App) runtimeSubsystem() runtimeLifecycle {
	return runtimeLifecycle{
		app: a,
		cfg: a.subsystemConfig().Runtime,
	}
}

func (s runtimeLifecycle) Name() string {
	return "runtime"
}

func (s runtimeLifecycle) Init(context.Context) error {
	if s.app == nil {
		return nil
	}
	s.app.initRuntime()
	return nil
}

type remediationLifecycle struct {
	app *App
}

func (a *App) remediationSubsystem() remediationLifecycle {
	return remediationLifecycle{app: a}
}

func (s remediationLifecycle) Name() string {
	return "remediation"
}

func (s remediationLifecycle) Init(context.Context) error {
	if s.app == nil {
		return nil
	}
	s.app.initRemediation()
	return nil
}

func (s remediationLifecycle) Start(ctx context.Context) error {
	if s.app == nil {
		return nil
	}
	s.app.startEventRemediation(ctx)
	return nil
}

type graphLifecycle struct {
	app    *App
	cfg    GraphConfig
	events EventConfig
}

func (a *App) graphSubsystem() graphLifecycle {
	cfg := a.subsystemConfig()
	return graphLifecycle{
		app:    a,
		cfg:    cfg.Graph,
		events: cfg.Events,
	}
}

func (s graphLifecycle) Name() string {
	return "graph"
}

func (s graphLifecycle) Init(ctx context.Context) error {
	if s.app == nil {
		return nil
	}
	s.app.initGraphPersistenceStore()
	if err := runInitErrorStep("graph_store_backend", func() error {
		return s.app.initConfiguredSecurityGraphStore(ctx)
	}); err != nil {
		return err
	}
	if err := runInitErrorStep("graph_writer_lease", func() error {
		return s.app.initGraphWriterLease(ctx)
	}); err != nil {
		return err
	}
	if err := runInitErrorStep("entity_search_backend", func() error {
		return s.app.initEntitySearchBackend(ctx)
	}); err != nil {
		return err
	}
	return nil
}

func (s graphLifecycle) Start(ctx context.Context) error {
	if s.app == nil {
		return nil
	}
	s.app.initSecurityGraph(ctx)
	if s.events.TapGraphConsumerEnabled() {
		s.app.initTapGraphConsumer(ctx)
	}
	return nil
}

type eventLifecycle struct {
	app *App
	cfg EventConfig
}

func (a *App) eventsSubsystem() eventLifecycle {
	return eventLifecycle{
		app: a,
		cfg: a.subsystemConfig().Events,
	}
}

func (s eventLifecycle) Name() string {
	return "events"
}

func (s eventLifecycle) Start(ctx context.Context) error {
	if s.app == nil || !s.cfg.AlertRoutingEnabled() {
		return nil
	}
	s.app.startEventAlertRouting(ctx)
	return nil
}
