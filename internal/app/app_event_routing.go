package app

import (
	"context"
	"strings"

	"github.com/evalops/cerebro/internal/events"
	"github.com/evalops/cerebro/internal/graph"
	"github.com/evalops/cerebro/internal/webhooks"
)

func (a *App) startEventAlertRouting(_ context.Context) {
	if a == nil || a.Config == nil || a.Webhooks == nil {
		return
	}
	if !a.Config.AlertRouterEnabled {
		return
	}
	if !a.Config.NATSJetStreamEnabled {
		return
	}

	routingConfig, err := events.LoadAlertRoutingConfig(a.Config.AlertRouterConfigPath)
	if err != nil {
		a.Logger.Warn("failed to load alert routing config", "error", err, "path", a.Config.AlertRouterConfigPath)
		return
	}

	notifier, err := events.NewNATSAlertNotifier(events.AlertNotifierConfig{
		URLs:                  a.Config.NATSJetStreamURLs,
		ConnectTimeout:        a.Config.NATSJetStreamConnectTimeout,
		AuthMode:              a.Config.NATSJetStreamAuthMode,
		Username:              a.Config.NATSJetStreamUsername,
		Password:              a.Config.NATSJetStreamPassword,
		NKeySeed:              a.Config.NATSJetStreamNKeySeed,
		UserJWT:               a.Config.NATSJetStreamUserJWT,
		TLSEnabled:            a.Config.NATSJetStreamTLSEnabled,
		TLSCAFile:             a.Config.NATSJetStreamTLSCAFile,
		TLSCertFile:           a.Config.NATSJetStreamTLSCertFile,
		TLSKeyFile:            a.Config.NATSJetStreamTLSKeyFile,
		TLSServerName:         a.Config.NATSJetStreamTLSServerName,
		TLSInsecureSkipVerify: a.Config.NATSJetStreamTLSInsecure,
	}, a.Logger)
	if err != nil {
		a.Logger.Warn("failed to initialize alert notifier", "error", err)
		return
	}

	subjectPrefix := strings.TrimSpace(a.Config.AlertRouterNotifyPrefix)
	stateStore, err := events.NewSQLiteAlertRouterStateStore(a.Config.AlertRouterStateFile)
	if err != nil {
		a.Logger.Warn("failed to initialize alert router state store", "error", err, "path", a.Config.AlertRouterStateFile)
		stateStore = nil
	}
	router, err := events.NewAlertRouter(events.AlertRouterOptions{
		Config:        routingConfig,
		Resolver:      events.NewGraphAlertResolver(a.currentOrStoredEventRoutingGraph),
		Sender:        notifier,
		StateStore:    stateStore,
		SubjectPrefix: subjectPrefix,
		Logger:        a.Logger,
	})
	if err != nil {
		if stateStore != nil {
			_ = stateStore.Close()
		}
		_ = notifier.Close()
		a.Logger.Warn("failed to initialize alert router", "error", err)
		return
	}

	a.AlertRouter = router
	a.Webhooks.Subscribe(func(eventCtx context.Context, event webhooks.Event) error {
		if routeErr := router.Route(eventCtx, event); routeErr != nil {
			a.Logger.Warn("alert routing failed", "event_type", event.Type, "error", routeErr)
		}
		return nil
	})
	a.Logger.Info("event alert routing enabled",
		"routes", router.RouteCount(),
		"subject_prefix", subjectPrefix,
	)
}

func (a *App) currentOrStoredEventRoutingGraph() *graph.Graph {
	if a == nil {
		return nil
	}
	g, err := a.currentOrStoredPassiveSecurityGraphView()
	if err != nil {
		if a.Logger != nil {
			a.Logger.Warn("failed to resolve event routing graph", "error", err)
		}
		return nil
	}
	return g
}
