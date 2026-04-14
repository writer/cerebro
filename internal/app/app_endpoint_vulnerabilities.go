package app

import (
	"context"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/endpointvuln"
	"github.com/writer/cerebro/internal/providers"
)

const endpointVulnerabilityRefreshTimeout = 2 * time.Minute

func (a *App) refreshEndpointVulnerabilityTables(ctx context.Context, trigger string) error {
	if a == nil || a.Warehouse == nil {
		return nil
	}

	if ctx == nil {
		ctx = context.Background()
	}
	ctx = backgroundWorkContext(ctx)

	refreshCtx, cancel := context.WithTimeout(ctx, endpointVulnerabilityRefreshTimeout)
	defer cancel()

	trigger = strings.TrimSpace(trigger)
	if trigger == "" {
		trigger = "unspecified"
	}

	start := time.Now()
	a.endpointVulnRefreshMu.Lock()
	defer a.endpointVulnRefreshMu.Unlock()

	refresher := endpointvuln.Refresher{
		Warehouse:   a.Warehouse,
		ThreatIntel: a.ThreatIntel,
		Advisories:  a.VulnDB,
		Logger:      a.Logger,
	}
	if err := refresher.Refresh(refreshCtx); err != nil {
		return err
	}

	if tables, err := a.Warehouse.ListAvailableTables(refreshCtx); err == nil {
		a.AvailableTables = tables
	} else if refreshCtx.Err() == nil && a.Logger != nil {
		a.Logger.Warn("failed to refresh available tables after endpoint vulnerability refresh",
			"trigger", trigger,
			"error", err,
		)
	}

	if a.Logger != nil {
		a.Logger.Info("refreshed endpoint vulnerability correlation tables",
			"trigger", trigger,
			"duration", time.Since(start),
		)
	}

	return nil
}

func (a *App) endpointProviderSyncHook(ctx context.Context, provider providers.Provider, _ *providers.SyncResult, syncErr error) error {
	if syncErr != nil || provider == nil {
		return nil
	}
	return a.refreshEndpointVulnerabilityTables(ctx, "provider_sync:"+provider.Name())
}
