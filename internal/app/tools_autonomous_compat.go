package app

import (
	"context"
	"fmt"
	"strings"

	"github.com/writer/cerebro/internal/actionengine"
	"github.com/writer/cerebro/internal/autonomous"
	appRuntime "github.com/writer/cerebro/internal/runtime"
)

//nolint:unused // compatibility shim for package-level tests during tools extraction
func (a *App) autonomousRunStore() (autonomous.RunStore, error) {
	if a != nil && a.ExecutionStore != nil {
		return autonomous.NewSQLiteRunStoreWithExecutionStore(a.ExecutionStore), nil
	}
	if a == nil || a.Config == nil {
		return nil, fmt.Errorf("execution store is not configured")
	}
	store, err := autonomous.NewSQLiteRunStore(a.Config.ExecutionStoreFile)
	if err != nil {
		return nil, fmt.Errorf("open autonomous workflow store: %w", err)
	}
	return store, nil
}

func (a *App) saveAutonomousRunBestEffort(ctx context.Context, store autonomous.RunStore, run *autonomous.RunRecord) {
	if store == nil || run == nil {
		return
	}
	if err := store.SaveRun(ctx, run); err != nil {
		a.warnAutonomousRunPersistence("persist autonomous workflow run failed", run.ID, err)
	}
}

func (a *App) appendAutonomousRunEventBestEffort(ctx context.Context, store autonomous.RunStore, runID string, event autonomous.RunEvent) {
	if store == nil {
		return
	}
	if _, err := store.AppendEvent(ctx, runID, event); err != nil {
		a.warnAutonomousRunPersistence("persist autonomous workflow event failed", runID, err)
	}
}

func (a *App) warnAutonomousRunPersistence(message, runID string, err error) {
	if err == nil || a == nil || a.Logger == nil {
		return
	}
	a.Logger.Warn(message, "run_id", strings.TrimSpace(runID), "error", err)
}

//nolint:unused // compatibility shim for package-level tests during tools extraction
func (a *App) autonomousRuntimeBlocklist() *appRuntime.Blocklist {
	if a == nil || a.RuntimeRespond == nil {
		return nil
	}
	return a.RuntimeRespond.Blocklist()
}

//nolint:unused // compatibility shim for package-level tests during tools extraction
func (a *App) autonomousActionHandler() appRuntime.ActionHandler {
	if a != nil && a.RuntimeRespond != nil && a.RuntimeRespond.ActionHandler() != nil {
		return a.RuntimeRespond.ActionHandler()
	}
	return appRuntime.NewDefaultActionHandler(appRuntime.DefaultActionHandlerOptions{
		Blocklist:    a.autonomousRuntimeBlocklist(),
		RemoteCaller: a.RemoteTools,
	})
}

//nolint:unused // compatibility shim for package-level tests during tools extraction
func (a *App) autonomousActionStore() (*actionengine.SQLiteStore, error) {
	if a != nil && a.ExecutionStore != nil {
		return actionengine.NewSQLiteStoreWithExecutionStore(a.ExecutionStore, actionengine.DefaultNamespace), nil
	}
	if a == nil || a.Config == nil {
		return nil, fmt.Errorf("execution store is not configured")
	}
	store, err := actionengine.NewSQLiteStore(a.Config.ExecutionStoreFile, actionengine.DefaultNamespace)
	if err != nil {
		return nil, fmt.Errorf("open action execution store: %w", err)
	}
	return store, nil
}
