package app

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"cloud.google.com/go/spanner"
	databaseadmin "cloud.google.com/go/spanner/admin/database/apiv1"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/neptunedata"
	"github.com/writer/cerebro/internal/graph"
)

type graphStoreBackendHandle struct {
	Store graph.GraphStore
	Close func() error
}

type graphStoreBackendProvider interface {
	Backend() graph.StoreBackend
	Open(ctx context.Context, app *App) (graphStoreBackendHandle, error)
	LogFields(app *App) []any
}

type graphStoreBackendProviderFactory func(app *App, backend graph.StoreBackend) (graphStoreBackendProvider, error)

type neptuneGraphStoreBackendProvider struct{}

type spannerGraphStoreBackendProvider struct{}

var (
	_ graphStoreBackendProvider = (*neptuneGraphStoreBackendProvider)(nil)
	_ graphStoreBackendProvider = (*spannerGraphStoreBackendProvider)(nil)
)

func (a *App) resolveGraphStoreBackendProvider(backend graph.StoreBackend) (graphStoreBackendProvider, error) {
	if a != nil && a.graphStoreBackendProviderFactory != nil {
		return a.graphStoreBackendProviderFactory(a, backend)
	}
	switch backend {
	case graph.StoreBackendNeptune:
		return &neptuneGraphStoreBackendProvider{}, nil
	case graph.StoreBackendSpanner:
		return &spannerGraphStoreBackendProvider{}, nil
	default:
		return nil, fmt.Errorf("unsupported graph store backend %q", backend)
	}
}

func (p *neptuneGraphStoreBackendProvider) Backend() graph.StoreBackend {
	return graph.StoreBackendNeptune
}

func (p *neptuneGraphStoreBackendProvider) Open(ctx context.Context, app *App) (graphStoreBackendHandle, error) {
	if app == nil || app.Config == nil {
		return graphStoreBackendHandle{}, graph.ErrStoreUnavailable
	}
	region := strings.TrimSpace(app.Config.GraphStoreNeptuneRegion)
	if region == "" {
		region = "us-east-1"
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return graphStoreBackendHandle{}, fmt.Errorf("load aws config for neptune graph store: %w", err)
	}
	endpoint := strings.TrimSpace(app.Config.GraphStoreNeptuneEndpoint)
	pooledExec, err := graph.NewPooledNeptuneDataExecutor(func() (graph.NeptuneDataClient, error) {
		return neptunedata.NewFromConfig(awsCfg, func(options *neptunedata.Options) {
			if endpoint != "" {
				options.BaseEndpoint = aws.String(endpoint)
			}
		}), nil
	}, graph.NeptuneDataExecutorPoolConfig{
		Size:                app.Config.GraphStoreNeptunePoolSize,
		HealthCheckInterval: app.Config.GraphStoreNeptunePoolHealthCheckInterval,
		HealthCheckTimeout:  app.Config.GraphStoreNeptunePoolHealthCheckTimeout,
		MaxClientLifetime:   app.Config.GraphStoreNeptunePoolMaxClientLifetime,
		MaxClientUses:       app.Config.GraphStoreNeptunePoolMaxClientUses,
		DrainTimeout:        app.Config.GraphStoreNeptunePoolDrainTimeout,
	})
	if err != nil {
		return graphStoreBackendHandle{}, fmt.Errorf("create neptune graph store executor: %w", err)
	}
	return graphStoreBackendHandle{
		Store: graph.NewNeptuneGraphStore(pooledExec),
		Close: pooledExec.Close,
	}, nil
}

func (p *neptuneGraphStoreBackendProvider) LogFields(app *App) []any {
	if app == nil || app.Config == nil {
		return nil
	}
	region := strings.TrimSpace(app.Config.GraphStoreNeptuneRegion)
	if region == "" {
		region = "us-east-1"
	}
	return []any{
		"endpoint", strings.TrimSpace(app.Config.GraphStoreNeptuneEndpoint),
		"region", region,
	}
}

func (p *spannerGraphStoreBackendProvider) Backend() graph.StoreBackend {
	return graph.StoreBackendSpanner
}

func (p *spannerGraphStoreBackendProvider) Open(ctx context.Context, app *App) (graphStoreBackendHandle, error) {
	if app == nil || app.Config == nil {
		return graphStoreBackendHandle{}, graph.ErrStoreUnavailable
	}
	database := strings.TrimSpace(app.Config.GraphStoreSpannerDatabase)
	client, err := spanner.NewClient(ctx, database)
	if err != nil {
		return graphStoreBackendHandle{}, fmt.Errorf("connect spanner graph store: %w", err)
	}
	var (
		adminClient *databaseadmin.DatabaseAdminClient
		ddlApplier  graph.SpannerDDLApplier
	)
	if app.Config.GraphStoreSpannerAutoBootstrap {
		adminClient, err = databaseadmin.NewDatabaseAdminClient(ctx)
		if err != nil {
			client.Close()
			return graphStoreBackendHandle{}, fmt.Errorf("create spanner database admin client: %w", err)
		}
		ddlApplier = graph.NewCloudSpannerDDLApplier(adminClient)
	}
	closeFn := func() error {
		var errs []error
		if adminClient != nil {
			if err := adminClient.Close(); err != nil {
				errs = append(errs, err)
			}
		}
		client.Close()
		if len(errs) == 0 {
			return nil
		}
		return fmt.Errorf("close spanner graph store admin client: %v", errs)
	}
	store := graph.NewSpannerGraphStore(graph.NewCloudSpannerGraphStoreAdapter(client, database, ddlApplier))
	if app.Config.GraphStoreSpannerAutoBootstrap {
		if err := store.EnsureIndexes(ctx); err != nil {
			return graphStoreBackendHandle{}, closeHandle(graphStoreBackendHandle{Close: closeFn}, fmt.Errorf("bootstrap spanner graph store schema: %w", err))
		}
	}
	return graphStoreBackendHandle{
		Store: store,
		Close: closeFn,
	}, nil
}

func (p *spannerGraphStoreBackendProvider) LogFields(app *App) []any {
	if app == nil || app.Config == nil {
		return nil
	}
	return []any{
		"database", strings.TrimSpace(app.Config.GraphStoreSpannerDatabase),
		"auto_bootstrap", app.Config.GraphStoreSpannerAutoBootstrap,
	}
}

func closeHandle(handle graphStoreBackendHandle, base error) error {
	if handle.Close == nil {
		return base
	}
	if err := handle.Close(); err != nil {
		return errors.Join(base, err)
	}
	return base
}
