package app

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/writer/cerebro/internal/graph"
)

type entitySearchBackendHandle struct {
	Backend graph.EntitySearchBackend
	Close   func() error
}

type entitySearchBackendProvider interface {
	Backend() graph.EntitySearchBackendType
	Open(ctx context.Context, app *App) (entitySearchBackendHandle, error)
	LogFields(app *App) []any
}

type entitySearchBackendProviderFactory func(app *App, backend graph.EntitySearchBackendType) (entitySearchBackendProvider, error)

type openSearchEntitySearchBackendProvider struct{}

func (a *App) resolveEntitySearchBackendProvider(backend graph.EntitySearchBackendType) (entitySearchBackendProvider, error) {
	if a != nil && a.entitySearchBackendProviderFactory != nil {
		return a.entitySearchBackendProviderFactory(a, backend)
	}
	if backend == graph.EntitySearchBackendOpenSearch {
		return &openSearchEntitySearchBackendProvider{}, nil
	}
	return nil, fmt.Errorf("unsupported graph search backend %q", backend)
}

func (p *openSearchEntitySearchBackendProvider) Backend() graph.EntitySearchBackendType {
	return graph.EntitySearchBackendOpenSearch
}

func (p *openSearchEntitySearchBackendProvider) Open(ctx context.Context, app *App) (entitySearchBackendHandle, error) {
	if app == nil || app.Config == nil {
		return entitySearchBackendHandle{}, graph.ErrStoreUnavailable
	}

	region := strings.TrimSpace(app.Config.GraphSearchOpenSearchRegion)
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return entitySearchBackendHandle{}, fmt.Errorf("load aws config for graph search backend: %w", err)
	}

	backend, err := graph.NewOpenSearchEntitySearchBackend(graph.OpenSearchEntitySearchBackendOptions{
		Endpoint:      app.Config.GraphSearchOpenSearchEndpoint,
		Region:        region,
		Index:         app.Config.GraphSearchOpenSearchIndex,
		HTTPClient:    &http.Client{Timeout: app.Config.GraphSearchRequestTimeout},
		Credentials:   awsCfg.Credentials,
		HydrateEntity: app.hydrateCurrentEntitySearchRecord,
		MaxCandidates: app.Config.GraphSearchMaxCandidates,
	})
	if err != nil {
		return entitySearchBackendHandle{}, err
	}

	return entitySearchBackendHandle{
		Backend: backend,
	}, nil
}

func (p *openSearchEntitySearchBackendProvider) LogFields(app *App) []any {
	if app == nil || app.Config == nil {
		return nil
	}
	return []any{
		"endpoint", strings.TrimSpace(app.Config.GraphSearchOpenSearchEndpoint),
		"region", strings.TrimSpace(app.Config.GraphSearchOpenSearchRegion),
		"index", strings.TrimSpace(app.Config.GraphSearchOpenSearchIndex),
	}
}
