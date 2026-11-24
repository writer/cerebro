package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/connectorsecretstores"
	"github.com/writer/cerebro/internal/mcpoperations"
	"github.com/writer/cerebro/internal/panicsafe"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourceconfig"
	vulnhttp "github.com/writer/cerebro/internal/sourcehttp/vulnerabilities"
	"github.com/writer/cerebro/internal/vulnpipeline"
)

const vulnerabilityPullPollInterval = 30 * time.Second

func (app *App) newVulnerabilityService() *vulnpipeline.Service {
	store, _ := app.deps.StateStore.(ports.VulnerabilityPipelineStore)
	return vulnpipeline.NewService(store, vulnpipeline.Options{
		Pullers: []vulnpipeline.Puller{vulnpipeline.StrixPuller{}, vulnpipeline.HTTPPuller{}, vulnpipeline.S3Puller{Sources: config.VulnerabilityPullS3Sources}},
		ResolveConfig: func(ctx context.Context, profile *ports.VulnerabilityProfile, values map[string]string) (map[string]string, error) {
			return resolveRuntimeSourceConfigWithStore(ctx, app.cfg.ConnectorCredentials, app.cfg.ConnectorSecretStores, app.deps.StateStore, vulnpipeline.SecretScopeSourceID, sourceconfig.WithRuntimeContext(values, profile.TenantID, profile.ID))
		},
		AuthorizeConfig: func(ctx context.Context, profile *ports.VulnerabilityProfile, values map[string]string) error {
			if err := authorizeRuntimeConfigEnvReferences(ctx, vulnpipeline.SecretScopeSourceID, values); err != nil {
				return err
			}
			if err := connectorsecretstores.AuthorizeRuntimeReferences(vulnpipeline.SecretScopeSourceID, profile.TenantID, profile.ID, values); err != nil {
				return fmt.Errorf("%w: %w", vulnpipeline.ErrInvalidRequest, err)
			}
			return nil
		},
		IsSecretReference: func(value string) bool {
			return sourceconfig.IsSecretReference(value) || sourceconfig.IsCredentialReference(value) || connectorsecretstores.IsReference(value)
		},
	})
}

// StartVulnerabilityPullScheduler runs due pull profiles until ctx ends.
func (app *App) StartVulnerabilityPullScheduler(ctx context.Context, logf func(string, ...any)) <-chan struct{} {
	done := make(chan struct{})
	service := app.services.vulnerabilities
	if service == nil || !service.Available() {
		close(done)
		return done
	}
	owner := startupJobLeaseOwner()
	panicsafe.Go(ctx, "vulnerability_pull.scheduler", func() {
		defer close(done)
		ticker := time.NewTicker(vulnerabilityPullPollInterval)
		defer ticker.Stop()
		for {
			if _, err := service.RunDuePulls(ctx, owner); err != nil && ctx.Err() == nil && logf != nil {
				logf("run due vulnerability pulls: %v", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	})
	return done
}

func (app *App) mcpVulnerabilityTool(r *http.Request, name string, args map[string]any) (any, error) {
	tenantID, err := effectiveTenantFilter(r.Context(), mcpTenantArg(r, args))
	if err != nil {
		return nil, err
	}
	arguments, _ := json.Marshal(args) // args was decoded from JSON, so it always re-encodes.
	result, err := vulnhttp.MCPTool(r.Context(), app.services.vulnerabilities, name, tenantID, customDashboardActorID(r.Context()), arguments)
	switch {
	case vulnhttp.IsClientError(err):
		return nil, fmt.Errorf("%w: %w", errInvalidHTTPRequest, err)
	case errors.Is(err, vulnpipeline.ErrNotFound), errors.Is(err, ports.ErrVulnerabilityProfileNotFound):
		return nil, fmt.Errorf("%w: vulnerability record not found", errInvalidHTTPRequest)
	case err != nil:
		return nil, err
	}
	return result, nil
}

func mcpVulnerabilityTools() []mcpTool {
	definitions := mcpoperations.VulnerabilityToolDefinitions()
	tools := make([]mcpTool, 0, len(definitions))
	for _, definition := range definitions {
		annotations := mcpReadOnlyAnnotations(definition.Title)
		if operation, ok := mcpoperations.Lookup(definition.Name); ok && operation.Behavior == mcpoperations.BehaviorExecute {
			annotations = mcpWriteAnnotations(definition.Title, definition.Idempotent)
			annotations["destructiveHint"] = definition.Destructive
		}
		tools = append(tools, mcpTool{Name: definition.Name, Title: definition.Title, Description: definition.Description, InputSchema: definition.InputSchema, OutputSchema: definition.OutputSchema, Annotations: annotations})
	}
	return tools
}
