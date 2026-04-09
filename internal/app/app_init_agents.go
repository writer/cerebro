package app

import (
	"context"

	"github.com/writer/cerebro/internal/agents"
	agentproviders "github.com/writer/cerebro/internal/agents/providers"
	"github.com/writer/cerebro/internal/scm"
)

func (a *App) initAgents(ctx context.Context) {
	if ctx == nil {
		ctx = context.Background()
	}
	a.Agents = agents.NewAgentRegistry()
	switch {
	case a.appStateDB != nil:
		a.Agents.SetSessionStore(agents.NewPostgresSessionStore(a.appStateDB))
	case a.Snowflake != nil:
		store, err := agents.NewSnowflakeSessionStore(a.Snowflake)
		if err != nil {
			a.Logger.Warn("failed to initialize persistent agent session store, using in-memory store", "error", err)
		} else if err := store.EnsureSchema(ctx); err != nil {
			a.Logger.Warn("failed to ensure persistent agent session store schema, using in-memory store", "error", err)
		} else {
			a.Agents.SetSessionStore(store)
		}
	}

	a.rebuildAgentTooling(ctx, a.Config)
	registerConfiguredAIAgents(a.Agents, a.Config, a.configuredAgentTools(a.Config))
}

func (a *App) configuredAgentTools(cfg *Config) []agents.Tool {
	if a == nil {
		return nil
	}
	return agents.MergeTools(a.securityAgentTools(cfg), a.remoteAgentTools)
}

func (a *App) rebuildAgentTooling(ctx context.Context, cfg *Config) {
	if a == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}

	a.remoteAgentTools = nil
	if a.RemoteTools != nil {
		if err := a.RemoteTools.Close(); err != nil && a.Logger != nil {
			a.Logger.Warn("failed to close previous remote tool provider", "error", err)
		}
	}
	a.RemoteTools = nil
	if a.RemediationExecutor != nil {
		a.RemediationExecutor.SetRemoteCaller(nil)
	}
	if a.RuntimeRespond != nil {
		a.RuntimeRespond.SetRemoteCaller(nil)
	}

	remoteProvider, err := agents.NewRemoteToolProvider(remoteToolProviderConfigFromConfig(cfg), a.Logger)
	if err != nil {
		if a.Logger != nil {
			a.Logger.Warn("failed to initialize remote tool provider", "error", err)
		}
	} else if remoteProvider != nil {
		remoteTools, err := remoteProvider.DiscoverTools(ctx)
		if err != nil {
			if a.Logger != nil {
				a.Logger.Warn("failed to discover remote tools", "error", err)
			}
			_ = remoteProvider.Close()
		} else {
			a.remoteAgentTools = append([]agents.Tool(nil), remoteTools...)
			a.RemoteTools = remoteProvider
			if a.RemediationExecutor != nil {
				a.RemediationExecutor.SetRemoteCaller(remoteProvider)
			}
			if a.RuntimeRespond != nil {
				a.RuntimeRespond.SetRemoteCaller(remoteProvider)
			}
			if a.Logger != nil {
				a.Logger.Info("registered remote tools for agents", "count", len(remoteTools))
			}
		}
	}

	if a.ToolPublisher != nil {
		if err := a.ToolPublisher.Close(); err != nil && a.Logger != nil {
			a.Logger.Warn("failed to close previous cerebro tool publisher", "error", err)
		}
	}
	a.ToolPublisher = nil
	publisher, err := agents.NewToolPublisher(toolPublisherConfigFromConfig(cfg), a.AgentSDKTools(), a.Logger)
	if err != nil {
		if a.Logger != nil {
			a.Logger.Warn("failed to initialize cerebro tool publisher", "error", err)
		}
		return
	}
	if publisher != nil {
		a.ToolPublisher = publisher
	}
}

func (a *App) securityAgentTools(cfg *Config) []agents.Tool {
	if a == nil {
		return nil
	}
	if cfg == nil {
		cfg = a.Config
	}

	sfClient := a.Snowflake
	if sfClient == nil {
		sfClient = a.LegacySnowflake
	}

	var scmClient scm.Client
	if cfg != nil {
		scmClient = scm.NewConfiguredClient(cfg.GitHubToken, cfg.GitLabToken, cfg.GitLabBaseURL)
	}

	return agents.NewSecurityTools(sfClient, a.Findings, a.Policy, scmClient).GetTools()
}

func (a *App) refreshConfiguredAgentTools(cfg *Config) {
	if a == nil || a.Agents == nil {
		return
	}
	tools := a.configuredAgentTools(cfg)
	for _, agentID := range configuredAIAgentIDs(cfg) {
		a.Agents.RefreshAgentTools(agentID, tools)
	}
}

func (a *App) syncConfiguredAIAgents(cfg *Config) {
	if a == nil || a.Agents == nil {
		return
	}
	tools := a.configuredAgentTools(cfg)
	syncConfiguredAIAgents(a.Agents, cfg, tools)
}

func (a *App) replaceConfiguredAgentTools(cfg *Config, previousBaseTools []agents.Tool) {
	if a == nil || a.Agents == nil {
		return
	}
	tools := a.configuredAgentTools(cfg)
	for _, agentID := range configuredAIAgentIDs(cfg) {
		a.Agents.ReplaceAgentTools(agentID, previousBaseTools, tools)
	}
}

func (a *App) syncConfiguredAIAgentsReplacingTools(cfg *Config, previousBaseTools []agents.Tool) {
	if a == nil || a.Agents == nil {
		return
	}
	tools := a.configuredAgentTools(cfg)
	syncConfiguredAIAgentsReplacingTools(a.Agents, cfg, tools, previousBaseTools)
}

func configuredAIAgentIDs(cfg *Config) []string {
	configured := configuredAIAgents(cfg, nil)
	ids := make([]string, 0, len(configured))
	for _, agent := range configured {
		if agent == nil {
			continue
		}
		ids = append(ids, agent.ID)
	}
	return ids
}

func remoteToolProviderConfigFromConfig(cfg *Config) agents.RemoteToolProviderConfig {
	return agents.RemoteToolProviderConfig{
		Enabled:               cfg.AgentRemoteToolsEnabled,
		URLs:                  cfg.NATSJetStreamURLs,
		ManifestSubject:       cfg.AgentRemoteToolsManifestSubject,
		RequestPrefix:         cfg.AgentRemoteToolsRequestPrefix,
		DiscoverTimeout:       cfg.AgentRemoteToolsDiscoverTimeout,
		RequestTimeout:        cfg.AgentRemoteToolsRequestTimeout,
		MaxTools:              cfg.AgentRemoteToolsMaxTools,
		ConnectTimeout:        cfg.NATSJetStreamConnectTimeout,
		AuthMode:              cfg.NATSJetStreamAuthMode,
		Username:              cfg.NATSJetStreamUsername,
		Password:              cfg.NATSJetStreamPassword,
		NKeySeed:              cfg.NATSJetStreamNKeySeed,
		UserJWT:               cfg.NATSJetStreamUserJWT,
		TLSEnabled:            cfg.NATSJetStreamTLSEnabled,
		TLSCAFile:             cfg.NATSJetStreamTLSCAFile,
		TLSCertFile:           cfg.NATSJetStreamTLSCertFile,
		TLSKeyFile:            cfg.NATSJetStreamTLSKeyFile,
		TLSServerName:         cfg.NATSJetStreamTLSServerName,
		TLSInsecureSkipVerify: cfg.NATSJetStreamTLSInsecure,
	}
}

func toolPublisherConfigFromConfig(cfg *Config) agents.ToolPublisherConfig {
	return agents.ToolPublisherConfig{
		Enabled:               cfg.AgentToolPublisherEnabled,
		URLs:                  cfg.NATSJetStreamURLs,
		ManifestSubject:       cfg.AgentToolPublisherManifestSubject,
		RequestPrefix:         cfg.AgentToolPublisherRequestPrefix,
		RequestTimeout:        cfg.AgentToolPublisherRequestTimeout,
		ConnectTimeout:        cfg.NATSJetStreamConnectTimeout,
		AuthMode:              cfg.NATSJetStreamAuthMode,
		Username:              cfg.NATSJetStreamUsername,
		Password:              cfg.NATSJetStreamPassword,
		NKeySeed:              cfg.NATSJetStreamNKeySeed,
		UserJWT:               cfg.NATSJetStreamUserJWT,
		TLSEnabled:            cfg.NATSJetStreamTLSEnabled,
		TLSCAFile:             cfg.NATSJetStreamTLSCAFile,
		TLSCertFile:           cfg.NATSJetStreamTLSCertFile,
		TLSKeyFile:            cfg.NATSJetStreamTLSKeyFile,
		TLSServerName:         cfg.NATSJetStreamTLSServerName,
		TLSInsecureSkipVerify: cfg.NATSJetStreamTLSInsecure,
	}
}

func registerConfiguredAIAgents(registry *agents.AgentRegistry, cfg *Config, tools []agents.Tool) {
	syncConfiguredAIAgents(registry, cfg, tools)
}

func syncConfiguredAIAgents(registry *agents.AgentRegistry, cfg *Config, tools []agents.Tool) {
	syncConfiguredAIAgentsReplacingTools(registry, cfg, tools, nil)
}

func syncConfiguredAIAgentsReplacingTools(registry *agents.AgentRegistry, cfg *Config, tools, previousBaseTools []agents.Tool) {
	if registry == nil {
		return
	}

	configured := configuredAIAgents(cfg, tools)
	desired := make(map[string]struct{}, len(configured))
	for _, agent := range configured {
		if agent == nil {
			continue
		}
		desired[agent.ID] = struct{}{}
		registry.UpsertAgentReplacingTools(agent, previousBaseTools)
	}

	for _, agentID := range []string{"security-analyst", "incident-responder"} {
		if _, ok := desired[agentID]; ok {
			continue
		}
		registry.RemoveAgent(agentID)
	}
}

func configuredAIAgents(cfg *Config, tools []agents.Tool) []*agents.Agent {
	if cfg == nil {
		return nil
	}

	configured := make([]*agents.Agent, 0, 2)
	if cfg.AnthropicAPIKey != "" {
		provider := agentproviders.NewAnthropicProvider(agentproviders.AnthropicConfig{
			APIKey: cfg.AnthropicAPIKey,
		})
		configured = append(configured, &agents.Agent{
			ID:          "security-analyst",
			Name:        "Security Analyst",
			Description: "AI-powered security analyst for investigating findings and incidents",
			Provider:    provider,
			Tools:       tools,
			Memory:      agents.NewMemory(100),
		})
	}

	if cfg.OpenAIAPIKey != "" {
		provider := agentproviders.NewOpenAIProvider(agentproviders.OpenAIConfig{
			APIKey: cfg.OpenAIAPIKey,
		})
		configured = append(configured, &agents.Agent{
			ID:          "incident-responder",
			Name:        "Incident Responder",
			Description: "AI-powered incident responder for triage and remediation",
			Provider:    provider,
			Tools:       tools,
			Memory:      agents.NewMemory(100),
		})
	}

	return configured
}
