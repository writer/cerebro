package app

import (
	"context"

	"github.com/evalops/cerebro/internal/agents"
	agentproviders "github.com/evalops/cerebro/internal/agents/providers"
	"github.com/evalops/cerebro/internal/scm"
)

func (a *App) initAgents() {
	a.Agents = agents.NewAgentRegistry()
	if a.Snowflake != nil {
		store, err := agents.NewSnowflakeSessionStore(a.Snowflake)
		if err != nil {
			a.Logger.Warn("failed to initialize persistent agent session store, using in-memory store", "error", err)
		} else {
			a.Agents.SetSessionStore(store)
		}
	}

	scmClient := scm.NewConfiguredClient(a.Config.GitHubToken, a.Config.GitLabToken, a.Config.GitLabBaseURL)
	toolset := agents.NewSecurityTools(a.Snowflake, a.Findings, a.Policy, scmClient)
	agentTools := toolset.GetTools()

	remoteProvider, err := agents.NewRemoteToolProvider(remoteToolProviderConfigFromConfig(a.Config), a.Logger)
	if err != nil {
		a.Logger.Warn("failed to initialize remote tool provider", "error", err)
	} else if remoteProvider != nil {
		remoteTools, err := remoteProvider.DiscoverTools(context.Background())
		if err != nil {
			a.Logger.Warn("failed to discover remote tools", "error", err)
			_ = remoteProvider.Close()
		} else {
			agentTools = agents.MergeTools(agentTools, remoteTools)
			a.RemoteTools = remoteProvider
			if a.RemediationExecutor != nil {
				a.RemediationExecutor.SetRemoteCaller(remoteProvider)
			}
			a.Logger.Info("registered remote tools for agents", "count", len(remoteTools))
		}
	}

	publisher, err := agents.NewToolPublisher(toolPublisherConfigFromConfig(a.Config), a.AgentSDKTools(), a.Logger)
	if err != nil {
		a.Logger.Warn("failed to initialize cerebro tool publisher", "error", err)
	} else if publisher != nil {
		a.ToolPublisher = publisher
	}

	registerConfiguredAIAgents(a.Agents, a.Config, agentTools)
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
	if cfg.AnthropicAPIKey != "" {
		provider := agentproviders.NewAnthropicProvider(agentproviders.AnthropicConfig{
			APIKey: cfg.AnthropicAPIKey,
		})
		registry.RegisterAgent(&agents.Agent{
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
		registry.RegisterAgent(&agents.Agent{
			ID:          "incident-responder",
			Name:        "Incident Responder",
			Description: "AI-powered incident responder for triage and remediation",
			Provider:    provider,
			Tools:       tools,
			Memory:      agents.NewMemory(100),
		})
	}
}
