package app

import "github.com/writer/cerebro/internal/agents"

// AgentSDKTools exposes the curated Cerebro tool surface so API, MCP, and NATS
// publishers all share one canonical registry.
func (a *App) AgentSDKTools() []agents.Tool {
	return a.cerebroTools()
}
