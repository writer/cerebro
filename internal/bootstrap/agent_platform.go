package bootstrap

import (
	"net/http"

	"github.com/writer/cerebro/internal/agentplatform"
)

func (a *App) handleAgentPlatformContract(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, agentplatform.Snapshot())
}
