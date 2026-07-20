package bootstrap

import (
	"github.com/writer/cerebro/internal/evidenceledger"
	"github.com/writer/cerebro/internal/ports"
)

func (a *App) newEvidenceLedgerService() *evidenceledger.Service {
	if a == nil || a.deps.AppendLog == nil {
		return nil
	}
	store, ok := a.deps.StateStore.(ports.EvidenceLedgerStore)
	if !ok || isNilInterface(store) {
		return nil
	}
	return evidenceledger.New(store, a.deps.AppendLog)
}
