package bootstrap

import (
	"github.com/writer/cerebro/internal/complianceremediation"
	"github.com/writer/cerebro/internal/ports"
)

func (a *App) newComplianceRemediationService() *complianceremediation.Service {
	if a == nil || a.deps.AppendLog == nil {
		return nil
	}
	replayer, ok := a.deps.AppendLog.(ports.EventReplayPager)
	if !ok || isNilInterface(replayer) {
		return nil
	}
	store, projector := complianceRemediationCapabilities(a.deps.StateStore)
	if store == nil || projector == nil {
		return nil
	}
	return complianceremediation.New(store, projector, a.deps.AppendLog, replayer)
}

func complianceRemediationCapabilities(state ports.StateStore) (complianceremediation.Store, complianceremediation.Projector) {
	store, storeOK := state.(complianceremediation.Store)
	projector, projectorOK := state.(complianceremediation.Projector)
	if storeOK && projectorOK && !isNilInterface(store) && !isNilInterface(projector) {
		return store, projector
	}
	return nil, nil
}
