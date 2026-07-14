package workflowevents

import "sync"

var (
	kindRegistryMu sync.RWMutex
	kindRegistry   = map[string]string{}
)

func registerKind(kind, schema string) {
	kindRegistryMu.Lock()
	defer kindRegistryMu.Unlock()
	kindRegistry[kind] = schema
}

// KindRegistered reports whether the supplied workflow event kind is known to this package.
func KindRegistered(kind string) bool {
	kindRegistryMu.RLock()
	defer kindRegistryMu.RUnlock()
	_, ok := kindRegistry[kind]
	return ok
}

// SchemaForKind returns the registered schema URN for the supplied workflow event kind, or "" when unknown.
func SchemaForKind(kind string) string {
	kindRegistryMu.RLock()
	defer kindRegistryMu.RUnlock()
	return kindRegistry[kind]
}

// RegisteredKinds returns a snapshot of all known workflow event kinds in undefined order.
func RegisteredKinds() []string {
	kindRegistryMu.RLock()
	defer kindRegistryMu.RUnlock()
	kinds := make([]string, 0, len(kindRegistry))
	for kind := range kindRegistry {
		kinds = append(kinds, kind)
	}
	return kinds
}

func init() {
	registerKind(EventKindKnowledgeDecisionRecorded, SchemaKnowledgeDecisionRecorded)
	registerKind(EventKindKnowledgeActionRecorded, SchemaKnowledgeActionRecorded)
	registerKind(EventKindKnowledgeOutcomeRecorded, SchemaKnowledgeOutcomeRecorded)
	registerKind(EventKindFindingRecorded, SchemaFindingRecorded)
	registerKind(EventKindFindingNoteAdded, SchemaFindingNoteAdded)
	registerKind(EventKindFindingTicketLinked, SchemaFindingTicketLinked)
	registerKind(EventKindFindingStatusChanged, SchemaFindingStatusChanged)
	for _, kind := range registeredComplianceKinds() {
		registerKind(kind, SchemaComplianceAggregate)
	}
}
