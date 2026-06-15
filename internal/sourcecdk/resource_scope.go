package sourcecdk

import (
	"github.com/writer/cerebro/internal/primitives"
	"github.com/writer/cerebro/internal/resourcescope"
)

func applyResourceScopePolicy(pull Pull, policy resourcescope.Policy) Pull {
	if policy.Empty() || len(pull.Events) == 0 {
		return pull
	}
	events := make([]*primitives.Event, 0, len(pull.Events))
	for _, event := range pull.Events {
		if event == nil {
			continue
		}
		if policy.ExcludesEvent(event.GetKind(), event.GetId(), event.GetAttributes()) {
			continue
		}
		events = append(events, event)
	}
	if len(events) == len(pull.Events) {
		return pull
	}
	pull.Events = events
	return pull
}
