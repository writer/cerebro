package primitives

import cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"

// Event is the canonical v1 append-log envelope.
type Event = cerebrov1.EventEnvelope

// Stream is a named durable append-only log.
type Stream interface {
	Spec() *cerebrov1.StreamSpec
}

// View is a named materialized read model.
type View interface {
	Spec() *cerebrov1.ViewSpec
}

// Rule is a deterministic evaluator over one or more streams or views.
type Rule interface {
	Spec() *cerebrov1.RuleSpec
}

// Action is an idempotent side-effecting operation.
type Action interface {
	Spec() *cerebrov1.ActionSpec
}

// Agent is a conversational orchestrator over the other primitives.
type Agent interface {
	Spec() *cerebrov1.AgentSpec
}
