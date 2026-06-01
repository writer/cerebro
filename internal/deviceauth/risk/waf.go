package risk

import (
	"context"
	"encoding/json"
	"io"
	"sync"
	"time"
)

// WAFRuleUpdate is what the scorer hands to a [WAFEmitter] when a "high"
// risk decision fires. The emitter is responsible for translating the
// update into the appropriate AWS WAFv2 IPSet update / EventBridge event.
type WAFRuleUpdate struct {
	DeviceID string    `json:"device_id"`
	TenantID string    `json:"tenant_id"`
	IP       string    `json:"ip"`
	Reason   string    `json:"reason"`
	At       time.Time `json:"at"`
}

// WAFEmitter sends WAF updates somewhere durable. Implementations are
// expected to be best-effort: a failed Emit should not block the request
// pipeline, and the Scorer logs but does not propagate emit errors.
type WAFEmitter interface {
	Emit(ctx context.Context, update WAFRuleUpdate) error
}

// NoOpEmitter discards updates. Used when WAF integration is disabled.
type NoOpEmitter struct{}

// Emit implements [WAFEmitter].
func (NoOpEmitter) Emit(_ context.Context, _ WAFRuleUpdate) error { return nil }

// JSONLogEmitter writes a JSON line per update to a configurable
// [io.Writer]. In production this Writer is the bootstrap process's
// structured-event stream; CloudWatch / EventBridge picks the line up
// downstream.
type JSONLogEmitter struct {
	mu sync.Mutex
	w  io.Writer
}

// NewJSONLogEmitter returns an emitter that writes to w.
func NewJSONLogEmitter(w io.Writer) *JSONLogEmitter { return &JSONLogEmitter{w: w} }

// Emit implements [WAFEmitter].
func (e *JSONLogEmitter) Emit(_ context.Context, update WAFRuleUpdate) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	enc := json.NewEncoder(e.w)
	return enc.Encode(struct {
		Kind string `json:"kind"`
		Name string `json:"name"`
		WAFRuleUpdate
	}{
		Kind:          "event",
		Name:          "cerebro.deviceauth.waf_emit",
		WAFRuleUpdate: update,
	})
}
