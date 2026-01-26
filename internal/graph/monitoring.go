package graph

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// ToxicCombinationMonitor continuously monitors for toxic combinations
type ToxicCombinationMonitor struct {
	graph       *Graph
	engine      *ToxicCombinationEngine
	interval    time.Duration
	lastResults []*ToxicCombination
	subscribers []chan<- *ToxicCombinationEvent
	logger      *slog.Logger
	mu          sync.RWMutex
	stopCh      chan struct{}
	running     bool
	stopOnce    sync.Once
}

// ToxicCombinationEvent represents a change in toxic combinations
type ToxicCombinationEvent struct {
	Timestamp   time.Time         `json:"timestamp"`
	EventType   string            `json:"event_type"` // new, resolved, changed
	Combination *ToxicCombination `json:"combination"`
	Previous    *ToxicCombination `json:"previous,omitempty"`
	Delta       float64           `json:"delta,omitempty"` // Score change
}

// NewToxicCombinationMonitor creates a new monitor
func NewToxicCombinationMonitor(g *Graph, interval time.Duration, logger *slog.Logger) *ToxicCombinationMonitor {
	engine := NewToxicCombinationEngine()

	return &ToxicCombinationMonitor{
		graph:    g,
		engine:   engine,
		interval: interval,
		logger:   logger,
		stopCh:   make(chan struct{}),
	}
}

// Subscribe adds a channel to receive toxic combination events
func (m *ToxicCombinationMonitor) Subscribe(ch chan<- *ToxicCombinationEvent) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.subscribers = append(m.subscribers, ch)
}

// Unsubscribe removes a channel from receiving events
func (m *ToxicCombinationMonitor) Unsubscribe(ch chan<- *ToxicCombinationEvent) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, sub := range m.subscribers {
		if sub == ch {
			m.subscribers = append(m.subscribers[:i], m.subscribers[i+1:]...)
			return
		}
	}
}

// Start begins continuous monitoring
func (m *ToxicCombinationMonitor) Start(ctx context.Context) error {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return fmt.Errorf("monitor already running")
	}
	m.running = true
	m.mu.Unlock()

	m.logger.Info("starting toxic combination monitor", "interval", m.interval)

	// Initial scan
	m.scan()

	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			m.logger.Info("stopping toxic combination monitor")
			m.mu.Lock()
			m.running = false
			m.mu.Unlock()
			return ctx.Err()
		case <-m.stopCh:
			m.logger.Info("stopping toxic combination monitor")
			m.mu.Lock()
			m.running = false
			m.mu.Unlock()
			return nil
		case <-ticker.C:
			m.scan()
		}
	}
}

// Stop stops the monitor (safe to call multiple times)
func (m *ToxicCombinationMonitor) Stop() {
	m.stopOnce.Do(func() {
		close(m.stopCh)
	})
}

// GetLastResults returns the most recent scan results
func (m *ToxicCombinationMonitor) GetLastResults() []*ToxicCombination {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastResults
}

func (m *ToxicCombinationMonitor) scan() {
	start := time.Now()
	newResults := m.engine.Analyze(m.graph)
	duration := time.Since(start)

	m.logger.Debug("toxic combination scan complete",
		"duration", duration,
		"count", len(newResults))

	// Compare with previous results
	events := m.compareResults(m.lastResults, newResults)

	m.mu.Lock()
	m.lastResults = newResults
	m.mu.Unlock()

	// Publish events
	for _, event := range events {
		m.publish(event)
	}
}

func (m *ToxicCombinationMonitor) compareResults(old, new []*ToxicCombination) []*ToxicCombinationEvent {
	var events []*ToxicCombinationEvent
	now := time.Now()

	oldMap := make(map[string]*ToxicCombination)
	for _, tc := range old {
		oldMap[tc.ID] = tc
	}

	newMap := make(map[string]*ToxicCombination)
	for _, tc := range new {
		newMap[tc.ID] = tc
	}

	// Find new combinations
	for id, tc := range newMap {
		if _, exists := oldMap[id]; !exists {
			events = append(events, &ToxicCombinationEvent{
				Timestamp:   now,
				EventType:   "new",
				Combination: tc,
			})
			m.logger.Warn("new toxic combination detected",
				"id", tc.ID,
				"name", tc.Name,
				"severity", tc.Severity,
				"score", tc.Score)
		}
	}

	// Find resolved combinations
	for id, tc := range oldMap {
		if _, exists := newMap[id]; !exists {
			events = append(events, &ToxicCombinationEvent{
				Timestamp:   now,
				EventType:   "resolved",
				Combination: tc,
			})
			m.logger.Info("toxic combination resolved",
				"id", tc.ID,
				"name", tc.Name)
		}
	}

	// Find changed combinations (score changes)
	for id, newTC := range newMap {
		if oldTC, exists := oldMap[id]; exists {
			delta := newTC.Score - oldTC.Score
			if delta > 5 || delta < -5 { // Significant change threshold
				events = append(events, &ToxicCombinationEvent{
					Timestamp:   now,
					EventType:   "changed",
					Combination: newTC,
					Previous:    oldTC,
					Delta:       delta,
				})
				m.logger.Info("toxic combination score changed",
					"id", newTC.ID,
					"name", newTC.Name,
					"oldScore", oldTC.Score,
					"newScore", newTC.Score,
					"delta", delta)
			}
		}
	}

	return events
}

func (m *ToxicCombinationMonitor) publish(event *ToxicCombinationEvent) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, ch := range m.subscribers {
		select {
		case ch <- event:
		default:
			// Channel full, skip
		}
	}
}

// AttackPathMonitor monitors for changes in attack paths
type AttackPathMonitor struct {
	graph       *Graph
	simulator   *AttackPathSimulator
	interval    time.Duration
	lastResult  *SimulationResult
	subscribers []chan<- *AttackPathEvent
	logger      *slog.Logger
	mu          sync.RWMutex
	stopCh      chan struct{}
	running     bool
	stopOnce    sync.Once
}

// AttackPathEvent represents a change in attack paths
type AttackPathEvent struct {
	Timestamp  time.Time         `json:"timestamp"`
	EventType  string            `json:"event_type"` // new_path, path_removed, new_critical, chokepoint_change
	Path       *ScoredAttackPath `json:"path,omitempty"`
	Chokepoint *Chokepoint       `json:"chokepoint,omitempty"`
	Summary    string            `json:"summary"`
}

// NewAttackPathMonitor creates a new attack path monitor
func NewAttackPathMonitor(g *Graph, interval time.Duration, logger *slog.Logger) *AttackPathMonitor {
	return &AttackPathMonitor{
		graph:    g,
		interval: interval,
		logger:   logger,
		stopCh:   make(chan struct{}),
	}
}

// Subscribe adds a channel to receive attack path events
func (m *AttackPathMonitor) Subscribe(ch chan<- *AttackPathEvent) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.subscribers = append(m.subscribers, ch)
}

// Start begins continuous monitoring
func (m *AttackPathMonitor) Start(ctx context.Context) error {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return fmt.Errorf("monitor already running")
	}
	m.running = true
	m.mu.Unlock()

	m.logger.Info("starting attack path monitor", "interval", m.interval)

	// Initial scan
	m.scan()

	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			m.mu.Lock()
			m.running = false
			m.mu.Unlock()
			return ctx.Err()
		case <-m.stopCh:
			m.mu.Lock()
			m.running = false
			m.mu.Unlock()
			return nil
		case <-ticker.C:
			m.scan()
		}
	}
}

// Stop stops the monitor (safe to call multiple times)
func (m *AttackPathMonitor) Stop() {
	m.stopOnce.Do(func() {
		close(m.stopCh)
	})
}

// GetLastResult returns the most recent simulation result
func (m *AttackPathMonitor) GetLastResult() *SimulationResult {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastResult
}

func (m *AttackPathMonitor) scan() {
	start := time.Now()
	m.simulator = NewAttackPathSimulator(m.graph)
	newResult := m.simulator.Simulate(6)
	duration := time.Since(start)

	m.logger.Debug("attack path scan complete",
		"duration", duration,
		"paths", newResult.TotalPaths,
		"critical", newResult.CriticalPaths)

	// Compare with previous
	events := m.compareResults(m.lastResult, newResult)

	m.mu.Lock()
	m.lastResult = newResult
	m.mu.Unlock()

	// Publish events
	for _, event := range events {
		m.publish(event)
	}
}

func (m *AttackPathMonitor) compareResults(old, new *SimulationResult) []*AttackPathEvent {
	var events []*AttackPathEvent
	now := time.Now()

	if old == nil {
		// First run, report if critical paths exist
		if new.CriticalPaths > 0 {
			events = append(events, &AttackPathEvent{
				Timestamp: now,
				EventType: "initial_scan",
				Summary:   fmt.Sprintf("Initial scan found %d attack paths, %d critical", new.TotalPaths, new.CriticalPaths),
			})
		}
		return events
	}

	// Check for new critical paths
	if new.CriticalPaths > old.CriticalPaths {
		delta := new.CriticalPaths - old.CriticalPaths
		events = append(events, &AttackPathEvent{
			Timestamp: now,
			EventType: "new_critical",
			Summary:   fmt.Sprintf("%d new critical attack paths detected", delta),
		})
		m.logger.Warn("new critical attack paths detected",
			"count", delta,
			"total", new.CriticalPaths)
	}

	// Check for chokepoint changes
	if len(new.Chokepoints) > 0 && len(old.Chokepoints) > 0 {
		if new.Chokepoints[0].Node.ID != old.Chokepoints[0].Node.ID {
			events = append(events, &AttackPathEvent{
				Timestamp:  now,
				EventType:  "chokepoint_change",
				Chokepoint: new.Chokepoints[0],
				Summary:    fmt.Sprintf("Top remediation priority changed to %s", new.Chokepoints[0].Node.Name),
			})
		}
	}

	return events
}

func (m *AttackPathMonitor) publish(event *AttackPathEvent) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, ch := range m.subscribers {
		select {
		case ch <- event:
		default:
		}
	}
}

// PrivilegeEscalationMonitor monitors for privilege escalation risks
type PrivilegeEscalationMonitor struct {
	graph       *Graph
	interval    time.Duration
	lastRisks   map[string][]*PrivilegeEscalationRisk
	subscribers []chan<- *PrivilegeEscalationEvent
	logger      *slog.Logger
	mu          sync.RWMutex
	stopCh      chan struct{}
	running     bool
	stopOnce    sync.Once
}

// PrivilegeEscalationEvent represents a new escalation risk
type PrivilegeEscalationEvent struct {
	Timestamp time.Time                `json:"timestamp"`
	EventType string                   `json:"event_type"` // new, resolved
	Risk      *PrivilegeEscalationRisk `json:"risk"`
}

// NewPrivilegeEscalationMonitor creates a new monitor
func NewPrivilegeEscalationMonitor(g *Graph, interval time.Duration, logger *slog.Logger) *PrivilegeEscalationMonitor {
	return &PrivilegeEscalationMonitor{
		graph:     g,
		interval:  interval,
		lastRisks: make(map[string][]*PrivilegeEscalationRisk),
		logger:    logger,
		stopCh:    make(chan struct{}),
	}
}

// Subscribe adds a channel to receive events
func (m *PrivilegeEscalationMonitor) Subscribe(ch chan<- *PrivilegeEscalationEvent) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.subscribers = append(m.subscribers, ch)
}

// Start begins continuous monitoring
func (m *PrivilegeEscalationMonitor) Start(ctx context.Context) error {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return fmt.Errorf("monitor already running")
	}
	m.running = true
	m.mu.Unlock()

	m.logger.Info("starting privilege escalation monitor", "interval", m.interval)

	// Initial scan
	m.scan()

	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			m.mu.Lock()
			m.running = false
			m.mu.Unlock()
			return ctx.Err()
		case <-m.stopCh:
			m.mu.Lock()
			m.running = false
			m.mu.Unlock()
			return nil
		case <-ticker.C:
			m.scan()
		}
	}
}

// Stop stops the monitor (safe to call multiple times)
func (m *PrivilegeEscalationMonitor) Stop() {
	m.stopOnce.Do(func() {
		close(m.stopCh)
	})
}

func (m *PrivilegeEscalationMonitor) scan() {
	start := time.Now()
	newRisks := make(map[string][]*PrivilegeEscalationRisk)

	for _, node := range m.graph.GetAllNodes() {
		if !node.IsIdentity() {
			continue
		}
		risks := DetectPrivilegeEscalationRisks(m.graph, node.ID)
		if len(risks) > 0 {
			newRisks[node.ID] = risks
		}
	}

	duration := time.Since(start)

	totalRisks := 0
	for _, risks := range newRisks {
		totalRisks += len(risks)
	}

	m.logger.Debug("privilege escalation scan complete",
		"duration", duration,
		"principals_at_risk", len(newRisks),
		"total_risks", totalRisks)

	// Compare and generate events
	events := m.compareResults(m.lastRisks, newRisks)

	m.mu.Lock()
	m.lastRisks = newRisks
	m.mu.Unlock()

	for _, event := range events {
		m.publish(event)
	}
}

func (m *PrivilegeEscalationMonitor) compareResults(old, new map[string][]*PrivilegeEscalationRisk) []*PrivilegeEscalationEvent {
	var events []*PrivilegeEscalationEvent
	now := time.Now()

	// Build lookup of old risks
	oldLookup := make(map[string]bool)
	for principalID, risks := range old {
		for _, risk := range risks {
			key := fmt.Sprintf("%s:%s", principalID, risk.EscalationPath.ID)
			oldLookup[key] = true
		}
	}

	// Find new risks
	for principalID, risks := range new {
		for _, risk := range risks {
			key := fmt.Sprintf("%s:%s", principalID, risk.EscalationPath.ID)
			if !oldLookup[key] {
				events = append(events, &PrivilegeEscalationEvent{
					Timestamp: now,
					EventType: "new",
					Risk:      risk,
				})
				m.logger.Warn("new privilege escalation risk detected",
					"principal", risk.Principal.Name,
					"path", risk.EscalationPath.Name,
					"score", risk.RiskScore)
			}
		}
	}

	return events
}

func (m *PrivilegeEscalationMonitor) publish(event *PrivilegeEscalationEvent) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, ch := range m.subscribers {
		select {
		case ch <- event:
		default:
		}
	}
}
