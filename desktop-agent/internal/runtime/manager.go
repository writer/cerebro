package runtime

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"os"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/WriterInternal/cerebro/desktop-agent/internal/client"
	"github.com/WriterInternal/cerebro/desktop-agent/internal/collector"
	"github.com/WriterInternal/cerebro/desktop-agent/internal/config"
	"github.com/WriterInternal/cerebro/desktop-agent/internal/pack"
	"github.com/WriterInternal/cerebro/desktop-agent/internal/types"
)

const (
	taskSourceLocal  = "local"
	taskSourceRemote = "remote"
)

// Manager coordinates snapshot and event collectors, batching telemetry and
// handling pack scheduling. It is the central runtime orchestrator for the
// desktop agent.
type Manager struct {
	cfg                config.Config
	httpClient         *client.Service
	logger             *log.Logger
	snapshotCollectors map[string]collector.SnapshotCollector
	eventCollectors    []collector.EventCollector
	mu                 sync.Mutex
	eventQueue         []types.HostEvent
	packLoader         pack.Loader
	schedMu            sync.Mutex
	scheduledTasks     map[string]*scheduledTask
	identityMu         sync.RWMutex
	hostID             string
	hostname           string
}

// scheduledTask tracks when a pack-defined task should execute next.
type scheduledTask struct {
	source   string
	packName string
	task     pack.Task
	nextRun  time.Time
}

// NewManager constructs a runtime manager with empty collector registries.
func NewManager(cfg config.Config, httpClient *client.Service, logger *log.Logger) *Manager {
	rand.Seed(time.Now().UnixNano())
	return &Manager{
		cfg:                cfg,
		httpClient:         httpClient,
		logger:             logger,
		snapshotCollectors: make(map[string]collector.SnapshotCollector),
		eventCollectors:    make([]collector.EventCollector, 0),
		mu:                 sync.Mutex{},
		schedMu:            sync.Mutex{},
		scheduledTasks:     make(map[string]*scheduledTask),
	}
}

// RegisterSnapshot makes a snapshot collector available for fan-out when the
// manager executes its collection loop.
func (m *Manager) RegisterSnapshot(c collector.SnapshotCollector) {
	if c == nil {
		return
	}
	m.snapshotCollectors[c.Name()] = c
}

// RegisterEvent appends an event collector whose deltas will be buffered and
// flushed to the backend.
func (m *Manager) RegisterEvent(c collector.EventCollector) {
	if c == nil {
		return
	}
	m.eventCollectors = append(m.eventCollectors, c)
}

// Run launches the continuous collection loop, driving snapshots, events, and
// scheduled artifact pack tasks until the context is cancelled.
func (m *Manager) Run(ctx context.Context) error {
	if len(m.snapshotCollectors) == 0 && len(m.eventCollectors) == 0 {
		return errors.New("no collectors registered")
	}

	if len(m.eventCollectors) > 0 && m.cfg.EventFlushInterval <= 0 {
		m.cfg.EventFlushInterval = time.Minute
	}
	if len(m.eventCollectors) > 0 && m.cfg.EventBatchSize <= 0 {
		m.cfg.EventBatchSize = 100
	}

	m.initializeScheduledTasks()

	if len(m.snapshotCollectors) > 0 {
		if err := m.collectSnapshots(ctx); err != nil {
			m.logger.Printf("snapshot collection failed: %v", err)
		}
	}
	if len(m.eventCollectors) > 0 {
		if err := m.collectEvents(ctx); err != nil {
			m.logger.Printf("event collection failed: %v", err)
		}
		m.flushEvents(ctx, true)
	}

	if m.cfg.ArtifactPollInterval > 0 {
		go m.pollRemotePacks(ctx)
	}

	snapshotTicker := time.NewTicker(m.cfg.Interval)
	defer snapshotTicker.Stop()

	var eventTicker *time.Ticker
	var eventC <-chan time.Time
	if len(m.eventCollectors) > 0 {
		eventTicker = time.NewTicker(m.cfg.EventFlushInterval)
		eventC = eventTicker.C
		defer eventTicker.Stop()
	}

	var packTicker *time.Ticker
	var packC <-chan time.Time
	if m.cfg.PackDirectory != "" || m.cfg.ArtifactPollInterval > 0 {
		packTicker = time.NewTicker(5 * time.Second)
		packC = packTicker.C
		defer packTicker.Stop()
	}

	for {
		select {
		case <-ctx.Done():
			m.flushEvents(ctx, true)
			return nil
		case <-snapshotTicker.C:
			if len(m.snapshotCollectors) == 0 {
				continue
			}
			if err := m.collectSnapshots(ctx); err != nil {
				m.logger.Printf("snapshot collection failed: %v", err)
			}
		case <-eventC:
			if err := m.collectEvents(ctx); err != nil {
				m.logger.Printf("event collection failed: %v", err)
			}
			m.flushEvents(ctx, false)
		case <-packC:
			m.runScheduledTasks(ctx)
		}
	}
}

// RunOnce executes a single iteration of the collection loop. It is primarily
// used by tests or one-shot diagnostics.
func (m *Manager) RunOnce(ctx context.Context) error {
	if len(m.snapshotCollectors) == 0 && len(m.eventCollectors) == 0 {
		return errors.New("no collectors registered")
	}
	m.initializeScheduledTasks()
	if len(m.snapshotCollectors) > 0 {
		if err := m.collectSnapshots(ctx); err != nil {
			m.logger.Printf("snapshot collection failed: %v", err)
		}
	}
	if len(m.eventCollectors) > 0 {
		if err := m.collectEvents(ctx); err != nil {
			return err
		}
		m.flushEvents(ctx, true)
	}
	if m.cfg.ArtifactPollInterval > 0 {
		if err := m.refreshRemotePacks(ctx); err != nil {
			m.logger.Printf("artifact pack refresh failed: %v", err)
		}
	}
	m.runScheduledTasks(ctx)
	return nil
}

// collectSnapshots invokes each registered snapshot collector, updates the
// manager's cached host identity, and forwards the resulting payloads to the
// Cerebro API.
func (m *Manager) collectSnapshots(ctx context.Context) error {
	for _, collector := range m.snapshotCollectors {
		telemetry, err := collector.Collect(ctx, m.cfg, nil)
		if err != nil {
			m.logger.Printf("collector %s error: %v", collector.Name(), err)
			continue
		}
		if telemetry == nil {
			continue
		}
		m.identityMu.Lock()
		m.hostID = telemetry.HostID
		m.hostname = telemetry.Hostname
		m.identityMu.Unlock()
		if err := m.httpClient.SendSnapshot(ctx, telemetry); err != nil {
			m.logger.Printf("failed to send snapshot: %v", err)
		}
	}
	return nil
}

// initializeScheduledTasks loads pack definitions from disk so the scheduler
// can execute local artifact tasks. Missing directories are tolerated to make
// local development workflows smoother.
func (m *Manager) initializeScheduledTasks() {
	if m.cfg.PackDirectory == "" {
		return
	}
	packList, err := m.packLoader.LoadDirectory(m.cfg.PackDirectory)
	if err != nil {
		m.logger.Printf("failed to load packs: %v", err)
		return
	}
	m.syncSourceTasks(taskSourceLocal, packList)
}

// runScheduledTasks executes any pack tasks that are due, clones their config
// to avoid mutation, and pushes the next run forward with jitter to prevent
// herd behaviour.
func (m *Manager) runScheduledTasks(ctx context.Context) {
	m.schedMu.Lock()
	if len(m.scheduledTasks) == 0 {
		m.schedMu.Unlock()
		return
	}
	now := time.Now().UTC()
	due := make([]scheduledTask, 0)
	for _, sched := range m.scheduledTasks {
		if now.Before(sched.nextRun) {
			continue
		}
		interval := m.taskInterval(sched.task)
		sched.nextRun = now.Add(interval)
		due = append(due, scheduledTask{
			source:   sched.source,
			packName: sched.packName,
			task:     cloneTask(sched.task),
			nextRun:  sched.nextRun,
		})
	}
	m.schedMu.Unlock()

	for _, sched := range due {
		if !m.taskEligible(ctx, sched) {
			continue
		}
		collector := m.snapshotCollectors[sched.task.Collector]
		if collector == nil {
			m.logger.Printf(
				"artifact task %s skipped: collector %s not registered",
				sched.task.Name,
				sched.task.Collector,
			)
			continue
		}
		params := buildTaskParameters(sched.task)
		telemetry, err := collector.Collect(ctx, m.cfg, params)
		if err != nil {
			m.logger.Printf(
				"artifact task %s collector error: %v",
				sched.task.Name,
				err,
			)
			continue
		}
		if telemetry == nil {
			continue
		}
		tagTelemetryWithTask(telemetry, sched)
		if err := m.httpClient.SendSnapshot(ctx, telemetry); err != nil {
			m.logger.Printf(
				"artifact task %s send failed: %v",
				sched.task.Name,
				err,
			)
		}
	}
}

// taskInterval resolves the execution cadence for a scheduled artifact task.
// Pack-level overrides win, then agent config, followed by a safe default.
func (m *Manager) taskInterval(task pack.Task) time.Duration {
	interval := task.Interval.Duration
	if interval <= 0 {
		interval = m.cfg.Interval
	}
	if interval <= 0 {
		interval = time.Minute
	}
	return interval
}

// cloneTask deep copies mutable fields on the task so scheduler mutations do
// not bleed back into the original pack definition.
func cloneTask(task pack.Task) pack.Task {
	clone := task
	if task.Tags != nil {
		clone.Tags = make(map[string]string, len(task.Tags))
		for k, v := range task.Tags {
			clone.Tags[k] = v
		}
	}
	if task.Config != nil {
		clone.Config = make(map[string]any, len(task.Config))
		for k, v := range task.Config {
			clone.Config[k] = v
		}
	}
	if task.ParameterValues != nil {
		clone.ParameterValues = make(map[string]any, len(task.ParameterValues))
		for k, v := range task.ParameterValues {
			clone.ParameterValues[k] = v
		}
	}
	if len(task.Discovery) > 0 {
		clone.Discovery = append([]string(nil), task.Discovery...)
	}
	if len(task.Parameters) > 0 {
		clone.Parameters = append([]types.ArtifactTaskParameter(nil), task.Parameters...)
	}
	if task.Resources != nil {
		res := *task.Resources
		clone.Resources = &res
	}
	if len(task.Tools) > 0 {
		clone.Tools = append([]types.ArtifactTool(nil), task.Tools...)
	}
	return clone
}

// syncSourceTasks merges scheduled tasks for a particular source (local or
// remote) and prunes missing entries so the scheduler stays in sync.
func (m *Manager) syncSourceTasks(source string, packs []pack.Pack) {
	now := time.Now().UTC()
	active := make(map[string]struct{})

	m.schedMu.Lock()
	for _, p := range packs {
		packName := p.Name
		if packName == "" {
			packName = "unnamed"
		}
		for _, task := range p.Tasks {
			key := scheduleKey(source, packName, task.Name)
			active[key] = struct{}{}
			interval := m.taskInterval(task)
			if existing, ok := m.scheduledTasks[key]; ok {
				existing.task = cloneTask(task)
				if existing.nextRun.IsZero() {
					existing.nextRun = now.Add(m.jitter(interval))
				}
				continue
			}
			m.scheduledTasks[key] = &scheduledTask{
				source:   source,
				packName: packName,
				task:     cloneTask(task),
				nextRun:  now.Add(m.jitter(interval)),
			}
		}
	}
	for key, sched := range m.scheduledTasks {
		if sched.source != source {
			continue
		}
		if _, ok := active[key]; !ok {
			delete(m.scheduledTasks, key)
		}
	}
	m.schedMu.Unlock()
}

// scheduleKey builds a stable map key for scheduled tasks.
func scheduleKey(source, packName, taskName string) string {
	return fmt.Sprintf("%s:%s:%s", source, packName, taskName)
}

// jitter applies up to 50% randomisation to avoid herd effects when many
// agents execute the same schedule simultaneously.
func (m *Manager) jitter(interval time.Duration) time.Duration {
	if interval <= 0 {
		return 0
	}
	max := interval / 2
	if max <= 0 {
		return 0
	}
	return time.Duration(rand.Int63n(int64(max) + 1))
}

// tagTelemetryWithTask annotates collected telemetry with pack/task metadata so
// the backend can attribute results to their source.
func tagTelemetryWithTask(telemetry *types.HostTelemetry, sched scheduledTask) {
	if telemetry.Tags == nil {
		telemetry.Tags = make(map[string]string)
	}
	for k, v := range sched.task.Tags {
		telemetry.Tags[k] = v
	}
	if sched.packName != "" {
		if _, exists := telemetry.Tags["pack"]; !exists {
			telemetry.Tags["pack"] = sched.packName
		}
	}
	if sched.task.Name != "" {
		telemetry.Tags["task"] = sched.task.Name
	}
	telemetry.Tags["pack_source"] = sched.source
	if sched.task.Resources != nil {
		if sched.task.Resources.TimeoutSeconds > 0 {
			telemetry.Tags["pack_timeout_seconds"] = fmt.Sprintf("%d", sched.task.Resources.TimeoutSeconds)
		}
		if sched.task.Resources.MaxRows > 0 {
			telemetry.Tags["pack_max_rows"] = fmt.Sprintf("%d", sched.task.Resources.MaxRows)
		}
	}
}

// pollRemotePacks periodically fetches remote artifact packs from the control
// plane and merges them into the scheduler state.
func (m *Manager) pollRemotePacks(ctx context.Context) {
	if m.cfg.ArtifactPollInterval <= 0 {
		return
	}
	if err := m.refreshRemotePacks(ctx); err != nil {
		m.logger.Printf("artifact pack refresh failed: %v", err)
	}
	ticker := time.NewTicker(m.cfg.ArtifactPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := m.refreshRemotePacks(ctx); err != nil {
				m.logger.Printf("artifact pack refresh failed: %v", err)
			}
		}
	}
}

// refreshRemotePacks retrieves remote packs once and updates the in-memory
// schedule. It is invoked both on startup and on each polling interval.
func (m *Manager) refreshRemotePacks(ctx context.Context) error {
	m.identityMu.RLock()
	hostID := m.hostID
	hostname := m.hostname
	m.identityMu.RUnlock()

	if hostID == "" {
		return nil
	}

	packs, err := m.httpClient.FetchArtifactPacks(ctx, hostID, hostname, m.cfg.Tags)
	if err != nil {
		return err
	}

	converted := make([]pack.Pack, 0, len(packs))
	for _, definition := range packs {
		converted = append(converted, packFromDefinition(definition))
	}

	m.syncSourceTasks(taskSourceRemote, converted)
	return nil
}

// packFromDefinition converts an API artifact pack into the internal runtime
// representation understood by the scheduler.
func packFromDefinition(def types.ArtifactPackDefinition) pack.Pack {
	tasks := make([]pack.Task, 0, len(def.Tasks))
	for _, task := range def.Tasks {
		tasks = append(tasks, pack.Task{
			Name:            task.Name,
			Collector:       task.Collector,
			Interval:        pack.Duration{Duration: time.Duration(task.IntervalSeconds) * time.Second},
			Tags:            cloneStringMap(task.Tags),
			Config:          cloneAnyMap(task.Config),
			Discovery:       append([]string(nil), task.Discovery...),
			Parameters:      append([]types.ArtifactTaskParameter(nil), task.Parameters...),
			ParameterValues: cloneAnyMap(task.ParameterValues),
			Resources:       cloneResources(task.Resources),
			Tools:           append([]types.ArtifactTool(nil), task.Tools...),
		})
	}

	return pack.Pack{
		Name:        def.Name,
		Version:     def.Version,
		Description: def.Description,
		Selectors:   cloneSelectorMap(def.Selectors),
		Tasks:       tasks,
	}
}

// cloneStringMap deep copies a string map so scheduler mutations do not leak
// back into the artifact pack definition.
func cloneStringMap(input map[string]string) map[string]string {
	if input == nil {
		return nil
	}
	out := make(map[string]string, len(input))
	for k, v := range input {
		out[k] = v
	}
	return out
}

// cloneAnyMap duplicates a map[string]any, handling nil inputs gracefully.
func cloneAnyMap(input map[string]any) map[string]any {
	if input == nil {
		return nil
	}
	out := make(map[string]any, len(input))
	for k, v := range input {
		out[k] = v
	}
	return out
}

// cloneResources copies the optional resources struct attached to a task.
func cloneResources(input *types.ArtifactTaskResources) *types.ArtifactTaskResources {
	if input == nil {
		return nil
	}
	res := *input
	return &res
}

// cloneSelectorMap copies the selectors map associated with a pack.
func cloneSelectorMap(input map[string]any) map[string]any {
	if input == nil {
		return nil
	}
	out := make(map[string]any, len(input))
	for k, v := range input {
		out[k] = v
	}
	return out
}

// buildTaskParameters merges static collector config, explicit parameter
// values, and defaults in that precedence order before handing them to the
// snapshot collector.
func buildTaskParameters(task pack.Task) map[string]any {
	if len(task.Config) == 0 && len(task.ParameterValues) == 0 && len(task.Parameters) == 0 {
		return nil
	}
	merged := make(map[string]any)
	for k, v := range task.Config {
		merged[k] = v
	}
	for k, v := range task.ParameterValues {
		merged[k] = v
	}
	for _, param := range task.Parameters {
		if param.Name == "" {
			continue
		}
		if _, exists := merged[param.Name]; !exists && param.Default != nil {
			merged[param.Name] = param.Default
		}
	}
	return merged
}

// taskEligible evaluates discovery clauses to decide whether the task should
// execute on the current host.
func (m *Manager) taskEligible(_ context.Context, sched scheduledTask) bool {
	if len(sched.task.Discovery) == 0 {
		return true
	}
	tags := m.cfg.Tags
	site := m.cfg.Site
	org := m.cfg.Organization
	_, hostname := m.currentIdentity()
	if hostname == "" {
		if override := m.cfg.HostnameOverride; override != "" {
			hostname = override
		} else if hn, err := os.Hostname(); err == nil {
			hostname = hn
		}
	}

	for _, clause := range sched.task.Discovery {
		clause = strings.TrimSpace(clause)
		if clause == "" {
			continue
		}
		if !m.evaluateDiscoveryClause(clause, tags, site, org, hostname) {
			return false
		}
	}
	return true
}

// evaluateDiscoveryClause checks a single discovery expression (e.g.,
// "tag:env=prod", "!site:corp", "hostname~^corp", "collector:snapshot.basic")
// against the current host metadata. Clauses may be negated with a leading !
// and support regex matches for hostnames.
func (m *Manager) evaluateDiscoveryClause(
	clause string,
	tags map[string]string,
	site string,
	org string,
	hostname string,
) bool {
	negate := false
	if strings.HasPrefix(clause, "!") {
		negate = true
		clause = strings.TrimSpace(clause[1:])
	}

	if clause == "" {
		return !negate
	}

	lower := strings.ToLower(clause)
	var matched bool

	switch {
	case strings.HasPrefix(lower, "tag:"):
		keyValue := clause[len("tag:"):]
		matched = matchTagClause(keyValue, tags)
	case strings.HasPrefix(lower, "os:"):
		expected := strings.TrimSpace(clause[len("os:"):])
		matched = expected == "" || strings.EqualFold(expected, runtime.GOOS)
	case strings.HasPrefix(lower, "site:"):
		expected := strings.TrimSpace(clause[len("site:"):])
		matched = expected == "" || strings.EqualFold(expected, site)
	case strings.HasPrefix(lower, "org:"):
		expected := strings.TrimSpace(clause[len("org:"):])
		matched = expected == "" || strings.EqualFold(expected, org)
	case strings.HasPrefix(lower, "hostname~"):
		pattern := clause[len("hostname~"):]
		if re, err := regexp.Compile(pattern); err == nil {
			matched = re.MatchString(hostname)
		}
	case strings.HasPrefix(lower, "hostname:"):
		expected := strings.TrimSpace(clause[len("hostname:"):])
		matched = expected == "" || strings.EqualFold(expected, hostname)
	case strings.HasPrefix(lower, "collector:"):
		collectorName := strings.TrimSpace(clause[len("collector:"):])
		_, matched = m.snapshotCollectors[collectorName]
	default:
		matched = matchTagClause(clause, tags)
	}

	if negate {
		return !matched
	}
	return matched
}

// matchTagClause resolves tag equality expressions used in discovery clauses.
// A bare key checks for presence, while key=value enforces an exact match.
func matchTagClause(clause string, tags map[string]string) bool {
	key := clause
	value := ""
	if parts := strings.SplitN(clause, "=", 2); len(parts) > 0 {
		key = parts[0]
		if len(parts) == 2 {
			value = parts[1]
		}
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return false
	}
	actual := ""
	if tags != nil {
		actual = tags[key]
	}
	if value == "" {
		return actual != ""
	}
	return actual == value
}

// currentIdentity returns the last snapshot's host identifier and hostname.
// A read lock ensures collectors can query identity concurrently with updates
// from fresh snapshots.
func (m *Manager) currentIdentity() (string, string) {
	m.identityMu.RLock()
	defer m.identityMu.RUnlock()
	return m.hostID, m.hostname
}

// collectEvents polls each registered event collector, adds results to the
// queue, and triggers an immediate flush if the batch size threshold is hit.
func (m *Manager) collectEvents(ctx context.Context) error {
	for _, collector := range m.eventCollectors {
		events, err := collector.Collect(ctx, m.cfg)
		if err != nil {
			m.logger.Printf("event collector %s error: %v", collector.Name(), err)
			continue
		}
		if len(events) == 0 {
			continue
		}
		m.enqueueEvents(events)
		if len(m.eventQueue) >= m.cfg.EventBatchSize {
			m.flushEvents(ctx, false)
		}
	}
	return nil
}

// enqueueEvents appends events to the in-memory queue while respecting the
// configured batch size. A mutex guards the queue so snapshot collection can
// run concurrently without data races.
func (m *Manager) enqueueEvents(events []types.HostEvent) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.eventQueue = append(m.eventQueue, events...)
}

// flushEvents ships buffered events to the Cerebro API. When force is true
// (e.g. during shutdown) the queue is drained even if it is below the batch
// size threshold.
func (m *Manager) flushEvents(ctx context.Context, force bool) {
	m.mu.Lock()
	if len(m.eventQueue) == 0 {
		m.mu.Unlock()
		return
	}
	queued := cloneEvents(m.eventQueue)
	m.eventQueue = m.eventQueue[:0]
	m.mu.Unlock()

	batches := buildEventBatches(queued, m.cfg.AgentVersion, m.cfg.EventBatchSize, m.cfg.Organization, m.cfg.Site)
	failed := make([]types.HostEvent, 0)
	for _, batch := range batches {
		if len(batch.Events) == 0 {
			continue
		}
		if err := m.httpClient.SendEvents(ctx, batch); err != nil {
			m.logger.Printf("failed to send events batch: %v", err)
			failed = append(failed, batch.Events...)
		}
	}

	if len(failed) > 0 && !force {
		m.enqueueEvents(failed)
	}
}

// cloneEvents copies the slice to avoid sharing backing arrays when batches
// are chunked for transport or retried.
func cloneEvents(events []types.HostEvent) []types.HostEvent {
	out := make([]types.HostEvent, len(events))
	copy(out, events)
	return out
}

// buildEventBatches groups events by host id, chunks them according to the
// configured batch size, and stamps common metadata (organization, site,
// agent version, collection timestamp) so the backend can ingest them directly.
func buildEventBatches(events []types.HostEvent, agentVersion string, maxSize int, organization string, site string) []types.HostEventBatch {
	if len(events) == 0 {
		return nil
	}
	if maxSize <= 0 {
		maxSize = len(events)
	}

	table := make(map[string][]types.HostEvent)
	hostnames := make(map[string]string)
	for _, event := range events {
		key := event.HostID
		table[key] = append(table[key], event)
		if event.Hostname != "" {
			hostnames[key] = event.Hostname
		}
	}

	result := make([]types.HostEventBatch, 0)
	for hostID, list := range table {
		for i := 0; i < len(list); i += maxSize {
			end := i + maxSize
			if end > len(list) {
				end = len(list)
			}
			batch := types.HostEventBatch{
				HostID:       hostID,
				Hostname:     hostnames[hostID],
				Organization: organization,
				Site:         site,
				AgentVersion: agentVersion,
				CollectedAt:  time.Now().UTC(),
				Events:       cloneEvents(list[i:end]),
			}
			result = append(result, batch)
		}
	}
	return result
}
