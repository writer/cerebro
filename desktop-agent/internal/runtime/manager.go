package runtime

import (
	"context"
	"errors"
	"log"
	"math/rand"
	"sync"
	"time"

	"github.com/WriterInternal/cerebro/desktop-agent/internal/client"
	"github.com/WriterInternal/cerebro/desktop-agent/internal/collector"
	"github.com/WriterInternal/cerebro/desktop-agent/internal/config"
	"github.com/WriterInternal/cerebro/desktop-agent/internal/pack"
	"github.com/WriterInternal/cerebro/desktop-agent/internal/types"
)

type Manager struct {
	cfg                config.Config
	httpClient         *client.Service
	logger             *log.Logger
	snapshotCollectors map[string]collector.SnapshotCollector
	eventCollectors    []collector.EventCollector
	mu                 sync.Mutex
	eventQueue         []types.HostEvent
	packLoader         pack.Loader
	scheduledTasks     []scheduledTask
}

type scheduledTask struct {
	packName string
	task     pack.Task
	nextRun  time.Time
}

func NewManager(cfg config.Config, httpClient *client.Service, logger *log.Logger) *Manager {
	return &Manager{
		cfg:                cfg,
		httpClient:         httpClient,
		logger:             logger,
		snapshotCollectors: make(map[string]collector.SnapshotCollector),
		eventCollectors:    make([]collector.EventCollector, 0),
		mu:                 sync.Mutex{},
	}
}

func (m *Manager) RegisterSnapshot(c collector.SnapshotCollector) {
	if c == nil {
		return
	}
	m.snapshotCollectors[c.Name()] = c
}

func (m *Manager) RegisterEvent(c collector.EventCollector) {
	if c == nil {
		return
	}
	m.eventCollectors = append(m.eventCollectors, c)
}

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
	if len(m.scheduledTasks) > 0 {
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
	if len(m.scheduledTasks) > 0 {
		m.runScheduledTasks(ctx)
	}
	return nil
}

func (m *Manager) collectSnapshots(ctx context.Context) error {
	for _, collector := range m.snapshotCollectors {
		telemetry, err := collector.Collect(ctx, m.cfg)
		if err != nil {
			m.logger.Printf("collector %s error: %v", collector.Name(), err)
			continue
		}
		if telemetry == nil {
			continue
		}
		if err := m.httpClient.SendSnapshot(ctx, telemetry); err != nil {
			m.logger.Printf("failed to send snapshot: %v", err)
		}
	}
	return nil
}

func (m *Manager) initializeScheduledTasks() {
	if m.cfg.PackDirectory == "" {
		return
	}
	packList, err := m.packLoader.LoadDirectory(m.cfg.PackDirectory)
	if err != nil {
		m.logger.Printf("failed to load packs: %v", err)
		return
	}
	if len(packList) == 0 {
		return
	}
	now := time.Now().UTC()
	for _, p := range packList {
		for _, task := range p.Tasks {
			interval := m.taskInterval(task)
			var jitter time.Duration
			if interval > 0 {
				jitter = time.Duration(rand.Int63n(int64(interval/2 + 1)))
			}
			scheduled := scheduledTask{
				packName: p.Name,
				task:     cloneTask(task),
				nextRun:  now.Add(jitter),
			}
			m.scheduledTasks = append(m.scheduledTasks, scheduled)
		}
	}
}

func (m *Manager) runScheduledTasks(ctx context.Context) {
	if len(m.scheduledTasks) == 0 {
		return
	}
	now := time.Now().UTC()
	for idx := range m.scheduledTasks {
		sched := &m.scheduledTasks[idx]
		if now.Before(sched.nextRun) {
			continue
		}
		collector := m.snapshotCollectors[sched.task.Collector]
		interval := m.taskInterval(sched.task)
		if collector == nil {
			m.logger.Printf(
				"artifact task %s skipped: collector %s not registered",
				sched.task.Name,
				sched.task.Collector,
			)
			sched.nextRun = now.Add(interval)
			continue
		}
		telemetry, err := collector.Collect(ctx, m.cfg)
		if err != nil {
			m.logger.Printf(
				"artifact task %s collector error: %v",
				sched.task.Name,
				err,
			)
			sched.nextRun = now.Add(interval)
			continue
		}
		if telemetry == nil {
			sched.nextRun = now.Add(interval)
			continue
		}
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
		if err := m.httpClient.SendSnapshot(ctx, telemetry); err != nil {
			m.logger.Printf(
				"artifact task %s send failed: %v",
				sched.task.Name,
				err,
			)
		}
		sched.nextRun = now.Add(interval)
	}
}

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

func cloneTask(task pack.Task) pack.Task {
	clone := task
	if task.Tags != nil {
		clone.Tags = make(map[string]string, len(task.Tags))
		for k, v := range task.Tags {
			clone.Tags[k] = v
		}
	}
	return clone
}

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

func (m *Manager) enqueueEvents(events []types.HostEvent) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.eventQueue = append(m.eventQueue, events...)
}

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

func cloneEvents(events []types.HostEvent) []types.HostEvent {
	out := make([]types.HostEvent, len(events))
	copy(out, events)
	return out
}

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
