package app

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/writer/cerebro/internal/cerrors"
	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/health"
	"github.com/writer/cerebro/internal/metrics"
)

const (
	defaultGraphWriterLeaseBucket = "CEREBRO_GRAPH_LEASES"
	defaultGraphWriterLeaseName   = "security_graph_writer"
)

type GraphWriterRole string

const (
	GraphWriterRoleDisabled GraphWriterRole = "disabled"
	GraphWriterRoleWriter   GraphWriterRole = "writer"
	GraphWriterRoleFollower GraphWriterRole = "follower"
)

type GraphWriterLeaseStatus struct {
	Enabled          bool            `json:"enabled"`
	Role             GraphWriterRole `json:"role"`
	LeaseName        string          `json:"lease_name,omitempty"`
	OwnerID          string          `json:"owner_id,omitempty"`
	LeaseHolderID    string          `json:"lease_holder_id,omitempty"`
	LeaseUntil       time.Time       `json:"lease_until,omitempty"`
	LastHeartbeatAt  time.Time       `json:"last_heartbeat_at,omitempty"`
	LastTransitionAt time.Time       `json:"last_transition_at,omitempty"`
	LastError        string          `json:"last_error,omitempty"`
}

type graphWriterLeaseSnapshot struct {
	Name       string    `json:"name"`
	OwnerID    string    `json:"owner_id"`
	LeaseUntil time.Time `json:"lease_until"`
	RenewedAt  time.Time `json:"renewed_at"`
	Revision   uint64    `json:"revision,omitempty"`
}

func (s graphWriterLeaseSnapshot) active(now time.Time) bool {
	return !s.LeaseUntil.IsZero() && s.LeaseUntil.After(now)
}

type graphWriterLeaseStore interface {
	TryAcquire(ctx context.Context, name, ownerID string, ttl time.Duration, now time.Time) (graphWriterLeaseSnapshot, bool, error)
	Renew(ctx context.Context, name, ownerID string, ttl time.Duration, now time.Time) (graphWriterLeaseSnapshot, bool, error)
	Current(ctx context.Context, name string, now time.Time) (graphWriterLeaseSnapshot, error)
	Release(ctx context.Context, name, ownerID string) error
	Close() error
}

type graphWriterLeaseCallbacks struct {
	onAcquire func(context.Context)
	onLose    func(context.Context)
}

type graphWriterLeaseCallbackEvent struct {
	ctx context.Context
	fn  func(context.Context)
}

type graphWriterLeaseManager struct {
	logger    *slog.Logger
	store     graphWriterLeaseStore
	leaseName string
	ownerID   string
	ttl       time.Duration
	heartbeat time.Duration
	callback  graphWriterLeaseCallbacks

	mu     sync.RWMutex
	status GraphWriterLeaseStatus

	callbackQueue chan graphWriterLeaseCallbackEvent
	callbackStop  chan struct{}
	callbackWG    sync.WaitGroup

	loopCancel context.CancelFunc
	loopWG     sync.WaitGroup
}

func defaultGraphWriterLeaseOwnerID() string {
	hostname, err := os.Hostname()
	if err != nil || strings.TrimSpace(hostname) == "" {
		hostname = "unknown-host"
	}
	return fmt.Sprintf("%s:%d", strings.TrimSpace(hostname), os.Getpid())
}

func newGraphWriterLeaseManager(logger *slog.Logger, store graphWriterLeaseStore, leaseName, ownerID string, ttl, heartbeat time.Duration, callback graphWriterLeaseCallbacks) *graphWriterLeaseManager {
	status := GraphWriterLeaseStatus{
		Enabled:   true,
		Role:      GraphWriterRoleFollower,
		LeaseName: strings.TrimSpace(leaseName),
		OwnerID:   strings.TrimSpace(ownerID),
	}
	if logger == nil {
		logger = slog.Default()
	}
	manager := &graphWriterLeaseManager{
		logger:        logger,
		store:         store,
		leaseName:     strings.TrimSpace(leaseName),
		ownerID:       strings.TrimSpace(ownerID),
		ttl:           ttl,
		heartbeat:     heartbeat,
		callback:      callback,
		status:        status,
		callbackQueue: make(chan graphWriterLeaseCallbackEvent, 8),
		callbackStop:  make(chan struct{}),
	}
	manager.startCallbackLoop()
	return manager
}

func (m *graphWriterLeaseManager) startCallbackLoop() {
	if m == nil {
		return
	}
	m.callbackWG.Add(1)
	go func() {
		defer m.callbackWG.Done()
		for {
			select {
			case <-m.callbackStop:
				return
			case event := <-m.callbackQueue:
				if event.fn != nil {
					event.fn(event.ctx)
				}
			}
		}
	}()
}

func (m *graphWriterLeaseManager) enqueueCallback(ctx context.Context, fn func(context.Context)) {
	if m == nil || fn == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	event := graphWriterLeaseCallbackEvent{ctx: ctx, fn: fn}
	select {
	case <-m.callbackStop:
		return
	case m.callbackQueue <- event:
	}
}

func (m *graphWriterLeaseManager) start(ctx context.Context) {
	if m == nil {
		return
	}
	loopCtx, cancel := context.WithCancel(backgroundWorkContext(ctx))
	m.mu.Lock()
	if m.loopCancel != nil {
		m.mu.Unlock()
		cancel()
		return
	}
	m.loopCancel = cancel
	m.mu.Unlock()

	m.loopWG.Add(1)
	go func() {
		defer m.loopWG.Done()
		ticker := time.NewTicker(m.heartbeat)
		defer ticker.Stop()
		for {
			select {
			case <-loopCtx.Done():
				return
			case <-ticker.C:
				if err := m.sync(loopCtx); err != nil && m.logger != nil {
					m.logger.Warn("graph writer lease heartbeat failed", "lease", m.leaseName, "owner", m.ownerID, "error", err)
				}
			}
		}
	}()
}

func (m *graphWriterLeaseManager) stop(ctx context.Context) error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	cancel := m.loopCancel
	m.loopCancel = nil
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	m.loopWG.Wait()
	select {
	case <-m.callbackStop:
	default:
		close(m.callbackStop)
	}
	m.callbackWG.Wait()

	if ctx == nil {
		ctx = context.Background()
	}
	if m.isWriter() {
		if err := m.store.Release(ctx, m.leaseName, m.ownerID); err != nil && m.logger != nil {
			m.logger.Warn("failed to release graph writer lease", "lease", m.leaseName, "owner", m.ownerID, "error", err)
		}
	}
	if m.store != nil {
		return m.store.Close()
	}
	return nil
}

func (m *graphWriterLeaseManager) sync(ctx context.Context) error {
	if m == nil || m.store == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	now := time.Now().UTC()
	wasWriter := m.isWriter()

	var (
		snapshot graphWriterLeaseSnapshot
		writer   bool
		err      error
	)
	if wasWriter {
		snapshot, writer, err = m.store.Renew(ctx, m.leaseName, m.ownerID, m.ttl, now)
	} else {
		snapshot, writer, err = m.store.TryAcquire(ctx, m.leaseName, m.ownerID, m.ttl, now)
	}
	if err != nil {
		snapshot, _ = m.store.Current(ctx, m.leaseName, now)
	}

	acquired, lost := m.updateStatus(now, snapshot, writer, err)
	if err != nil {
		return err
	}
	if acquired && m.callback.onAcquire != nil {
		m.enqueueCallback(ctx, m.callback.onAcquire)
	}
	if lost && m.callback.onLose != nil {
		m.enqueueCallback(ctx, m.callback.onLose)
	}
	return nil
}

func (m *graphWriterLeaseManager) updateStatus(now time.Time, snapshot graphWriterLeaseSnapshot, writer bool, syncErr error) (acquired, lost bool) {
	if m == nil {
		return false, false
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	prevRole := m.status.Role
	m.status.Enabled = true
	m.status.LeaseName = m.leaseName
	m.status.OwnerID = m.ownerID
	m.status.LeaseUntil = snapshot.LeaseUntil
	m.status.LastHeartbeatAt = now
	if syncErr != nil {
		m.status.LastError = strings.TrimSpace(syncErr.Error())
	} else {
		m.status.LastError = ""
	}

	holderID := ""
	if snapshot.active(now) {
		holderID = strings.TrimSpace(snapshot.OwnerID)
	}
	m.status.LeaseHolderID = holderID

	if writer {
		m.status.Role = GraphWriterRoleWriter
		m.status.LeaseHolderID = m.ownerID
	} else {
		m.status.Role = GraphWriterRoleFollower
	}

	if prevRole != m.status.Role {
		m.status.LastTransitionAt = now
	}
	acquired = prevRole != GraphWriterRoleWriter && m.status.Role == GraphWriterRoleWriter
	lost = prevRole == GraphWriterRoleWriter && m.status.Role != GraphWriterRoleWriter
	metrics.SetGraphWriterLeaseState(m.status.Role == GraphWriterRoleWriter, m.status.LeaseUntil, now)
	return acquired, lost
}

func (m *graphWriterLeaseManager) isWriter() bool {
	if m == nil {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.status.Role == GraphWriterRoleWriter
}

func (m *graphWriterLeaseManager) snapshot() GraphWriterLeaseStatus {
	if m == nil {
		return GraphWriterLeaseStatus{Role: GraphWriterRoleDisabled}
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.status
}

func (a *App) initGraphWriterLease(ctx context.Context) error {
	if a == nil || a.Config == nil {
		return nil
	}
	metrics.SetGraphWriterLeaseState(false, time.Time{}, time.Now().UTC())
	if !a.Config.GraphWriterLeaseEnabled {
		return nil
	}
	store, err := newNATSGraphWriterLeaseStore(a.Config)
	if err != nil {
		return err
	}
	manager := newGraphWriterLeaseManager(a.Logger, store, a.Config.GraphWriterLeaseName, a.Config.GraphWriterLeaseOwnerID, a.Config.GraphWriterLeaseTTL, a.Config.GraphWriterLeaseHeartbeat, graphWriterLeaseCallbacks{
		onAcquire: a.handleGraphWriterLeaseAcquired,
		onLose:    a.handleGraphWriterLeaseLost,
	})
	a.graphWriterLease = manager
	if err := manager.sync(ctx); err != nil {
		a.graphWriterLease = nil
		_ = manager.stop(ctx)
		return err
	}
	manager.start(ctx)
	if a.Logger != nil {
		a.Logger.Info("graph writer lease enabled",
			"lease", a.Config.GraphWriterLeaseName,
			"owner", a.Config.GraphWriterLeaseOwnerID,
			"ttl", a.Config.GraphWriterLeaseTTL,
			"heartbeat", a.Config.GraphWriterLeaseHeartbeat,
			"role", manager.snapshot().Role,
		)
	}
	return nil
}

func (a *App) stopGraphWriterLeaseLoop() {
	if a == nil || a.graphWriterLease == nil {
		return
	}
	if err := a.graphWriterLease.stop(context.Background()); err != nil && a.Logger != nil {
		a.Logger.Warn("failed to stop graph writer lease loop", "error", err)
	}
	a.graphWriterLease = nil
	metrics.SetGraphWriterLeaseState(false, time.Time{}, time.Now().UTC())
}

func (a *App) GraphWriterLeaseStatusSnapshot() GraphWriterLeaseStatus {
	if a == nil || a.graphWriterLease == nil {
		return GraphWriterLeaseStatus{Enabled: false, Role: GraphWriterRoleDisabled}
	}
	return a.graphWriterLease.snapshot()
}

func (a *App) graphWriterLeaseAllowsWrites() bool {
	if a == nil || a.Config == nil || !a.Config.GraphWriterLeaseEnabled {
		return true
	}
	if a.graphWriterLease == nil {
		return false
	}
	return a.graphWriterLease.isWriter()
}

func (a *App) requireGraphWriterLease(op string) error {
	if a == nil || a.Config == nil || !a.Config.GraphWriterLeaseEnabled {
		return nil
	}
	status := a.GraphWriterLeaseStatusSnapshot()
	if status.Role == GraphWriterRoleWriter {
		return nil
	}
	message := "graph writer lease not held by this process"
	if op != "" {
		message = op + ": " + message
	}
	return cerrors.E(cerrors.Op("graph_writer_lease"), cerrors.ErrForbidden, message)
}

func (a *App) graphReadyClosed() bool {
	if a == nil || a.graphReady == nil {
		return false
	}
	select {
	case <-a.graphReady:
		return true
	default:
		return false
	}
}

func (a *App) handleGraphWriterLeaseAcquired(ctx context.Context) {
	if a == nil || a.SecurityGraphBuilder == nil || !a.graphReadyClosed() {
		return
	}
	a.graphWriterLeaseTransitionWG.Add(1)
	go func() {
		defer a.graphWriterLeaseTransitionWG.Done()
		promotionCtx := withoutGraphReplicaReplay(backgroundWorkContext(ctx))
		if err := a.promoteOrRebuildSecurityGraph(promotionCtx); err != nil {
			if a.Logger != nil {
				a.Logger.Warn("graph writer promotion failed", "error", err)
			}
			return
		}
		a.startTapGraphConsumer(promotionCtx)
	}()
}

func (a *App) promoteOrRebuildSecurityGraph(ctx context.Context) error {
	if current := a.CurrentSecurityGraph(); current != nil && current.NodeCount() > 0 {
		meta, promoted, err := func() (graph.Metadata, bool, error) {
			a.graphUpdateMu.Lock()
			defer a.graphUpdateMu.Unlock()

			current = a.CurrentSecurityGraph()
			if current == nil || current.NodeCount() == 0 {
				return graph.Metadata{}, false, nil
			}

			meta, err := a.activateBuiltSecurityGraph(ctx, current.Clone())
			if err != nil {
				return graph.Metadata{}, false, err
			}
			return meta, true, nil
		}()
		if err != nil {
			return err
		}
		if promoted {
			a.emitGraphRebuiltEvent(ctx, meta, 0)
			a.emitGraphMutationEvent(ctx, graph.GraphMutationSummary{
				Mode:      graph.GraphMutationModeFullRebuild,
				Since:     meta.BuiltAt,
				Until:     meta.BuiltAt,
				NodeCount: meta.NodeCount,
				EdgeCount: meta.EdgeCount,
			}, "lease_promotion")
			return nil
		}
	}
	return a.RebuildSecurityGraph(ctx)
}

func (a *App) handleGraphWriterLeaseLost(ctx context.Context) {
	if a == nil || a.Config == nil || !a.Config.NATSConsumerEnabled {
		return
	}
	a.startTapGraphConsumer(backgroundWorkContext(ctx))
	if a.Logger != nil {
		a.Logger.Info("graph writer lease lost; continuing tap consumer in follower replica mode",
			"lease", a.Config.GraphWriterLeaseName,
			"holder", a.GraphWriterLeaseStatusSnapshot().LeaseHolderID,
		)
	}
}

func (a *App) graphWriterLeaseHealthCheck() health.Checker {
	return func(_ context.Context) health.CheckResult {
		start := time.Now().UTC()
		result := health.CheckResult{
			Name:      "graph_writer_lease",
			Timestamp: start,
		}
		status := a.GraphWriterLeaseStatusSnapshot()
		switch {
		case !status.Enabled:
			result.Status = health.StatusHealthy
			result.Message = "graph writer lease disabled"
		case status.Role == GraphWriterRoleWriter:
			result.Status = health.StatusHealthy
			result.Message = "graph writer lease held locally"
		case strings.TrimSpace(status.LastError) != "":
			result.Status = health.StatusDegraded
			result.Message = "graph writer lease unavailable"
		case strings.TrimSpace(status.LeaseHolderID) != "":
			result.Status = health.StatusHealthy
			result.Message = "graph writer lease held remotely"
		default:
			result.Status = health.StatusDegraded
			result.Message = "graph writer lease not yet acquired"
		}
		result.Latency = time.Since(start)
		return result
	}
}

type inMemoryGraphWriterLeaseStore struct {
	mu       sync.Mutex
	revision uint64
	records  map[string]graphWriterLeaseSnapshot
}

func newInMemoryGraphWriterLeaseStore() *inMemoryGraphWriterLeaseStore {
	return &inMemoryGraphWriterLeaseStore{records: map[string]graphWriterLeaseSnapshot{}}
}

func (s *inMemoryGraphWriterLeaseStore) TryAcquire(_ context.Context, name, ownerID string, ttl time.Duration, now time.Time) (graphWriterLeaseSnapshot, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current := s.records[name]
	if current.active(now) && current.OwnerID != ownerID {
		return current, false, nil
	}
	s.revision++
	next := graphWriterLeaseSnapshot{
		Name:       strings.TrimSpace(name),
		OwnerID:    strings.TrimSpace(ownerID),
		LeaseUntil: now.Add(ttl),
		RenewedAt:  now,
		Revision:   s.revision,
	}
	s.records[name] = next
	return next, true, nil
}

func (s *inMemoryGraphWriterLeaseStore) Renew(_ context.Context, name, ownerID string, ttl time.Duration, now time.Time) (graphWriterLeaseSnapshot, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current := s.records[name]
	if current.OwnerID != ownerID || !current.active(now) {
		return current, false, nil
	}
	s.revision++
	current.LeaseUntil = now.Add(ttl)
	current.RenewedAt = now
	current.Revision = s.revision
	s.records[name] = current
	return current, true, nil
}

func (s *inMemoryGraphWriterLeaseStore) Current(_ context.Context, name string, _ time.Time) (graphWriterLeaseSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.records[name], nil
}

func (s *inMemoryGraphWriterLeaseStore) Release(_ context.Context, name, ownerID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	current := s.records[name]
	if current.OwnerID == ownerID {
		delete(s.records, name)
	}
	return nil
}

func (s *inMemoryGraphWriterLeaseStore) Close() error {
	return nil
}
