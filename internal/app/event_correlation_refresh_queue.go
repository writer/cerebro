package app

import (
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/evalops/cerebro/internal/metrics"
)

type eventCorrelationBackpressureLevel string

const (
	eventCorrelationBackpressureNormal   eventCorrelationBackpressureLevel = "normal"
	eventCorrelationBackpressureWarning  eventCorrelationBackpressureLevel = "warning"
	eventCorrelationBackpressureCritical eventCorrelationBackpressureLevel = "critical"

	defaultEventCorrelationRefreshDebounce             = 2 * time.Second
	defaultEventCorrelationRefreshBackpressureWarn     = 250 * time.Millisecond
	defaultEventCorrelationRefreshBackpressureCritical = 1500 * time.Millisecond
	eventCorrelationBackpressureWarningDelay           = 10 * time.Millisecond
	eventCorrelationBackpressureCriticalDelay          = 50 * time.Millisecond
)

type eventCorrelationRefreshQueue struct {
	mu            sync.Mutex
	debounce      time.Duration
	warnAfter     time.Duration
	criticalAfter time.Duration
	process       func(string)
	pending       map[string]struct{}
	pendingSince  time.Time
	running       bool
	closed        bool
	notifyCh      chan struct{}
	stopCh        chan struct{}
	doneCh        chan struct{}
}

func newEventCorrelationRefreshQueue(process func(string)) *eventCorrelationRefreshQueue {
	return &eventCorrelationRefreshQueue{
		debounce:      defaultEventCorrelationRefreshDebounce,
		warnAfter:     defaultEventCorrelationRefreshBackpressureWarn,
		criticalAfter: defaultEventCorrelationRefreshBackpressureCritical,
		process:       process,
		pending:       make(map[string]struct{}),
		notifyCh:      make(chan struct{}, 1),
		stopCh:        make(chan struct{}),
		doneCh:        make(chan struct{}),
	}
}

func (q *eventCorrelationRefreshQueue) start() {
	if q == nil {
		return
	}
	metrics.SetCorrelationRefreshQueueDepth(0)
	go q.run()
}

func (q *eventCorrelationRefreshQueue) stop() {
	if q == nil {
		return
	}
	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		return
	}
	q.closed = true
	close(q.stopCh)
	q.mu.Unlock()
	<-q.doneCh
	metrics.SetCorrelationRefreshQueueDepth(0)
}

func (q *eventCorrelationRefreshQueue) enqueue(reason string) eventCorrelationBackpressureLevel {
	if q == nil {
		return eventCorrelationBackpressureNormal
	}
	now := time.Now().UTC()
	reason = normalizeEventCorrelationRefreshReason(reason)

	q.mu.Lock()
	defer q.mu.Unlock()

	if q.closed {
		metrics.RecordCorrelationRefreshDrop()
		return eventCorrelationBackpressureCritical
	}
	if len(q.pending) == 0 {
		q.pendingSince = now
	}
	q.pending[reason] = struct{}{}
	depth := len(q.pending)
	level := q.backpressureLevelLocked(now)
	metrics.SetCorrelationRefreshQueueDepth(depth)
	q.signalLocked()
	return level
}

func (q *eventCorrelationRefreshQueue) run() {
	defer close(q.doneCh)

	var (
		timer   *time.Timer
		timerCh <-chan time.Time
	)

	stopTimer := func() {
		if timer == nil {
			timerCh = nil
			return
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer = nil
		timerCh = nil
	}

	resetTimer := func() {
		if timer == nil {
			timer = time.NewTimer(q.debounce)
			timerCh = timer.C
			return
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(q.debounce)
		timerCh = timer.C
	}

	for {
		select {
		case <-q.stopCh:
			stopTimer()
			return
		case <-q.notifyCh:
			resetTimer()
		case <-timerCh:
			stopTimer()
			reasons := q.takePendingBatch()
			if len(reasons) == 0 {
				continue
			}
			start := time.Now()
			q.process(strings.Join(reasons, ","))
			metrics.ObserveCorrelationRefreshDuration(time.Since(start))

			q.mu.Lock()
			q.running = false
			depth := len(q.pending)
			q.mu.Unlock()
			metrics.SetCorrelationRefreshQueueDepth(depth)
			if depth > 0 {
				q.signal()
			}
		}
	}
}

func (q *eventCorrelationRefreshQueue) takePendingBatch() []string {
	q.mu.Lock()
	defer q.mu.Unlock()

	if len(q.pending) == 0 {
		q.pendingSince = time.Time{}
		return nil
	}
	reasons := make([]string, 0, len(q.pending))
	for reason := range q.pending {
		reasons = append(reasons, reason)
	}
	sort.Strings(reasons)
	q.pending = make(map[string]struct{})
	q.pendingSince = time.Time{}
	q.running = true
	return reasons
}

func (q *eventCorrelationRefreshQueue) backpressureLevelLocked(now time.Time) eventCorrelationBackpressureLevel {
	if !q.running || len(q.pending) == 0 {
		return eventCorrelationBackpressureNormal
	}
	if q.pendingSince.IsZero() {
		return eventCorrelationBackpressureWarning
	}
	age := now.Sub(q.pendingSince)
	if age >= q.criticalAfter {
		return eventCorrelationBackpressureCritical
	}
	if age >= q.warnAfter {
		return eventCorrelationBackpressureWarning
	}
	return eventCorrelationBackpressureNormal
}

func (q *eventCorrelationRefreshQueue) signal() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.signalLocked()
}

func (q *eventCorrelationRefreshQueue) signalLocked() {
	select {
	case q.notifyCh <- struct{}{}:
	default:
	}
}

func normalizeEventCorrelationRefreshReason(reason string) string {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return "tap_mapping"
	}
	return reason
}

func eventCorrelationBackpressureDelay(level eventCorrelationBackpressureLevel) time.Duration {
	switch level {
	case eventCorrelationBackpressureCritical:
		return eventCorrelationBackpressureCriticalDelay
	case eventCorrelationBackpressureWarning:
		return eventCorrelationBackpressureWarningDelay
	default:
		return 0
	}
}
