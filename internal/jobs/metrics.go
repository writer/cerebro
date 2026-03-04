package jobs

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// MetricsRecorder is the interface for recording worker metrics.
type MetricsRecorder interface {
	RecordJobProcessed(duration time.Duration, succeeded bool, timedOut bool)
	RecordHeartbeat(succeeded bool)
	RecordMessagesReceived(count int)
	RecordMessagesDeleted(count int)
	RecordMessagesDeleteFailed(count int)
	Flush(ctx context.Context) error
	StartFlusher(ctx context.Context, interval time.Duration)
}

// Metrics collects worker metrics and logs them periodically.
type Metrics struct {
	logger   *slog.Logger
	workerID string

	mu                   sync.Mutex
	jobsProcessed        int64
	jobsSucceeded        int64
	jobsFailed           int64
	jobsTimedOut         int64
	totalLatencyMs       int64
	heartbeatsSent       int64
	heartbeatsFailed     int64
	messagesReceived     int64
	messagesDeleted      int64
	messagesDeleteFailed int64
}

// MetricsConfig configures the metrics collector.
type MetricsConfig struct {
	Namespace string // For future CloudWatch support
	WorkerID  string
	Logger    *slog.Logger
}

// NewMetrics creates a new metrics collector.
// Note: Currently logs metrics. CloudWatch support can be added by vendoring
// github.com/aws/aws-sdk-go-v2/service/cloudwatch
func NewMetrics(logger *slog.Logger, config MetricsConfig) *Metrics {
	return &Metrics{
		logger:   logger,
		workerID: config.WorkerID,
	}
}

// RecordJobProcessed records a job completion with its duration and status.
func (m *Metrics) RecordJobProcessed(duration time.Duration, succeeded bool, timedOut bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.jobsProcessed++
	m.totalLatencyMs += duration.Milliseconds()

	if succeeded {
		m.jobsSucceeded++
	} else {
		m.jobsFailed++
		if timedOut {
			m.jobsTimedOut++
		}
	}
}

// RecordHeartbeat records a heartbeat attempt.
func (m *Metrics) RecordHeartbeat(succeeded bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.heartbeatsSent++
	if !succeeded {
		m.heartbeatsFailed++
	}
}

// RecordMessagesReceived records messages received from SQS.
func (m *Metrics) RecordMessagesReceived(count int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.messagesReceived += int64(count)
}

// RecordMessagesDeleted records messages deleted from SQS.
func (m *Metrics) RecordMessagesDeleted(count int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.messagesDeleted += int64(count)
}

// RecordMessagesDeleteFailed records failed message delete attempts from SQS.
func (m *Metrics) RecordMessagesDeleteFailed(count int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.messagesDeleteFailed += int64(count)
}

// Flush logs accumulated metrics and resets counters.
func (m *Metrics) Flush(ctx context.Context) error {
	m.mu.Lock()

	if m.jobsProcessed == 0 && m.messagesReceived == 0 {
		m.mu.Unlock()
		return nil
	}

	var avgLatency float64
	if m.jobsProcessed > 0 {
		avgLatency = float64(m.totalLatencyMs) / float64(m.jobsProcessed)
	}

	var successRate float64
	if m.jobsProcessed > 0 {
		successRate = float64(m.jobsSucceeded) / float64(m.jobsProcessed) * 100
	}

	stats := struct {
		WorkerID             string
		JobsProcessed        int64
		JobsSucceeded        int64
		JobsFailed           int64
		JobsTimedOut         int64
		AvgLatencyMs         float64
		SuccessRate          float64
		MessagesReceived     int64
		MessagesDeleted      int64
		MessagesDeleteFailed int64
		HeartbeatsSent       int64
		HeartbeatsFailed     int64
	}{
		WorkerID:             m.workerID,
		JobsProcessed:        m.jobsProcessed,
		JobsSucceeded:        m.jobsSucceeded,
		JobsFailed:           m.jobsFailed,
		JobsTimedOut:         m.jobsTimedOut,
		AvgLatencyMs:         avgLatency,
		SuccessRate:          successRate,
		MessagesReceived:     m.messagesReceived,
		MessagesDeleted:      m.messagesDeleted,
		MessagesDeleteFailed: m.messagesDeleteFailed,
		HeartbeatsSent:       m.heartbeatsSent,
		HeartbeatsFailed:     m.heartbeatsFailed,
	}

	// Reset counters
	m.jobsProcessed = 0
	m.jobsSucceeded = 0
	m.jobsFailed = 0
	m.jobsTimedOut = 0
	m.totalLatencyMs = 0
	m.heartbeatsSent = 0
	m.heartbeatsFailed = 0
	m.messagesReceived = 0
	m.messagesDeleted = 0
	m.messagesDeleteFailed = 0
	m.mu.Unlock()

	if m.logger != nil {
		m.logger.Info("worker metrics",
			"worker_id", stats.WorkerID,
			"jobs_processed", stats.JobsProcessed,
			"jobs_succeeded", stats.JobsSucceeded,
			"jobs_failed", stats.JobsFailed,
			"jobs_timed_out", stats.JobsTimedOut,
			"avg_latency_ms", stats.AvgLatencyMs,
			"success_rate", stats.SuccessRate,
			"messages_received", stats.MessagesReceived,
			"messages_deleted", stats.MessagesDeleted,
			"messages_delete_failed", stats.MessagesDeleteFailed,
			"heartbeats_sent", stats.HeartbeatsSent,
			"heartbeats_failed", stats.HeartbeatsFailed,
		)
	}

	return nil
}

// StartFlusher starts a background goroutine that flushes metrics periodically.
func (m *Metrics) StartFlusher(ctx context.Context, interval time.Duration) {
	// #nosec G118 -- flusher goroutine is intentionally long-lived, outlives request scope
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				// Final flush on shutdown
				flushCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = m.Flush(flushCtx)
				return
			case <-ticker.C:
				_ = m.Flush(ctx)
			}
		}
	}()
}

// NoOpMetrics is a metrics implementation that does nothing.
type NoOpMetrics struct{}

func (n *NoOpMetrics) RecordJobProcessed(duration time.Duration, succeeded bool, timedOut bool) {}
func (n *NoOpMetrics) RecordHeartbeat(succeeded bool)                                           {}
func (n *NoOpMetrics) RecordMessagesReceived(count int)                                         {}
func (n *NoOpMetrics) RecordMessagesDeleted(count int)                                          {}
func (n *NoOpMetrics) RecordMessagesDeleteFailed(count int)                                     {}
func (n *NoOpMetrics) Flush(ctx context.Context) error                                          { return nil }
func (n *NoOpMetrics) StartFlusher(ctx context.Context, interval time.Duration)                 {}
