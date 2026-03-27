package cli

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/nats-io/nats.go"

	"github.com/writer/cerebro/internal/app"
	"github.com/writer/cerebro/internal/events"
	"github.com/writer/cerebro/internal/jobs"
)

type jobRuntime struct {
	db    *sql.DB
	nc    *nats.Conn
	queue jobs.Queue
	store jobs.Store
}

func distributedJobsConfigured(cfg *app.Config) bool {
	return cfg != nil && strings.TrimSpace(cfg.JobDatabaseURL) != ""
}

func openJobRuntime(ctx context.Context, cfg *app.Config) (*jobRuntime, error) {
	if cfg == nil {
		return nil, fmt.Errorf("job config is required")
	}
	databaseURL := strings.TrimSpace(cfg.JobDatabaseURL)
	if databaseURL == "" {
		return nil, fmt.Errorf("JOB_DATABASE_URL is required")
	}
	if len(cfg.NATSJetStreamURLs) == 0 {
		return nil, fmt.Errorf("NATS_URLS is required")
	}

	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("open job database: %w", err)
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping job database: %w", err)
	}

	store := jobs.NewPostgresStore(db)
	if err := store.EnsureSchema(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ensure job schema: %w", err)
	}

	jetStreamCfg := events.JetStreamConfig{
		URLs:                  cfg.NATSJetStreamURLs,
		ConnectTimeout:        cfg.NATSJetStreamConnectTimeout,
		AuthMode:              cfg.NATSJetStreamAuthMode,
		Username:              cfg.NATSJetStreamUsername,
		Password:              cfg.NATSJetStreamPassword,
		NKeySeed:              cfg.NATSJetStreamNKeySeed,
		UserJWT:               cfg.NATSJetStreamUserJWT,
		TLSEnabled:            cfg.NATSJetStreamTLSEnabled,
		TLSCAFile:             cfg.NATSJetStreamTLSCAFile,
		TLSCertFile:           cfg.NATSJetStreamTLSCertFile,
		TLSKeyFile:            cfg.NATSJetStreamTLSKeyFile,
		TLSServerName:         cfg.NATSJetStreamTLSServerName,
		TLSInsecureSkipVerify: cfg.NATSJetStreamTLSInsecure,
	}
	natsOptions, err := jetStreamCfg.NATSOptions()
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("build job NATS options: %w", err)
	}

	nc, err := nats.Connect(strings.Join(cfg.NATSJetStreamURLs, ","), natsOptions...)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("connect to job NATS: %w", err)
	}

	js, err := nc.JetStream()
	if err != nil {
		nc.Close()
		_ = db.Close()
		return nil, fmt.Errorf("obtain job JetStream context: %w", err)
	}

	queue := jobs.NewNATSQueue(js, jobs.NATSQueueConfig{
		Stream:       strings.TrimSpace(cfg.JobNATSStream),
		Subject:      strings.TrimSpace(cfg.JobNATSSubject),
		Consumer:     strings.TrimSpace(cfg.JobNATSConsumer),
		CreateStream: false,
	})
	if err := queue.EnsureStream(ctx); err != nil {
		nc.Close()
		_ = db.Close()
		return nil, fmt.Errorf("ensure job stream: %w", err)
	}

	return &jobRuntime{
		db:    db,
		nc:    nc,
		queue: queue,
		store: store,
	}, nil
}

func (r *jobRuntime) newIdempotencyStore(ctx context.Context) (*jobs.PostgresIdempotencyStore, error) {
	if r == nil || r.db == nil {
		return nil, fmt.Errorf("job database is not available")
	}
	store := jobs.NewPostgresIdempotencyStore(r.db)
	if err := store.EnsureSchema(ctx); err != nil {
		return nil, fmt.Errorf("ensure idempotency schema: %w", err)
	}
	return store, nil
}

func (r *jobRuntime) Close() error {
	if r == nil {
		return nil
	}
	var err error
	if r.nc != nil {
		r.nc.Close()
	}
	if r.db != nil {
		err = errors.Join(err, r.db.Close())
	}
	return err
}

func summarizeDatabaseTarget(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "unset"
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed == nil {
		return "configured"
	}
	host := strings.TrimSpace(parsed.Host)
	path := strings.TrimPrefix(strings.TrimSpace(parsed.Path), "/")
	switch {
	case host != "" && path != "":
		return host + "/" + path
	case host != "":
		return host
	case path != "":
		return path
	default:
		return "configured"
	}
}
