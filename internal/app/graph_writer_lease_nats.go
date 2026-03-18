package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/evalops/cerebro/internal/events"
	"github.com/nats-io/nats.go"
)

type natsGraphWriterLeaseStore struct {
	key string
	nc  *nats.Conn
	kv  nats.KeyValue
}

// natsGraphWriterLeaseReleaseBeforeDeleteHook lets tests interleave a lease
// change after Release has loaded the current record but before it attempts the
// compare-and-delete operation.
var natsGraphWriterLeaseReleaseBeforeDeleteHook func()

func newNATSGraphWriterLeaseStore(cfg *Config) (*natsGraphWriterLeaseStore, error) {
	if cfg == nil {
		return nil, fmt.Errorf("graph writer lease config required")
	}
	base := events.JetStreamConfig{
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
	options, err := base.NATSOptions()
	if err != nil {
		return nil, err
	}
	nc, err := nats.Connect(strings.Join(cfg.NATSJetStreamURLs, ","), options...)
	if err != nil {
		return nil, fmt.Errorf("connect graph writer lease to nats: %w", err)
	}
	js, err := nc.JetStream()
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("initialize graph writer lease jetstream context: %w", err)
	}
	bucket := strings.TrimSpace(cfg.GraphWriterLeaseBucket)
	kv, err := js.KeyValue(bucket)
	if errors.Is(err, nats.ErrBucketNotFound) {
		kv, err = js.CreateKeyValue(&nats.KeyValueConfig{
			Bucket:      bucket,
			Description: "Cerebro graph writer leases",
			History:     1,
			Storage:     nats.FileStorage,
		})
	}
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("initialize graph writer lease bucket %s: %w", bucket, err)
	}
	return &natsGraphWriterLeaseStore{key: strings.TrimSpace(cfg.GraphWriterLeaseName), nc: nc, kv: kv}, nil
}

func (s *natsGraphWriterLeaseStore) TryAcquire(ctx context.Context, name, ownerID string, ttl time.Duration, now time.Time) (graphWriterLeaseSnapshot, bool, error) {
	return s.upsert(ctx, name, ownerID, ttl, now, false)
}

func (s *natsGraphWriterLeaseStore) Renew(ctx context.Context, name, ownerID string, ttl time.Duration, now time.Time) (graphWriterLeaseSnapshot, bool, error) {
	return s.upsert(ctx, name, ownerID, ttl, now, true)
}

func (s *natsGraphWriterLeaseStore) Current(ctx context.Context, _ string, _ time.Time) (graphWriterLeaseSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return graphWriterLeaseSnapshot{}, err
	}
	current, _, err := s.loadCurrent()
	return current, err
}

func (s *natsGraphWriterLeaseStore) Release(ctx context.Context, _ string, ownerID string) error {
	if s == nil || s.kv == nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	current, entry, err := s.loadCurrent()
	if err != nil {
		if errors.Is(err, nats.ErrKeyNotFound) {
			return nil
		}
		return err
	}
	if strings.TrimSpace(current.OwnerID) != strings.TrimSpace(ownerID) {
		return nil
	}
	if natsGraphWriterLeaseReleaseBeforeDeleteHook != nil {
		natsGraphWriterLeaseReleaseBeforeDeleteHook()
	}
	if entry == nil {
		return nil
	}
	if err := s.kv.Delete(s.key, nats.LastRevision(entry.Revision())); err != nil {
		reloaded, _, reloadErr := s.loadCurrent()
		switch {
		case reloadErr == nil && strings.TrimSpace(reloaded.OwnerID) != strings.TrimSpace(ownerID):
			return nil
		case errors.Is(err, nats.ErrKeyNotFound):
			return nil
		default:
			return err
		}
	}
	return nil
}

func (s *natsGraphWriterLeaseStore) Close() error {
	if s == nil || s.nc == nil {
		return nil
	}
	err := s.nc.Drain()
	s.nc.Close()
	return err
}

func (s *natsGraphWriterLeaseStore) upsert(ctx context.Context, name, ownerID string, ttl time.Duration, now time.Time, renewOnly bool) (graphWriterLeaseSnapshot, bool, error) {
	if s == nil || s.kv == nil {
		return graphWriterLeaseSnapshot{}, false, fmt.Errorf("graph writer lease store not initialized")
	}
	if err := ctx.Err(); err != nil {
		return graphWriterLeaseSnapshot{}, false, err
	}
	for attempts := 0; attempts < 3; attempts++ {
		current, entry, err := s.loadCurrent()
		if err != nil && !errors.Is(err, nats.ErrKeyNotFound) {
			return graphWriterLeaseSnapshot{}, false, err
		}
		desired := graphWriterLeaseSnapshot{
			Name:       strings.TrimSpace(name),
			OwnerID:    strings.TrimSpace(ownerID),
			LeaseUntil: now.Add(ttl),
			RenewedAt:  now,
		}
		switch {
		case errors.Is(err, nats.ErrKeyNotFound):
			if renewOnly {
				return graphWriterLeaseSnapshot{}, false, nil
			}
			if created, createErr := s.kv.Create(s.key, mustMarshalGraphWriterLease(desired)); createErr == nil {
				desired.Revision = created
				return desired, true, nil
			} else if errors.Is(createErr, nats.ErrKeyExists) {
				continue
			} else {
				return graphWriterLeaseSnapshot{}, false, createErr
			}
		case renewOnly && current.OwnerID != ownerID:
			return current, false, nil
		case renewOnly && !current.active(now):
			return current, false, nil
		case !renewOnly && current.active(now) && current.OwnerID != ownerID:
			return current, false, nil
		}
		if entry == nil {
			continue
		}
		updated, updateErr := s.kv.Update(s.key, mustMarshalGraphWriterLease(desired), entry.Revision())
		if updateErr == nil {
			desired.Revision = updated
			return desired, true, nil
		}
		if attempts < 2 {
			continue
		}
		return graphWriterLeaseSnapshot{}, false, updateErr
	}
	current, _, err := s.loadCurrent()
	return current, false, err
}

func (s *natsGraphWriterLeaseStore) loadCurrent() (graphWriterLeaseSnapshot, nats.KeyValueEntry, error) {
	entry, err := s.kv.Get(s.key)
	if err != nil {
		return graphWriterLeaseSnapshot{}, nil, err
	}
	var current graphWriterLeaseSnapshot
	if err := json.Unmarshal(entry.Value(), &current); err != nil {
		return graphWriterLeaseSnapshot{}, nil, fmt.Errorf("decode graph writer lease: %w", err)
	}
	current.Revision = entry.Revision()
	return current, entry, nil
}

func mustMarshalGraphWriterLease(snapshot graphWriterLeaseSnapshot) []byte {
	payload, err := json.Marshal(snapshot)
	if err != nil {
		panic(err)
	}
	return payload
}
