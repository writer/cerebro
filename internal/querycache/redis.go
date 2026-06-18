package querycache

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/writer/cerebro/internal/telemetry"
)

type RedisCache struct {
	client  *redis.Client
	options Options
}

func OpenRedis(rawURL string, options Options) (*RedisCache, error) {
	redisOptions, err := redis.ParseURL(strings.TrimSpace(rawURL))
	if err != nil {
		return nil, err
	}
	return &RedisCache{
		client:  redis.NewClient(redisOptions),
		options: normalizeOptions(options),
	}, nil
}

func (c *RedisCache) Get(ctx context.Context, key string) (Entry, error) {
	ctx, span := telemetry.Start(ctx, "redis.cache.get", redisTelemetryAttrs("get", c.options.Namespace))
	raw, err := c.client.Get(ctx, cacheKey(c.options.Namespace, key)).Bytes()
	if errors.Is(err, redis.Nil) {
		telemetry.End(span, "miss", telemetry.Attrs())
		return Entry{}, ErrMiss
	}
	if err != nil {
		redisTelemetryError(ctx, span, "get", err)
		return Entry{}, err
	}
	var entry Entry
	if err := json.Unmarshal(raw, &entry); err != nil {
		redisTelemetryError(ctx, span, "get", err)
		return Entry{}, err
	}
	if entry.State(time.Now().UTC()) == StateMiss {
		telemetry.End(span, "miss", telemetry.Attrs())
		return Entry{}, ErrMiss
	}
	telemetry.End(span, "hit", telemetry.Attrs())
	return entry, nil
}

func (c *RedisCache) Set(ctx context.Context, key string, payload []byte, ttl time.Duration, staleTTL time.Duration) error {
	ctx, span := telemetry.Start(ctx, "redis.cache.set", redisTelemetryAttrs("set", c.options.Namespace))
	if len(payload) == 0 || len(payload) > c.options.MaxPayloadBytes {
		telemetry.End(span, "skipped", telemetry.Attrs(telemetry.Field{Key: "status_detail", Value: "payload_size"}))
		return nil
	}
	now := time.Now().UTC()
	if ttl <= 0 {
		ttl = time.Second
	}
	if staleTTL < 0 {
		staleTTL = 0
	}
	entry := Entry{
		Payload:    append([]byte(nil), payload...),
		CreatedAt:  now,
		ExpiresAt:  now.Add(ttl),
		StaleUntil: now.Add(ttl + staleTTL),
	}
	raw, err := json.Marshal(entry)
	if err != nil {
		redisTelemetryError(ctx, span, "set", err)
		return err
	}
	if err := c.client.Set(ctx, cacheKey(c.options.Namespace, key), raw, ttl+staleTTL).Err(); err != nil {
		redisTelemetryError(ctx, span, "set", err)
		return err
	}
	telemetry.End(span, "completed", telemetry.Attrs())
	return nil
}

func (c *RedisCache) Version(ctx context.Context, scope string) (string, error) {
	ctx, span := telemetry.Start(ctx, "redis.cache.version", redisTelemetryAttrs("version", c.options.Namespace))
	value, err := c.client.Get(ctx, versionKey(c.options.Namespace, scope)).Result()
	if errors.Is(err, redis.Nil) {
		telemetry.End(span, "miss", telemetry.Attrs())
		return "0", nil
	}
	if err != nil {
		redisTelemetryError(ctx, span, "version", err)
		return value, err
	}
	telemetry.End(span, "completed", telemetry.Attrs())
	return value, err
}

func (c *RedisCache) BumpVersion(ctx context.Context, scope string) (string, error) {
	ctx, span := telemetry.Start(ctx, "redis.cache.bump_version", redisTelemetryAttrs("bump_version", c.options.Namespace))
	value, err := c.client.Incr(ctx, versionKey(c.options.Namespace, scope)).Result()
	if err != nil {
		redisTelemetryError(ctx, span, "bump_version", err)
		return "", err
	}
	telemetry.End(span, "completed", telemetry.Attrs())
	return strconv.FormatInt(value, 10), nil
}

func (c *RedisCache) Ping(ctx context.Context) error {
	ctx, span := telemetry.Start(ctx, "redis.ping", redisTelemetryAttrs("ping", c.options.Namespace))
	if err := c.client.Ping(ctx).Err(); err != nil {
		redisTelemetryError(ctx, span, "ping", err)
		return err
	}
	telemetry.End(span, "completed", telemetry.Attrs())
	return nil
}

func (c *RedisCache) Close(ctx context.Context) error {
	return c.client.Close()
}

func redisTelemetryAttrs(operation string, namespace string) telemetry.Attributes {
	return telemetry.Attrs(
		telemetry.Field{Key: "component", Value: "querycache.redis"},
		telemetry.Field{Key: "operation", Value: operation},
		telemetry.Field{Key: "cache.namespace", Value: strings.TrimSpace(namespace)},
	)
}

func redisTelemetryError(ctx context.Context, span *telemetry.Span, operation string, err error) {
	attrs := telemetry.Attrs(telemetry.Field{Key: "error_kind", Value: telemetry.ErrorKind(err)})
	telemetry.CaptureError(ctx, "redis.cache.error", err, telemetry.Attrs(
		telemetry.Field{Key: "component", Value: "querycache.redis"},
		telemetry.Field{Key: "operation", Value: operation},
	))
	telemetry.End(span, "failed", attrs)
}
