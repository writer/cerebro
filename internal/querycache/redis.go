package querycache

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
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
	raw, err := c.client.Get(ctx, cacheKey(c.options.Namespace, key)).Bytes()
	if errors.Is(err, redis.Nil) {
		return Entry{}, ErrMiss
	}
	if err != nil {
		return Entry{}, err
	}
	var entry Entry
	if err := json.Unmarshal(raw, &entry); err != nil {
		return Entry{}, err
	}
	if entry.State(time.Now().UTC()) == StateMiss {
		return Entry{}, ErrMiss
	}
	return entry, nil
}

func (c *RedisCache) Set(ctx context.Context, key string, payload []byte, ttl time.Duration, staleTTL time.Duration) error {
	if len(payload) == 0 || len(payload) > c.options.MaxPayloadBytes {
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
		return err
	}
	return c.client.Set(ctx, cacheKey(c.options.Namespace, key), raw, ttl+staleTTL).Err()
}

func (c *RedisCache) Version(ctx context.Context, scope string) (string, error) {
	value, err := c.client.Get(ctx, versionKey(c.options.Namespace, scope)).Result()
	if errors.Is(err, redis.Nil) {
		return "0", nil
	}
	return value, err
}

func (c *RedisCache) BumpVersion(ctx context.Context, scope string) (string, error) {
	value, err := c.client.Incr(ctx, versionKey(c.options.Namespace, scope)).Result()
	if err != nil {
		return "", err
	}
	return strconv.FormatInt(value, 10), nil
}

func (c *RedisCache) Ping(ctx context.Context) error {
	return c.client.Ping(ctx).Err()
}

func (c *RedisCache) Close(ctx context.Context) error {
	return c.client.Close()
}
