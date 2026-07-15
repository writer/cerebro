package querycache

import (
	"context"
	"errors"
	"strings"
	"time"
)

var (
	ErrMiss            = errors.New("query cache miss")
	ErrPayloadTooLarge = errors.New("query cache payload exceeds configured limit")
)

type State string

const (
	StateMiss  State = "miss"
	StateFresh State = "fresh"
	StateStale State = "stale"
)

type Entry struct {
	Payload    []byte    `json:"payload"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	StaleUntil time.Time `json:"stale_until"`
}

func (e Entry) State(now time.Time) State {
	if len(e.Payload) == 0 || e.StaleUntil.IsZero() || !now.Before(e.StaleUntil) {
		return StateMiss
	}
	if !e.ExpiresAt.IsZero() && now.Before(e.ExpiresAt) {
		return StateFresh
	}
	return StateStale
}

type Cache interface {
	Get(context.Context, string) (Entry, error)
	Set(context.Context, string, []byte, time.Duration, time.Duration) error
	Version(context.Context, string) (string, error)
	BumpVersion(context.Context, string) (string, error)
	Ping(context.Context) error
	Close(context.Context) error
}

type Options struct {
	Namespace       string
	MaxPayloadBytes int
	MaxEntries      int
}

func normalizeOptions(options Options) Options {
	options.Namespace = strings.Trim(strings.TrimSpace(options.Namespace), ":")
	if options.Namespace == "" {
		options.Namespace = "cerebro"
	}
	if options.MaxPayloadBytes <= 0 {
		options.MaxPayloadBytes = 1 << 20
	}
	if options.MaxEntries <= 0 {
		options.MaxEntries = 4096
	}
	return options
}

func cacheKey(namespace string, key string) string {
	key = strings.Trim(strings.TrimSpace(key), ":")
	if key == "" {
		key = "empty"
	}
	return namespace + ":" + key
}

func versionKey(namespace string, scope string) string {
	scope = strings.Trim(strings.TrimSpace(scope), ":")
	if scope == "" {
		scope = "global"
	}
	return namespace + ":version:" + scope
}
