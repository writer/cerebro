package config

import (
	"fmt"
	"os"
	"strings"
	"time"
)

const defaultHTTPAddr = ":8080"
const defaultShutdownTimeout = 10 * time.Second

// Config is the minimal bootstrap configuration for the rewrite skeleton.
type Config struct {
	HTTPAddr        string
	ShutdownTimeout time.Duration
}

// Load reads and validates process configuration.
func Load() (Config, error) {
	cfg := Config{
		HTTPAddr:        strings.TrimSpace(os.Getenv("CEREBRO_HTTP_ADDR")),
		ShutdownTimeout: defaultShutdownTimeout,
	}
	if cfg.HTTPAddr == "" {
		cfg.HTTPAddr = defaultHTTPAddr
	}
	if raw, ok := os.LookupEnv("CEREBRO_SHUTDOWN_TIMEOUT"); ok && strings.TrimSpace(raw) != "" {
		duration, err := time.ParseDuration(strings.TrimSpace(raw))
		if err != nil {
			return Config{}, fmt.Errorf("parse CEREBRO_SHUTDOWN_TIMEOUT: %w", err)
		}
		cfg.ShutdownTimeout = duration
	}
	if cfg.ShutdownTimeout <= 0 {
		return Config{}, fmt.Errorf("CEREBRO_SHUTDOWN_TIMEOUT must be greater than zero")
	}
	return cfg, nil
}
