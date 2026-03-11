package app

import (
	"log/slog"
	"os"
)

// Option customizes app construction in NewWithOptions.
type Option func(*constructorOptions)

type constructorOptions struct {
	config        *Config
	logger        *slog.Logger
	secretsLoader secretsLoader
}

// WithConfig overrides the environment-backed config used by NewWithOptions.
func WithConfig(cfg *Config) Option {
	return func(options *constructorOptions) {
		options.config = cfg
	}
}

// WithLogger overrides the default JSON stdout logger used by NewWithOptions.
func WithLogger(logger *slog.Logger) Option {
	return func(options *constructorOptions) {
		options.logger = logger
	}
}

func applyOptions(opts []Option) constructorOptions {
	options := constructorOptions{
		secretsLoader: envSecretsLoader{},
	}
	for _, opt := range opts {
		if opt != nil {
			opt(&options)
		}
	}
	return options
}

func newDefaultAppLogger(level string) *slog.Logger {
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: parseLogLevel(level),
	}))
}
