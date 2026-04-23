package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/writer/cerebro/internal/bootstrap"
	"github.com/writer/cerebro/internal/buildinfo"
	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/sourceregistry"
)

type usageError string

func (e usageError) Error() string {
	return string(e)
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		var usage usageError
		if errors.As(err, &usage) {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		log.Print(err)
		os.Exit(1)
	}
}

func run(args []string) error {
	command := "serve"
	if len(args) > 0 {
		command = args[0]
	}
	switch command {
	case "serve":
		return serve()
	case "version":
		fmt.Printf("%s %s\n", buildinfo.ServiceName, buildinfo.Version)
		return nil
	}
	return usageError(fmt.Sprintf("usage: %s [serve|version]", os.Args[0]))
}

func serve() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	deps, closeDeps, err := bootstrap.OpenDependencies(context.Background(), cfg)
	if err != nil {
		return fmt.Errorf("open dependencies: %w", err)
	}
	defer func() {
		if err := closeDeps(); err != nil {
			log.Printf("close dependencies: %v", err)
		}
	}()
	sources, err := sourceregistry.Builtin()
	if err != nil {
		return fmt.Errorf("open source registry: %w", err)
	}

	app := bootstrap.New(cfg, deps, sources)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		errCh <- app.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("serve: %w", err)
		}
		return nil
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
		defer cancel()
		if err := app.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown: %w", err)
		}
		if err := <-errCh; err != nil {
			return fmt.Errorf("serve: %w", err)
		}
		return nil
	}
}
