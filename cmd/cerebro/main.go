package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/writer/cerebro/internal/bootstrap"
	"github.com/writer/cerebro/internal/buildinfo"
	"github.com/writer/cerebro/internal/config"
)

func main() {
	command := "serve"
	if len(os.Args) > 1 {
		command = os.Args[1]
	}

	switch command {
	case "serve":
		serve()
	case "version":
		fmt.Printf("%s %s\n", buildinfo.ServiceName, buildinfo.Version)
	default:
		fmt.Fprintf(os.Stderr, "usage: %s [serve|version]\n", os.Args[0])
		os.Exit(2)
	}
}

func serve() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	app := bootstrap.New(cfg, bootstrap.Dependencies{})
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		errCh <- app.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		if err != nil {
			log.Fatalf("serve: %v", err)
		}
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
		defer cancel()
		if err := app.Shutdown(shutdownCtx); err != nil {
			log.Fatalf("shutdown: %v", err)
		}
	}
}
