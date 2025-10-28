package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/WriterInternal/cerebro/desktop-agent/internal/client"
	"github.com/WriterInternal/cerebro/desktop-agent/internal/collector"
	"github.com/WriterInternal/cerebro/desktop-agent/internal/config"
)

func main() {
	cfg := config.Load()

	logger := log.New(os.Stdout, "cerebro-agent ", log.LstdFlags|log.Lmsgprefix)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	httpClient, err := client.New(cfg)
	if err != nil {
		logger.Fatalf("failed to prepare client: %v", err)
	}

	run := func() {
		telemetry, collectErr := collector.Collect(cfg)
		if collectErr != nil {
			logger.Printf("collection error: %v", collectErr)
			return
		}

		if err := client.Send(ctx, httpClient, cfg, telemetry); err != nil {
			logger.Printf("failed to send telemetry: %v", err)
		} else {
			logger.Printf("sent telemetry for host %s", telemetry.HostID)
		}
	}

	run()
	if cfg.Once {
		return
	}

	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			logger.Println("shutting down")
			return
		case <-ticker.C:
			run()
		}
	}
}
