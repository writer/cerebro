package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/WriterInternal/cerebro/desktop-agent/internal/client"
	"github.com/WriterInternal/cerebro/desktop-agent/internal/collector"
	"github.com/WriterInternal/cerebro/desktop-agent/internal/config"
	"github.com/WriterInternal/cerebro/desktop-agent/internal/runtime"
)

func main() {
	cfg := config.Load()

	logger := log.New(os.Stdout, "cerebro-agent ", log.LstdFlags|log.Lmsgprefix)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	svc, err := client.New(cfg)
	if err != nil {
		logger.Fatalf("failed to prepare client: %v", err)
	}

	manager := runtime.NewManager(cfg, svc, logger)
	manager.RegisterSnapshot(collector.NewSnapshotCollector())
	manager.RegisterEvent(collector.NewProcessWatcher())

	if cfg.Once {
		if err := manager.RunOnce(ctx); err != nil {
			logger.Fatalf("collection failed: %v", err)
		}
		return
	}

	if err := manager.Run(ctx); err != nil {
		logger.Fatalf("manager error: %v", err)
	}
}
