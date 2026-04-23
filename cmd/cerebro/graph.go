package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/writer/cerebro/internal/bootstrap"
	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/graphrebuild"
	"github.com/writer/cerebro/internal/sourceregistry"
)

func runGraph(args []string) error {
	if len(args) == 0 {
		return usageError(fmt.Sprintf("usage: %s graph rebuild <runtime-id> [dry_run=true] [page_limit=N] [preview_limit=N]", os.Args[0]))
	}
	switch args[0] {
	case "rebuild":
		runtimeID, pageLimit, previewLimit, dryRun, err := parseGraphRebuildArgs(args[1:])
		if err != nil {
			return err
		}
		if !dryRun {
			return fmt.Errorf("graph rebuild currently only supports dry_run=true")
		}
		cfg, err := config.Load()
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}
		ctx := context.Background()
		deps, closeDeps, err := bootstrap.OpenDependencies(ctx, cfg)
		if err != nil {
			return fmt.Errorf("open dependencies: %w", err)
		}
		defer func() {
			if err := closeDeps(); err != nil {
				log.Printf("close dependencies: %v", err)
			}
		}()
		registry, err := sourceregistry.Builtin()
		if err != nil {
			return fmt.Errorf("open source registry: %w", err)
		}
		service := graphrebuild.New(registry, sourceRuntimeStore(deps.StateStore))
		result, err := service.RebuildDryRun(ctx, graphrebuild.Request{
			RuntimeID:    runtimeID,
			PageLimit:    pageLimit,
			PreviewLimit: previewLimit,
		})
		if err != nil {
			return err
		}
		return printJSON(result)
	default:
		return usageError(fmt.Sprintf("usage: %s graph rebuild <runtime-id> [dry_run=true] [page_limit=N] [preview_limit=N]", os.Args[0]))
	}
}

func parseGraphRebuildArgs(args []string) (string, uint32, int, bool, error) {
	if len(args) == 0 || strings.TrimSpace(args[0]) == "" {
		return "", 0, 0, false, usageError(fmt.Sprintf("usage: %s graph rebuild <runtime-id> [dry_run=true] [page_limit=N] [preview_limit=N]", os.Args[0]))
	}
	runtimeID := strings.TrimSpace(args[0])
	dryRun := true
	var (
		pageLimit    uint32
		previewLimit int
	)
	for _, arg := range args[1:] {
		key, value, ok := strings.Cut(arg, "=")
		if !ok {
			return "", 0, 0, false, usageError(fmt.Sprintf("expected key=value argument, got %q", arg))
		}
		switch strings.TrimSpace(key) {
		case "dry_run":
			parsed, err := strconv.ParseBool(strings.TrimSpace(value))
			if err != nil {
				return "", 0, 0, false, fmt.Errorf("parse dry_run: %w", err)
			}
			dryRun = parsed
		case "page_limit":
			parsed, err := strconv.ParseUint(strings.TrimSpace(value), 10, 32)
			if err != nil {
				return "", 0, 0, false, fmt.Errorf("parse page_limit: %w", err)
			}
			pageLimit = uint32(parsed)
		case "preview_limit":
			parsed, err := strconv.Atoi(strings.TrimSpace(value))
			if err != nil {
				return "", 0, 0, false, fmt.Errorf("parse preview_limit: %w", err)
			}
			previewLimit = parsed
		default:
			return "", 0, 0, false, usageError(fmt.Sprintf("unsupported graph rebuild argument %q", key))
		}
	}
	return runtimeID, pageLimit, previewLimit, dryRun, nil
}

func printJSON(value any) error {
	payload, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal response: %w", err)
	}
	if _, err := os.Stdout.Write(append(payload, '\n')); err != nil {
		return fmt.Errorf("write response: %w", err)
	}
	return nil
}
