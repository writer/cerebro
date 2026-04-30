package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/bootstrap"
	"github.com/writer/cerebro/internal/buildinfo"
	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourceops"
	"github.com/writer/cerebro/internal/sourceprojection"
	"github.com/writer/cerebro/internal/sourceregistry"
	"github.com/writer/cerebro/internal/sourceruntime"
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
	case "graph":
		return runGraph(args[1:])
	case "finding-rule":
		return runFindingRule(args[1:])
	case "source":
		return runSource(args[1:])
	case "source-runtime":
		return runSourceRuntime(args[1:])
	case "version":
		fmt.Printf("%s %s\n", buildinfo.ServiceName, buildinfo.Version)
		return nil
	}
	return usageError(fmt.Sprintf("usage: %s [serve|version|graph|finding-rule|source|source-runtime]", os.Args[0]))
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

func runSource(args []string) error {
	if len(args) == 0 {
		return usageError(fmt.Sprintf("usage: %s source [list|check|discover|read] ...", os.Args[0]))
	}
	ctx := context.Background()
	registry, err := sourceregistry.Builtin()
	if err != nil {
		return fmt.Errorf("open source registry: %w", err)
	}
	service := sourceops.New(registry)

	switch args[0] {
	case "list":
		return printProto(service.List())
	case "check":
		sourceID, config, _, err := parseSourceCommandArgs(args[1:])
		if err != nil {
			return err
		}
		config, err = prepareSourceConfig(ctx, sourceID, "check", config)
		if err != nil {
			return err
		}
		response, err := service.Check(ctx, &cerebrov1.CheckSourceRequest{
			SourceId: sourceID,
			Config:   config,
		})
		if err != nil {
			return err
		}
		return printProto(response)
	case "discover":
		sourceID, config, _, err := parseSourceCommandArgs(args[1:])
		if err != nil {
			return err
		}
		config, err = prepareSourceConfig(ctx, sourceID, "discover", config)
		if err != nil {
			return err
		}
		response, err := service.Discover(ctx, &cerebrov1.DiscoverSourceRequest{
			SourceId: sourceID,
			Config:   config,
		})
		if err != nil {
			return err
		}
		return printProto(response)
	case "read":
		sourceID, config, cursor, err := parseSourceCommandArgs(args[1:])
		if err != nil {
			return err
		}
		config, err = prepareSourceConfig(ctx, sourceID, "read", config)
		if err != nil {
			return err
		}
		response, err := service.Read(ctx, &cerebrov1.ReadSourceRequest{
			SourceId: sourceID,
			Config:   config,
			Cursor:   cursor,
		})
		if err != nil {
			return err
		}
		return printProto(response)
	default:
		return usageError(fmt.Sprintf("usage: %s source [list|check|discover|read] ...", os.Args[0]))
	}
}

func runSourceRuntime(args []string) error {
	if len(args) == 0 {
		return usageError(fmt.Sprintf("usage: %s source-runtime [put|get|sync] ...", os.Args[0]))
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
	service := sourceruntime.New(
		registry,
		sourceRuntimeStore(deps.StateStore),
		deps.AppendLog,
		sourceProjector(deps.StateStore, deps.GraphStore),
	)

	switch args[0] {
	case "put":
		runtime, err := parseSourceRuntimePutArgs(args[1:])
		if err != nil {
			return err
		}
		runtime, err = prepareSourceRuntime(ctx, runtime)
		if err != nil {
			return err
		}
		response, err := service.Put(ctx, &cerebrov1.PutSourceRuntimeRequest{Runtime: runtime})
		if err != nil {
			return err
		}
		return printProto(response)
	case "get":
		if len(args) < 2 || strings.TrimSpace(args[1]) == "" {
			return usageError(fmt.Sprintf("usage: %s source-runtime get <runtime-id>", os.Args[0]))
		}
		response, err := service.Get(ctx, &cerebrov1.GetSourceRuntimeRequest{Id: strings.TrimSpace(args[1])})
		if err != nil {
			return err
		}
		return printProto(response)
	case "sync":
		runtimeID, pageLimit, err := parseSourceRuntimeSyncArgs(args[1:])
		if err != nil {
			return err
		}
		response, err := service.Sync(ctx, &cerebrov1.SyncSourceRuntimeRequest{
			Id:        runtimeID,
			PageLimit: pageLimit,
		})
		if err != nil {
			return err
		}
		return printProto(response)
	default:
		return usageError(fmt.Sprintf("usage: %s source-runtime [put|get|sync] ...", os.Args[0]))
	}
}

func parseSourceCommandArgs(args []string) (string, map[string]string, *cerebrov1.SourceCursor, error) {
	if len(args) == 0 {
		return "", nil, nil, usageError(fmt.Sprintf("usage: %s source <command> <source-id> [key=value ...]", os.Args[0]))
	}
	config := make(map[string]string)
	var cursor *cerebrov1.SourceCursor
	for _, arg := range args[1:] {
		key, value, ok := strings.Cut(arg, "=")
		if !ok {
			return "", nil, nil, fmt.Errorf("invalid source argument %q; want key=value", arg)
		}
		if key == "cursor" {
			cursor = &cerebrov1.SourceCursor{Opaque: value}
			continue
		}
		resolved, err := sourceConfigValueFromArg(key, value)
		if err != nil {
			return "", nil, nil, err
		}
		config[key] = resolved
	}
	return args[0], config, cursor, nil
}

func parseSourceRuntimePutArgs(args []string) (*cerebrov1.SourceRuntime, error) {
	if len(args) < 2 {
		return nil, usageError(fmt.Sprintf("usage: %s source-runtime put <runtime-id> <source-id> [tenant_id=<tenant-id>] [key=value ...]", os.Args[0]))
	}
	runtime := &cerebrov1.SourceRuntime{
		Id:       strings.TrimSpace(args[0]),
		SourceId: strings.TrimSpace(args[1]),
		Config:   make(map[string]string),
	}
	if runtime.GetId() == "" || runtime.GetSourceId() == "" {
		return nil, usageError(fmt.Sprintf("usage: %s source-runtime put <runtime-id> <source-id> [tenant_id=<tenant-id>] [key=value ...]", os.Args[0]))
	}
	for _, arg := range args[2:] {
		key, value, ok := strings.Cut(arg, "=")
		if !ok {
			return nil, fmt.Errorf("invalid source runtime argument %q; want key=value", arg)
		}
		if key == "tenant_id" {
			runtime.TenantId = strings.TrimSpace(value)
			continue
		}
		resolved, err := sourceConfigValueFromArg(key, value)
		if err != nil {
			return nil, err
		}
		runtime.Config[key] = resolved
	}
	return runtime, nil
}

func sourceConfigValueFromArg(key string, value string) (string, error) {
	sensitive := sensitiveCLIConfigKey(key)
	if strings.HasPrefix(value, "env:") && !literalEnvPrefixCLIConfigKey(key) {
		return sourceConfigValueFromEnv(key, value)
	}
	if sensitive && strings.TrimSpace(value) != "" {
		return "", fmt.Errorf("source config %q is sensitive; pass env:VAR instead of a literal value", strings.TrimSpace(key))
	}
	return value, nil
}

func sourceConfigValueFromEnv(key string, value string) (string, error) {
	envName := strings.TrimSpace(strings.TrimPrefix(value, "env:"))
	if envName == "" {
		return "", fmt.Errorf("source config %q env reference is missing a variable name", strings.TrimSpace(key))
	}
	resolved, ok := os.LookupEnv(envName)
	if !ok {
		return "", fmt.Errorf("source config %q references unset environment variable %q", strings.TrimSpace(key), envName)
	}
	if sensitiveCLIConfigKey(key) && strings.TrimSpace(resolved) == "" {
		return "", fmt.Errorf("source config %q references empty environment variable %q", strings.TrimSpace(key), envName)
	}
	return resolved, nil
}

func literalEnvPrefixCLIConfigKey(key string) bool {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "filter", "phrase", "q", "search":
		return true
	default:
		return false
	}
}

func sensitiveCLIConfigKey(key string) bool {
	value := strings.ToLower(strings.TrimSpace(key))
	if value == "" {
		return false
	}
	if strings.Contains(value, "token") || strings.Contains(value, "secret") || strings.Contains(value, "password") {
		return true
	}
	compact := strings.NewReplacer("_", "", "-", "", ".", "").Replace(value)
	return compact == "key" ||
		strings.Contains(compact, "apikey") ||
		strings.Contains(compact, "privatekey")
}

func parseSourceRuntimeSyncArgs(args []string) (string, uint32, error) {
	if len(args) == 0 || strings.TrimSpace(args[0]) == "" {
		return "", 0, usageError(fmt.Sprintf("usage: %s source-runtime sync <runtime-id> [page_limit=N]", os.Args[0]))
	}
	runtimeID := strings.TrimSpace(args[0])
	var pageLimit uint32
	for _, arg := range args[1:] {
		key, value, ok := strings.Cut(arg, "=")
		if !ok {
			return "", 0, fmt.Errorf("invalid source runtime argument %q; want key=value", arg)
		}
		if key != "page_limit" {
			return "", 0, fmt.Errorf("unsupported source runtime argument %q", key)
		}
		parsed, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return "", 0, fmt.Errorf("parse page_limit: %w", err)
		}
		pageLimit = uint32(parsed)
	}
	return runtimeID, pageLimit, nil
}

func sourceRuntimeStore(store ports.StateStore) ports.SourceRuntimeStore {
	runtimeStore, ok := store.(ports.SourceRuntimeStore)
	if !ok {
		return nil
	}
	return runtimeStore
}

func sourceProjectionStateStore(store ports.StateStore) ports.ProjectionStateStore {
	projectionStore, ok := store.(ports.ProjectionStateStore)
	if !ok {
		return nil
	}
	return projectionStore
}

func sourceProjectionGraphStore(store ports.GraphStore) ports.ProjectionGraphStore {
	projectionStore, ok := store.(ports.ProjectionGraphStore)
	if !ok {
		return nil
	}
	return projectionStore
}

func sourceProjector(stateStore ports.StateStore, graphStore ports.GraphStore) ports.SourceProjector {
	state := sourceProjectionStateStore(stateStore)
	graph := sourceProjectionGraphStore(graphStore)
	if state == nil && graph == nil {
		return nil
	}
	return sourceprojection.New(state, graph)
}

func printProto(message proto.Message) error {
	payload, err := protojson.MarshalOptions{
		UseProtoNames:   true,
		EmitUnpopulated: true,
	}.Marshal(message)
	if err != nil {
		return fmt.Errorf("marshal response: %w", err)
	}
	if _, err := os.Stdout.Write(append(payload, '\n')); err != nil {
		return fmt.Errorf("write response: %w", err)
	}
	return nil
}
