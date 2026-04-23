package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/bootstrap"
	"github.com/writer/cerebro/internal/buildinfo"
	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/sourceops"
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
	case "source":
		return runSource(args[1:])
	case "version":
		fmt.Printf("%s %s\n", buildinfo.ServiceName, buildinfo.Version)
		return nil
	}
	return usageError(fmt.Sprintf("usage: %s [serve|version|source]", os.Args[0]))
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
		response, err := service.Check(context.Background(), &cerebrov1.CheckSourceRequest{
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
		response, err := service.Discover(context.Background(), &cerebrov1.DiscoverSourceRequest{
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
		response, err := service.Read(context.Background(), &cerebrov1.ReadSourceRequest{
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
		config[key] = value
	}
	return args[0], config, cursor, nil
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
