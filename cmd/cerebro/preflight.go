package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/bootstrap"
	appconfig "github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/graphagent"
)

type preflightReceipt struct {
	Kind        string           `json:"kind"`
	Status      string           `json:"status"`
	GeneratedAt string           `json:"generated_at"`
	Checks      []preflightCheck `json:"checks"`
}

type preflightCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

type preflightOptions struct {
	Format string
	Stdout io.Writer
}

type preflightRuntime struct {
	loadConfig       func() (appconfig.Config, error)
	openDependencies func(context.Context, appconfig.Config) (bootstrap.Dependencies, func() error, error)
	probeLLM         func(context.Context, graphagent.LLMClient) error
}

func runDeploy(args []string) error {
	if len(args) == 0 {
		return usageError("usage: cerebro deploy [preflight]")
	}
	switch args[0] {
	case "preflight":
		return runDeployPreflight(args[1:], preflightOptions{Stdout: os.Stdout})
	default:
		return usageError("usage: cerebro deploy [preflight]")
	}
}

func runDeployPreflight(args []string, opts preflightOptions) error {
	if opts.Stdout == nil {
		opts.Stdout = os.Stdout
	}
	fs := flag.NewFlagSet("deploy preflight", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	format := fs.String("format", "json", "output format: json or text")
	if err := fs.Parse(args); err != nil {
		return err
	}
	opts.Format = strings.ToLower(strings.TrimSpace(firstNonEmptyString(opts.Format, *format)))
	if opts.Format == "" {
		opts.Format = "json"
	}
	receipt := executeDeployPreflight(context.Background())
	if err := writePreflightReceipt(opts.Stdout, receipt, opts.Format); err != nil {
		return err
	}
	if receipt.Status != "pass" {
		return fmt.Errorf("deploy preflight failed")
	}
	return nil
}

func executeDeployPreflight(ctx context.Context) preflightReceipt {
	return executeDeployPreflightWith(ctx, preflightRuntime{
		loadConfig:       appconfig.Load,
		openDependencies: bootstrap.OpenDependencies,
		probeLLM:         graphagent.ProbeLLM,
	})
}

func executeDeployPreflightWith(ctx context.Context, runtime preflightRuntime) (receipt preflightReceipt) {
	receipt = preflightReceipt{
		Kind:        "cerebro.deploy_preflight",
		Status:      "pass",
		GeneratedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	addCheck := func(name string, err error) {
		check := preflightCheck{Name: name, Status: "pass"}
		if err != nil {
			check.Status = "fail"
			check.Detail = preflightErrorDetail(err)
			receipt.Status = "fail"
		}
		receipt.Checks = append(receipt.Checks, check)
	}

	cfg, err := runtime.loadConfig()
	addCheck("config.load", err)
	if err != nil {
		return receipt
	}
	deps, closeDeps, err := runtime.openDependencies(ctx, cfg)
	addCheck("dependencies.open", err)
	if err != nil {
		return receipt
	}
	defer func() {
		addCheck("dependencies.close", closeDeps())
	}()
	addCheck("graph_agent_llm.probe", runtime.probeLLM(ctx, deps.GraphAgentLLM))
	return receipt
}

func writePreflightReceipt(w io.Writer, receipt preflightReceipt, format string) error {
	switch format {
	case "json":
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		return encoder.Encode(receipt)
	case "text":
		_, err := fmt.Fprintf(w, "deploy preflight: %s\n", receipt.Status)
		if err != nil {
			return err
		}
		for _, check := range receipt.Checks {
			line := fmt.Sprintf("- %s: %s", check.Name, check.Status)
			if check.Detail != "" {
				line += " (" + check.Detail + ")"
			}
			if _, err := fmt.Fprintln(w, line); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("unsupported preflight output format %q", format)
	}
}

func preflightErrorDetail(err error) string {
	if err == nil {
		return ""
	}
	detail := sanitizeLogValue(err.Error())
	if len(detail) > 240 {
		detail = detail[:240]
	}
	return detail
}
