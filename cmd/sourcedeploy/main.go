// Command sourcedeploy renders the Pulumi config fragment that drives
// cerebro source ingestion in a given environment.
//
// Each source under sources/<id>/ may declare a deploy.yaml manifest. This
// tool walks the tree and emits a YAML fragment with cerebro:sourceSecretKeys
// and cerebro:sourceRuntimes suitable for inclusion in infra/aws/Pulumi.<env>.yaml
// in the WriterInternal/cerebro repository. Orchestrator schedules remain
// private infra cadence and are intentionally not rendered here.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/writer/cerebro/tools/sourcedeploy"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("sourcedeploy", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	sourcesRoot := fs.String("sources", "sources", "directory containing per-source manifests")
	env := fs.String("env", "", "environment to render (e.g. sec-dev, go-prod)")
	tenant := fs.String("tenant", "writer", "tenant identifier embedded in qualified runtime ids")
	out := fs.String("out", "-", "output path; '-' writes to stdout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *env == "" {
		fs.Usage()
		return fmt.Errorf("-env is required")
	}

	manifests, err := sourcedeploy.Discover(*sourcesRoot)
	if err != nil {
		return err
	}
	fragment, err := sourcedeploy.Render(manifests, sourcedeploy.RenderOptions{
		Environment: *env,
		TenantID:    *tenant,
	})
	if err != nil {
		return err
	}
	data, err := fragment.MarshalYAML()
	if err != nil {
		return err
	}
	if *out == "-" {
		_, err = os.Stdout.Write(data)
		return err
	}
	return os.WriteFile(*out, data, 0o644)
}
