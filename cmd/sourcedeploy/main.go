// Command sourcedeploy renders the Pulumi config fragment that drives
// cerebro source ingestion in a given environment.
//
// Each source under sources/<id>/ may declare a deploy.yaml manifest. This
// tool walks the tree and emits a YAML fragment with cerebro:sourceSecretKeys
// and cerebro:sourceRuntimes suitable for inclusion in environment-specific
// deployment configuration. Orchestrator schedules remain private deployment
// cadence and are intentionally not rendered here.
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
	env := fs.String("env", "", "environment to render (e.g. dev, prod)")
	tenant := fs.String("tenant", "example", "tenant identifier embedded in qualified runtime ids")
	format := fs.String("format", "yaml", "output format: yaml or contract-json")
	imageTag := fs.String("image-tag", "", "optional runtime image tag embedded in contract-json output")
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
	var data []byte
	switch *format {
	case "yaml":
		data, err = fragment.MarshalYAML()
	case "contract-json":
		contract, contractErr := sourcedeploy.RenderContract(*sourcesRoot, manifests, sourcedeploy.ContractOptions{
			Environment: *env,
			TenantID:    *tenant,
			ImageTag:    *imageTag,
		})
		if contractErr != nil {
			return contractErr
		}
		data, err = contract.MarshalJSONStable()
		if err == nil {
			data = append(data, '\n')
		}
	default:
		return fmt.Errorf("unsupported -format %q", *format)
	}
	if err != nil {
		return err
	}
	if *out == "-" {
		_, err = os.Stdout.Write(data)
		return err
	}
	return os.WriteFile(*out, data, 0o600)
}
