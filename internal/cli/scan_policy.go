package cli

import (
	"fmt"
	"strings"

	"github.com/writer/cerebro/internal/app"
	"github.com/writer/cerebro/internal/scanpolicy"
)

func loadScanPolicyEvaluator(cfg *app.Config) (scanpolicy.Evaluator, error) {
	if cfg == nil {
		return nil, nil
	}
	path := strings.TrimSpace(cfg.ScanPoliciesPath)
	if path == "" {
		return nil, nil
	}
	engine, err := scanpolicy.Load(path)
	if err != nil {
		return nil, fmt.Errorf("load scan policies: %w", err)
	}
	return engine, nil
}
