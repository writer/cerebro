// Per-source connector-definition JSON writer for the Source CDK promotion path.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/writer/cerebro/internal/connectorimport"
)

// writeDefinitionJSON writes each catalog-ready outcome's connector definition
// as <dir>/<source_id>.json. These files are consumable directly by
// `cerebro source-runtime sdk new <id> definition=<path>`, which lets a
// survivor be promoted to a full Source CDK package without first round-tripping
// through the built-in catalog (and without leaving a shadowed catalog entry to
// clean up afterwards).
func writeDefinitionJSON(dir string, outcomes []connectorimport.Outcome) (int, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return 0, fmt.Errorf("create defs dir %s: %w", dir, err)
	}
	written := 0
	for _, outcome := range outcomes {
		if !outcome.CatalogReady() {
			continue
		}
		payload, err := json.MarshalIndent(outcome.Definition, "", "  ")
		if err != nil {
			return written, fmt.Errorf("marshal definition %s: %w", outcome.SourceID, err)
		}
		path := filepath.Join(dir, outcome.SourceID+".json")
		if err := os.WriteFile(path, append(payload, '\n'), 0o600); err != nil {
			return written, fmt.Errorf("write definition %s: %w", path, err)
		}
		written++
	}
	return written, nil
}
