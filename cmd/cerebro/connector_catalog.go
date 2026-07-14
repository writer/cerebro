package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"sort"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/connectorcatalog"
	"github.com/writer/cerebro/internal/sourcecertification"
	"github.com/writer/cerebro/internal/sourceregistry"
)

type connectorCatalogCLIEntry struct {
	SourceID      string                           `json:"source_id"`
	DisplayName   string                           `json:"display_name"`
	CatalogStatus string                           `json:"catalog_status,omitempty"`
	Certification sourcecertification.Result       `json:"certification"`
	Availability  sourcecertification.Availability `json:"availability"`
}

type connectorCatalogCLIResponse struct {
	Connectors  []connectorCatalogCLIEntry `json:"connectors"`
	GeneratedAt string                     `json:"generated_at"`
}

func runConnectorCatalog(args []string, output io.Writer) error {
	if len(args) == 0 || args[0] != "list" {
		return usageError("usage: cerebro connector-catalog list [--min-certification-tier tier] [--include-preview]")
	}
	flags := flag.NewFlagSet("connector-catalog list", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	minimum := flags.String("min-certification-tier", "cataloged", "minimum certification tier")
	includePreview := flags.Bool("include-preview", false, "mark below-minimum connectors for evaluation")
	if err := flags.Parse(args[1:]); err != nil {
		return usageError(err.Error())
	}
	tier, err := sourcecertification.ParseTier(*minimum)
	if err != nil {
		return usageError(err.Error())
	}
	response, err := loadConnectorCatalogCLIResponse(time.Now().UTC(), sourcecertification.AvailabilityPolicy{MinimumTier: tier, IncludePreview: *includePreview})
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	return encoder.Encode(response)
}

func loadConnectorCatalogCLIResponse(now time.Time, policy sourcecertification.AvailabilityPolicy) (connectorCatalogCLIResponse, error) {
	registry, err := sourceregistry.Builtin()
	if err != nil {
		return connectorCatalogCLIResponse{}, fmt.Errorf("load source registry: %w", err)
	}
	analysis, err := connectorcatalog.BuiltinRuntime()
	if err != nil {
		return connectorCatalogCLIResponse{}, fmt.Errorf("load connector catalog: %w", err)
	}
	return buildConnectorCatalogCLIResponse(now, policy, registry.List(), analysis), nil
}

func buildConnectorCatalogCLIResponse(now time.Time, policy sourcecertification.AvailabilityPolicy, specs []*cerebrov1.SourceSpec, analysis connectorcatalog.Analysis) connectorCatalogCLIResponse {
	statusBySource := map[string]string{}
	nameBySource := map[string]string{}
	for _, entry := range analysis.Entries {
		statusBySource[entry.Definition.SourceID] = entry.Status
		nameBySource[entry.Definition.SourceID] = entry.Definition.DisplayName
	}
	seen := map[string]bool{}
	entries := make([]connectorCatalogCLIEntry, 0, len(specs)+len(analysis.Entries))
	appendEntry := func(sourceID, displayName string) {
		if seen[sourceID] {
			return
		}
		seen[sourceID] = true
		certification := sourcecertification.CatalogResult(sourceID, now, sourcecertification.RuntimeObservation{})
		entries = append(entries, connectorCatalogCLIEntry{
			SourceID: sourceID, DisplayName: displayName, CatalogStatus: statusBySource[sourceID], Certification: certification,
			Availability: sourcecertification.ApplyAvailability(certification, false, policy),
		})
	}
	for _, spec := range specs {
		appendEntry(spec.GetId(), spec.GetName())
	}
	for sourceID, displayName := range nameBySource {
		appendEntry(sourceID, displayName)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].SourceID < entries[j].SourceID })
	return connectorCatalogCLIResponse{Connectors: entries, GeneratedAt: now.Format(time.RFC3339)}
}
