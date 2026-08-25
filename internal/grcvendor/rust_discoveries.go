package grcvendor

import (
	"fmt"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

// ResolvedRuntimeIDs preserves the single-runtime selector's precedence over
// the multi-runtime selector while returning an owned slice.
func ResolvedRuntimeIDs(runtimeID string, runtimeIDs []string) []string {
	if runtimeID != "" {
		return []string{runtimeID}
	}
	return append([]string{}, runtimeIDs...)
}

// DiscoveriesResponse is the product response backed by the Rust graph read.
type DiscoveriesResponse struct {
	Summary           DiscoverySummary                               `json:"summary"`
	Discoveries       []VendorDiscovery                              `json:"discoveries"`
	SourceSummaries   []ports.VendorDiscoverySourceSummary           `json:"source_summaries"`
	Decisions         []*ports.GRCVendorDiscoveryDecisionRecord      `json:"decisions,omitempty"`
	DecisionEvents    []*ports.GRCVendorDiscoveryDecisionEventRecord `json:"decision_events,omitempty"`
	GraphRevision     uint64                                         `json:"graph_revision"`
	DataAuthority     string                                         `json:"data_authority"`
	DecisionAuthority string                                         `json:"decision_authority"`
	GeneratedAt       string                                         `json:"generated_at"`
}

// DiscoveriesFromRust maps the portable Rust graph contract into the stable
// vendor-discovery product model. Invalid Rust timestamps fail the read closed.
func DiscoveriesFromRust(rows []ports.VendorDiscoveryRow) ([]VendorDiscovery, error) {
	discoveries := make([]VendorDiscovery, 0, len(rows))
	for _, row := range rows {
		var decisionUpdatedAt *time.Time
		if raw := strings.TrimSpace(row.DecisionUpdatedAt); raw != "" {
			parsed, err := time.Parse(time.RFC3339, raw)
			if err != nil {
				return nil, fmt.Errorf("%w: rust vendor discovery returned an invalid decision timestamp", ErrRuntimeUnavailable)
			}
			parsed = parsed.UTC()
			decisionUpdatedAt = &parsed
		}
		signals := make([]VendorDiscoverySignal, 0, len(row.Signals))
		for _, signal := range row.Signals {
			signals = append(signals, VendorDiscoverySignal{ID: signal.ID, Label: signal.Label, SourceID: signal.SourceID, RuntimeID: signal.RuntimeID, EntityType: signal.EntityType, EntityURN: signal.EntityURN, ConfidenceScore: signal.ConfidenceScore, ObservedAt: signal.ObservedAt, Reason: signal.Reason, Attributes: signal.Attributes})
		}
		discoveries = append(discoveries, VendorDiscovery{
			URN: row.URN, DiscoveryID: row.DiscoveryID, Name: row.Name, NormalizedName: row.NormalizedName, SourceID: row.SourceID, SourceIDs: append([]string{}, row.SourceIDs...), RuntimeID: row.RuntimeID, Provider: row.Provider, SourceStatus: row.SourceStatus, DecisionState: row.DecisionState, Category: row.Category, WebsiteURL: row.WebsiteURL, ConfidenceScore: row.ConfidenceScore, DiscoveryReason: row.DiscoveryReason, FirstObservedAt: row.FirstObservedAt, LastObservedAt: row.LastObservedAt, LinkedVendorURN: row.LinkedVendorURN, DecisionReason: row.DecisionReason, DecisionUpdatedBy: row.DecisionUpdatedBy, DecisionUpdatedAt: decisionUpdatedAt, Signals: signals, Attributes: row.Attributes,
		})
	}
	return discoveries, nil
}
