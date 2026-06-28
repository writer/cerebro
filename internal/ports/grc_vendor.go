package ports

import (
	"context"
	"errors"
	"strings"
	"time"
)

const (
	GRCVendorDiscoveryDecisionApproved = "approved"
	GRCVendorDiscoveryDecisionRejected = "rejected"
	GRCVendorDiscoveryDecisionIgnored  = "ignored"
	GRCVendorDiscoveryDecisionLinked   = "linked"
)

var ErrGRCVendorDiscoveryDecisionNotFound = errors.New("grc vendor discovery decision not found")

type GRCVendorDiscoveryDecisionRecord struct {
	TenantID        string            `json:"tenant_id"`
	DiscoveryURN    string            `json:"discovery_urn"`
	SourceID        string            `json:"source_id,omitempty"`
	DecisionEventID string            `json:"decision_event_id,omitempty"`
	Version         int               `json:"version,omitempty"`
	Decision        string            `json:"decision"`
	Reason          string            `json:"reason,omitempty"`
	LinkedVendorURN string            `json:"linked_vendor_urn,omitempty"`
	UpdatedBy       string            `json:"updated_by,omitempty"`
	Attributes      map[string]string `json:"attributes,omitempty"`
	CreatedAt       time.Time         `json:"created_at"`
	UpdatedAt       time.Time         `json:"updated_at"`
}

type GRCVendorDiscoveryDecisionEventRecord struct {
	ID                string            `json:"id"`
	TenantID          string            `json:"tenant_id"`
	DiscoveryURN      string            `json:"discovery_urn"`
	SourceID          string            `json:"source_id,omitempty"`
	Decision          string            `json:"decision"`
	Reason            string            `json:"reason,omitempty"`
	LinkedVendorURN   string            `json:"linked_vendor_urn,omitempty"`
	UpdatedBy         string            `json:"updated_by,omitempty"`
	Attributes        map[string]string `json:"attributes,omitempty"`
	Version           int               `json:"version"`
	SupersedesEventID string            `json:"supersedes_event_id,omitempty"`
	CreatedAt         time.Time         `json:"created_at"`
}

type GRCVendorDiscoveryDecisionFilter struct {
	TenantID      string
	DiscoveryURNs []string
	SourceID      string
	Decision      string
	Limit         uint32
}

type GRCVendorDiscoveryDecisionEventFilter struct {
	TenantID      string
	DiscoveryURNs []string
	SourceID      string
	Decision      string
	Limit         uint32
}

type GRCVendorDiscoveryDecisionStore interface {
	StateStore
	UpsertGRCVendorDiscoveryDecision(context.Context, GRCVendorDiscoveryDecisionRecord) (*GRCVendorDiscoveryDecisionRecord, error)
	ListGRCVendorDiscoveryDecisions(context.Context, GRCVendorDiscoveryDecisionFilter) ([]*GRCVendorDiscoveryDecisionRecord, error)
	ListGRCVendorDiscoveryDecisionEvents(context.Context, GRCVendorDiscoveryDecisionEventFilter) ([]*GRCVendorDiscoveryDecisionEventRecord, error)
}

func IsGRCVendorDiscoveryDecision(value string) bool {
	switch strings.TrimSpace(value) {
	case GRCVendorDiscoveryDecisionApproved,
		GRCVendorDiscoveryDecisionRejected,
		GRCVendorDiscoveryDecisionIgnored,
		GRCVendorDiscoveryDecisionLinked:
		return true
	default:
		return false
	}
}
