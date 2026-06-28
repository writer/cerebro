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
	Decision        string            `json:"decision"`
	Reason          string            `json:"reason,omitempty"`
	LinkedVendorURN string            `json:"linked_vendor_urn,omitempty"`
	UpdatedBy       string            `json:"updated_by,omitempty"`
	Attributes      map[string]string `json:"attributes,omitempty"`
	CreatedAt       time.Time         `json:"created_at"`
	UpdatedAt       time.Time         `json:"updated_at"`
}

type GRCVendorDiscoveryDecisionFilter struct {
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
