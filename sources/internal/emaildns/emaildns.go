// Package emaildns is a small Source CDK helper for evaluating SPF, DKIM,
// DMARC, MX, and adjacent email-authentication posture for a single mail
// domain. It is intentionally protocol-only: it owns the DNS lookups,
// scoring, and severity ranking but emits no events. Source packages
// translate the resulting Health value into their own EventEnvelopes.
package emaildns

import (
	"context"
	"net"
	"regexp"
)

const (
	StatusHealthy  = "HEALTHY"
	StatusWarning  = "WARNING"
	StatusFailing  = "FAILING"
	StatusUnknown  = "UNKNOWN"
	SeverityCrit   = "CRITICAL"
	SeverityHigh   = "HIGH"
	SeverityMedium = "MEDIUM"
	SeverityLow    = "LOW"
)

var emailDomainPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)

// DefaultDKIMSelectors lists common DKIM selectors probed when the caller
// does not supply tenant-specific overrides.
var DefaultDKIMSelectors = []string{
	"default", "google", "selector1", "selector2", "s1", "s2", "k1", "k2", "mail", "mx",
}

// Resolver is the minimal DNS surface used by Evaluate.
type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
}

// NetResolver wraps net.DefaultResolver so callers can use the network
// resolver without redeclaring the adapter.
type NetResolver struct{}

func (NetResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return net.DefaultResolver.LookupTXT(ctx, name)
}

func (NetResolver) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	return net.DefaultResolver.LookupMX(ctx, name)
}

// DKIMSelector captures the result of probing a single DKIM selector.
type DKIMSelector struct {
	Selector string `json:"selector"`
	Status   string `json:"status"`
	KeyBits  int    `json:"key_bits"`
	Record   string `json:"record"`
}

// Issue describes a single SPF/DKIM/DMARC/MX problem discovered for a domain.
type Issue struct {
	ID             string `json:"id"`
	Protocol       string `json:"protocol"`
	Severity       string `json:"severity"`
	Code           string `json:"code"`
	Title          string `json:"title"`
	Detail         string `json:"detail"`
	Recommendation string `json:"recommendation"`
}

// Health is the structured email-authentication evaluation for one domain.
type Health struct {
	Domain            string         `json:"domain"`
	Status            string         `json:"status"`
	Score             int            `json:"score"`
	SPFStatus         string         `json:"spf_status"`
	DKIMStatus        string         `json:"dkim_status"`
	DMARCStatus       string         `json:"dmarc_status"`
	IssueCount        int            `json:"issue_count"`
	FailingIssueCount int            `json:"failing_issue_count"`
	SPFRecords        []string       `json:"spf_records"`
	SPFPolicy         string         `json:"spf_policy"`
	SPFLookupCount    int            `json:"spf_lookup_count"`
	DMARCRecords      []string       `json:"dmarc_records"`
	DMARCPolicy       string         `json:"dmarc_policy"`
	DMARCPct          int            `json:"dmarc_pct"`
	DMARCRua          []string       `json:"dmarc_rua"`
	MXRecords         []string       `json:"mx_records"`
	DKIMSelectors     []DKIMSelector `json:"dkim_selectors"`
	RelatedRecords    []string       `json:"related_records"`
	Issues            []Issue        `json:"issues"`
}

// Evaluate runs SPF/DKIM/DMARC/MX/MTA-STS/BIMI checks for the given domain
// using resolver. Results are deterministic given equivalent DNS input.
func Evaluate(ctx context.Context, resolver Resolver, domain string, dkimSelectors []string) Health {
	if len(dkimSelectors) == 0 {
		dkimSelectors = DefaultDKIMSelectors
	}
	result := Health{
		Domain:         domain,
		SPFRecords:     []string{},
		DMARCRecords:   []string{},
		DMARCRua:       []string{},
		MXRecords:      []string{},
		DKIMSelectors:  []DKIMSelector{},
		RelatedRecords: []string{},
		Issues:         []Issue{},
	}
	evaluateSPF(ctx, resolver, domain, &result)
	evaluateDMARC(ctx, resolver, domain, &result)
	foundSelectors := evaluateDKIM(ctx, resolver, domain, dkimSelectors, &result)
	evaluateMX(ctx, resolver, domain, &result)
	evaluateRelated(ctx, resolver, domain, &result)

	if foundSelectors == 0 {
		result.Issues = append(result.Issues, makeIssue("DKIM", SeverityHigh, "dkim_missing", "No DKIM selectors discovered", "No known DKIM selector records were found.", "Publish DKIM selectors (for example default/selector1) with valid public keys."))
	}
	sortIssues(result.Issues)
	result.IssueCount = len(result.Issues)
	result.FailingIssueCount = failingIssueCount(result.Issues)
	result.SPFStatus = protocolStatus("SPF", result.Issues, len(result.SPFRecords) > 0)
	result.DKIMStatus = protocolStatus("DKIM", result.Issues, len(result.DKIMSelectors) > 0)
	result.DMARCStatus = protocolStatus("DMARC", result.Issues, len(result.DMARCRecords) > 0)
	result.Score = issueScore(result.Issues)
	result.Status = overallStatus(result.SPFStatus, result.DKIMStatus, result.DMARCStatus, result.Issues)
	return result
}
