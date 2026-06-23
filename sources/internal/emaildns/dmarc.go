package emaildns

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

func evaluateDMARC(ctx context.Context, resolver Resolver, domain string, result *Health) {
	dmarcTXT, dmarcErr := resolver.LookupTXT(ctx, "_dmarc."+domain)
	dmarcRecords := filterTXTPrefix(dmarcTXT, "v=dmarc1")
	result.DMARCRecords = dmarcRecords
	if dmarcErr != nil {
		result.Issues = append(result.Issues, makeIssue("DMARC", SeverityMedium, "dmarc_lookup_failed", "DMARC lookup failed", dmarcErr.Error(), "Confirm _dmarc TXT records resolve."))
	}
	if len(dmarcRecords) == 0 {
		result.Issues = append(result.Issues, makeIssue("DMARC", SeverityHigh, "dmarc_missing", "DMARC record missing", "No DMARC TXT record was found.", "Publish a DMARC record with at least p=none and reporting, then move to p=quarantine/reject."))
		return
	}
	if len(dmarcRecords) > 1 {
		result.Issues = append(result.Issues, makeIssue("DMARC", SeverityHigh, "dmarc_multiple", "Multiple DMARC records found", fmt.Sprintf("Detected %d DMARC records.", len(dmarcRecords)), "Keep exactly one DMARC TXT record at _dmarc.<domain>."))
	}
	tags := parseTagRecord(dmarcRecords[0])
	policy := strings.ToLower(strings.TrimSpace(tags["p"]))
	result.DMARCPolicy = strings.ToUpper(policy)
	switch policy {
	case "":
		result.Issues = append(result.Issues, makeIssue("DMARC", SeverityHigh, "dmarc_policy_missing", "DMARC policy missing", "The p= tag is missing in the DMARC record.", "Add p=quarantine or p=reject after baseline monitoring."))
	case "none":
		result.Issues = append(result.Issues, makeIssue("DMARC", SeverityMedium, "dmarc_policy_none", "DMARC policy is monitoring-only", "DMARC policy is set to p=none.", "Move to p=quarantine or p=reject for enforcement."))
	case "quarantine", "reject":
	default:
		result.Issues = append(result.Issues, makeIssue("DMARC", SeverityHigh, "dmarc_policy_invalid", "DMARC policy value is invalid", fmt.Sprintf("p=%s is not one of none|quarantine|reject and will be treated as p=none by receivers.", policy), "Set p= to none, quarantine, or reject per RFC 7489."))
	}
	result.DMARCPct = 100
	if pct, err := strconv.Atoi(strings.TrimSpace(tags["pct"])); err == nil {
		result.DMARCPct = pct
		if pct < 100 {
			result.Issues = append(result.Issues, makeIssue("DMARC", SeverityLow, "dmarc_partial_pct", "DMARC enforcement is partial", fmt.Sprintf("pct=%d applies policy to only part of traffic.", pct), "Set pct=100 once confidence is high."))
		}
	}
	result.DMARCRua = parseDMARCReportAddresses(tags["rua"])
	if len(result.DMARCRua) == 0 {
		result.Issues = append(result.Issues, makeIssue("DMARC", SeverityLow, "dmarc_rua_missing", "DMARC aggregate reporting missing", "No rua reporting address is configured.", "Configure rua=mailto:... to collect aggregate authentication reports."))
	}
}

func parseDMARCReportAddresses(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return []string{}
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		out = append(out, trimmed)
	}
	sort.Strings(out)
	return out
}
