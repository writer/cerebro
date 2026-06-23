package emaildns

import (
	"context"
	"fmt"
	"strings"
)

func evaluateSPF(ctx context.Context, resolver Resolver, domain string, result *Health) {
	spfTXT, spfErr := resolver.LookupTXT(ctx, domain)
	spfRecords := filterTXTPrefix(spfTXT, "v=spf1")
	result.SPFRecords = spfRecords
	if spfErr != nil {
		result.Issues = append(result.Issues, makeIssue("SPF", SeverityMedium, "spf_lookup_failed", "SPF lookup failed", spfErr.Error(), "Confirm authoritative DNS responds for SPF TXT records."))
	}
	if len(spfRecords) == 0 {
		result.Issues = append(result.Issues, makeIssue("SPF", SeverityHigh, "spf_missing", "SPF record missing", "No SPF TXT record was found for this domain.", "Publish a single SPF TXT record that ends with '-all'."))
		return
	}
	if len(spfRecords) > 1 {
		result.Issues = append(result.Issues, makeIssue("SPF", SeverityHigh, "spf_multiple", "Multiple SPF records found", fmt.Sprintf("Detected %d SPF records.", len(spfRecords)), "Collapse to one SPF record to avoid permerror behavior."))
	}
	record := spfRecords[0]
	result.SPFPolicy = spfTerminalPolicy(record)
	result.SPFLookupCount = spfLookupCount(record)
	switch result.SPFPolicy {
	case "+all", "all":
		result.Issues = append(result.Issues, makeIssue("SPF", SeverityCrit, "spf_permissive_all", "SPF allows all senders", "SPF ends in '+all' which permits spoofing.", "Replace '+all' with '-all' after validating legitimate senders."))
	case "?all":
		result.Issues = append(result.Issues, makeIssue("SPF", SeverityHigh, "spf_neutral_all", "SPF uses neutral all", "SPF ends in '?all' which neither passes nor fails senders and offers no spoofing protection.", "Replace '?all' with '-all' after validating legitimate senders."))
	case "~all":
		result.Issues = append(result.Issues, makeIssue("SPF", SeverityMedium, "spf_softfail", "SPF uses soft-fail", "SPF ends in '~all' which is not strict enforcement.", "Move to '-all' when sender inventory is complete."))
	case "":
		result.Issues = append(result.Issues, makeIssue("SPF", SeverityMedium, "spf_no_terminal_policy", "SPF terminal policy missing", "SPF record does not include an all-mechanism policy.", "Add a terminal '-all' policy."))
	}
	if result.SPFLookupCount > 10 {
		result.Issues = append(result.Issues, makeIssue("SPF", SeverityHigh, "spf_lookup_limit_exceeded", "SPF lookup count exceeds RFC limit", fmt.Sprintf("Estimated lookup count is %d.", result.SPFLookupCount), "Reduce include/redirect mechanisms to 10 or fewer DNS lookups."))
	}
}

func spfTerminalPolicy(record string) string {
	fields := strings.Fields(strings.ToLower(record))
	hasRedirect := false
	for i := len(fields) - 1; i >= 0; i-- {
		field := strings.TrimSpace(fields[i])
		if strings.HasPrefix(field, "redirect=") && strings.TrimSpace(strings.TrimPrefix(field, "redirect=")) != "" {
			hasRedirect = true
			continue
		}
		if !strings.HasSuffix(field, "all") {
			continue
		}
		switch {
		case strings.HasPrefix(field, "+"):
			return "+all"
		case strings.HasPrefix(field, "-"):
			return "-all"
		case strings.HasPrefix(field, "~"):
			return "~all"
		case strings.HasPrefix(field, "?"):
			return "?all"
		default:
			return "all"
		}
	}
	if hasRedirect {
		return "redirect"
	}
	return ""
}

func spfLookupCount(record string) int {
	fields := strings.Fields(strings.ToLower(record))
	count := 0
	for _, field := range fields {
		switch {
		case strings.HasPrefix(field, "include:"),
			strings.HasPrefix(field, "exists:"),
			strings.HasPrefix(field, "redirect="),
			field == "a",
			strings.HasPrefix(field, "a:"),
			field == "mx",
			strings.HasPrefix(field, "mx:"),
			field == "ptr",
			strings.HasPrefix(field, "ptr:"):
			count++
		}
	}
	return count
}
