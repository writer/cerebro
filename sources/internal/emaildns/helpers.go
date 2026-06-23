package emaildns

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
)

func evaluateMX(ctx context.Context, resolver Resolver, domain string, result *Health) {
	mxRecords, mxErr := resolver.LookupMX(ctx, domain)
	if mxErr != nil {
		result.Issues = append(result.Issues, makeIssue("MX", SeverityMedium, "mx_lookup_failed", "MX lookup failed", mxErr.Error(), "Verify MX records exist and can be resolved publicly."))
	}
	if len(mxRecords) == 0 {
		result.Issues = append(result.Issues, makeIssue("MX", SeverityMedium, "mx_missing", "MX records missing", "No MX records were found for this domain.", "Publish MX records for inbound mail delivery."))
		return
	}
	sort.Slice(mxRecords, func(i, j int) bool {
		if mxRecords[i].Pref == mxRecords[j].Pref {
			return mxRecords[i].Host < mxRecords[j].Host
		}
		return mxRecords[i].Pref < mxRecords[j].Pref
	})
	for _, mx := range mxRecords {
		result.MXRecords = append(result.MXRecords, fmt.Sprintf("%d %s", mx.Pref, strings.TrimSuffix(mx.Host, ".")))
	}
}

func evaluateRelated(ctx context.Context, resolver Resolver, domain string, result *Health) {
	for _, related := range []string{"_mta-sts." + domain, "_smtp._tls." + domain, "default._bimi." + domain} {
		txt, err := resolver.LookupTXT(ctx, related)
		if err != nil || len(txt) == 0 {
			continue
		}
		for _, value := range txt {
			result.RelatedRecords = append(result.RelatedRecords, fmt.Sprintf("%s TXT %s", related, strings.TrimSpace(value)))
		}
	}
	sort.Strings(result.RelatedRecords)
}

func makeIssue(protocol, severity, code, title, detail, recommendation string) Issue {
	return Issue{ID: protocol + ":" + code, Protocol: protocol, Severity: severity, Code: code, Title: title, Detail: detail, Recommendation: recommendation}
}

func filterTXTPrefix(records []string, prefix string) []string {
	out := make([]string, 0, len(records))
	for _, record := range records {
		trimmed := strings.TrimSpace(record)
		if strings.HasPrefix(strings.ToLower(trimmed), strings.ToLower(prefix)) {
			out = append(out, trimmed)
		}
	}
	sort.Strings(out)
	return out
}

func parseTagRecord(record string) map[string]string {
	out := map[string]string{}
	for _, segment := range strings.Split(record, ";") {
		part := strings.TrimSpace(segment)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		out[strings.ToLower(strings.TrimSpace(kv[0]))] = strings.TrimSpace(kv[1])
	}
	return out
}

func sortIssues(issues []Issue) {
	sort.SliceStable(issues, func(i, j int) bool {
		li := SeverityRank(issues[i].Severity)
		lj := SeverityRank(issues[j].Severity)
		if li != lj {
			return li > lj
		}
		if issues[i].Protocol != issues[j].Protocol {
			return issues[i].Protocol < issues[j].Protocol
		}
		return issues[i].Code < issues[j].Code
	})
}

// SeverityRank converts a severity string into a numeric rank where higher
// numbers indicate more severe issues. Returned ranks are stable across
// callers so source attributes and finding rule logic agree.
func SeverityRank(severity string) int {
	switch strings.ToUpper(strings.TrimSpace(severity)) {
	case SeverityCrit:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

func issueScore(issues []Issue) int {
	score := 100
	for _, issue := range issues {
		switch strings.ToUpper(issue.Severity) {
		case SeverityCrit:
			score -= 30
		case SeverityHigh:
			score -= 20
		case SeverityMedium:
			score -= 10
		case SeverityLow:
			score -= 5
		default:
			score -= 2
		}
	}
	if score < 0 {
		return 0
	}
	return score
}

func failingIssueCount(issues []Issue) int {
	count := 0
	for _, issue := range issues {
		if SeverityRank(issue.Severity) >= 3 {
			count++
		}
	}
	return count
}

func protocolStatus(protocol string, issues []Issue, hasRecords bool) string {
	maxRank := -1
	for _, issue := range issues {
		if !strings.EqualFold(issue.Protocol, protocol) {
			continue
		}
		if rank := SeverityRank(issue.Severity); rank > maxRank {
			maxRank = rank
		}
	}
	switch {
	case maxRank >= 3:
		return StatusFailing
	case maxRank >= 1:
		return StatusWarning
	case hasRecords:
		return StatusHealthy
	default:
		return StatusUnknown
	}
}

func overallStatus(spfStatus, dkimStatus, dmarcStatus string, issues []Issue) string {
	for _, issue := range issues {
		if SeverityRank(issue.Severity) >= 3 {
			return StatusFailing
		}
	}
	for _, issue := range issues {
		if SeverityRank(issue.Severity) >= 1 {
			return StatusWarning
		}
	}
	if spfStatus == StatusUnknown && dkimStatus == StatusUnknown && dmarcStatus == StatusUnknown {
		return StatusUnknown
	}
	return StatusHealthy
}

// NormalizeDomain returns the canonical lowercase mail-domain form of raw,
// stripping URL prefixes, ports, and the leading "www.". It returns the
// empty string if raw is not a valid mail domain (for example IPs, internal
// suffixes, or malformed input).
func NormalizeDomain(raw string) string {
	candidate := strings.TrimSpace(strings.ToLower(raw))
	if candidate == "" {
		return ""
	}
	if strings.Contains(candidate, "@") {
		parts := strings.Split(candidate, "@")
		candidate = parts[len(parts)-1]
	}
	if strings.Contains(candidate, "://") {
		if parsed, err := url.Parse(candidate); err == nil && parsed.Host != "" {
			candidate = parsed.Host
		}
	}
	if strings.Contains(candidate, "/") {
		if parsed, err := url.Parse("https://" + candidate); err == nil && parsed.Host != "" {
			candidate = parsed.Host
		}
	}
	candidate = strings.Trim(candidate, "[]")
	candidate = strings.TrimSuffix(candidate, ".")
	if host, _, err := net.SplitHostPort(candidate); err == nil && host != "" {
		candidate = host
	} else if index := strings.LastIndex(candidate, ":"); index > 0 {
		candidate = candidate[:index]
	}
	for strings.HasPrefix(candidate, "www.") {
		candidate = strings.TrimPrefix(candidate, "www.")
	}
	if ip := net.ParseIP(candidate); ip != nil {
		return ""
	}
	if !emailDomainPattern.MatchString(candidate) {
		return ""
	}
	if strings.HasSuffix(candidate, ".local") || strings.HasSuffix(candidate, ".internal") {
		return ""
	}
	return candidate
}
