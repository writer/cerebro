// Package emaildns is a small Source CDK helper for evaluating SPF, DKIM,
// DMARC, MX, and adjacent email-authentication posture for a single mail
// domain. It is intentionally protocol-only: it owns the DNS lookups,
// scoring, and severity ranking but emits no events. Source packages
// translate the resulting Health value into their own EventEnvelopes.
package emaildns

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
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

func evaluateDKIM(ctx context.Context, resolver Resolver, domain string, dkimSelectors []string, result *Health) int {
	found := 0
	for _, selector := range dkimSelectors {
		recordName := selector + "._domainkey." + domain
		values, err := resolver.LookupTXT(ctx, recordName)
		if err != nil {
			continue
		}
		dkimRecords := filterTXTPrefix(values, "v=dkim1")
		if len(dkimRecords) == 0 {
			continue
		}
		found++
		record := dkimRecords[0]
		tags := parseTagRecord(record)
		keyValue := strings.TrimSpace(tags["p"])
		algorithm := dkimKeyAlgorithm(tags["k"])
		keyBits, keyValid := dkimKeyBits(keyValue, algorithm)
		status := StatusHealthy
		switch {
		case keyValue == "":
			status = StatusFailing
			result.Issues = append(result.Issues, makeIssue("DKIM", SeverityHigh, "dkim_missing_key", "DKIM public key missing", fmt.Sprintf("Selector %s is missing p= key material.", selector), "Publish valid DKIM public key material in p=."))
		case !keyValid:
			status = StatusFailing
			result.Issues = append(result.Issues, makeIssue("DKIM", SeverityHigh, "dkim_invalid_key", "DKIM public key is not valid base64", fmt.Sprintf("Selector %s p= value did not decode as base64 key material.", selector), "Republish the DKIM selector with valid base64-encoded key material."))
		case algorithm == "ed25519" && keyBits != 256:
			status = StatusFailing
			result.Issues = append(result.Issues, makeIssue("DKIM", SeverityHigh, "dkim_invalid_ed25519_key", "DKIM Ed25519 key length is invalid", fmt.Sprintf("Selector %s Ed25519 key size is %d bits; expected 256 bits.", selector, keyBits), "Republish the Ed25519 selector with a 32-byte public key."))
		case algorithm == "rsa" && keyBits < 1024:
			status = StatusFailing
			result.Issues = append(result.Issues, makeIssue("DKIM", SeverityCrit, "dkim_weak_key", "DKIM RSA key is too weak", fmt.Sprintf("Selector %s RSA key size is %d bits.", selector, keyBits), "Rotate selector to at least 2048-bit RSA key material."))
		case algorithm == "rsa" && keyBits < 2048:
			status = StatusWarning
			result.Issues = append(result.Issues, makeIssue("DKIM", SeverityMedium, "dkim_key_short", "DKIM RSA key length below recommended", fmt.Sprintf("Selector %s RSA key size is %d bits.", selector, keyBits), "Rotate selector to a 2048-bit RSA key."))
		}
		result.DKIMSelectors = append(result.DKIMSelectors, DKIMSelector{Selector: selector, Status: status, KeyBits: keyBits, Record: record})
	}
	return found
}

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

func spfTerminalPolicy(record string) string {
	fields := strings.Fields(strings.ToLower(record))
	for i := len(fields) - 1; i >= 0; i-- {
		field := strings.TrimSpace(fields[i])
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

func dkimKeyAlgorithm(raw string) string {
	algorithm := strings.ToLower(strings.TrimSpace(raw))
	if algorithm == "" {
		return "rsa"
	}
	return algorithm
}

// dkimKeyBits decodes the DKIM p= public-key payload and returns the key
// length in bits along with a flag indicating whether the payload was valid
// base64. Empty payloads return (0, true) so callers can distinguish a
// missing key from a malformed one. RSA keys use parsed modulus size when the
// payload is DER-encoded, falling back to byte length for legacy fixtures.
func dkimKeyBits(publicKey string, algorithm string) (int, bool) {
	cleaned := strings.ReplaceAll(strings.TrimSpace(publicKey), " ", "")
	if cleaned == "" {
		return 0, true
	}
	decoded, err := base64.StdEncoding.DecodeString(cleaned)
	if err != nil {
		return 0, false
	}
	if algorithm == "rsa" {
		if bits := rsaPublicKeyBits(decoded); bits > 0 {
			return bits, true
		}
	}
	return len(decoded) * 8, true
}

func rsaPublicKeyBits(der []byte) int {
	if key, err := x509.ParsePKIXPublicKey(der); err == nil {
		if rsaKey, ok := key.(*rsa.PublicKey); ok && rsaKey.N != nil {
			return rsaKey.N.BitLen()
		}
	}
	if key, err := x509.ParsePKCS1PublicKey(der); err == nil && key.N != nil {
		return key.N.BitLen()
	}
	return 0
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
