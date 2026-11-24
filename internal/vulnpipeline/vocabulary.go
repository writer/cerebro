package vulnpipeline

import (
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Normalized severity vocabulary. Source severity is preserved separately; this
// is the only severity scale observations are filtered and summarized on.
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityInfo     = "info"
	SeverityUnknown  = "unknown"
)

// Normalized lifecycle status vocabulary.
const (
	StatusOpen        = "open"
	StatusInProgress  = "in_progress"
	StatusSuppressed  = "suppressed"
	StatusNotAffected = "not_affected"
	StatusFixed       = "fixed"
)

// Observation classes describe what kind of subject a scanner examined.
const (
	ClassPackage        = "package"
	ClassContainerImage = "container_image"
	ClassHost           = "host"
	ClassCode           = "code"
	ClassWebApplication = "web_application"
	ClassCloudConfig    = "cloud_config"
	ClassOther          = "other"
)

// Severity scales a mapping can declare for numeric severity values.
const (
	SeverityScaleCVSS      = "cvss"
	SeverityScaleZeroFour  = "0-4"
	SeverityScaleOneFive   = "1-5"
	SeverityScaleLabelOnly = "label"
)

var (
	cvePattern    = regexp.MustCompile(`(?i)\bCVE-\d{4}-\d{4,}\b`)
	ghsaPattern   = regexp.MustCompile(`(?i)\bGHSA(-[23456789cfghjmpqrvwx]{4}){3}\b`)
	vulnIDPattern = regexp.MustCompile(`(?i)^(CVE-\d{4}-\d{4,}|GHSA(-[23456789cfghjmpqrvwx]{4}){3}|(OSV|PYSEC|GO|RUSTSEC|SNYK|ALAS|RHSA|DSA|USN|ELSA|DLA|MAL)-[A-Za-z0-9._:-]+)$`)
	cwePattern    = regexp.MustCompile(`(?i)^(CWE-)?\d{1,5}$`)
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	// vulnIDTokenPattern is the permissive shape any stored identifier must
	// have; vulnIDPattern is the stricter one inference uses to recognize IDs.
	vulnIDTokenPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`)
	vectorPattern      = regexp.MustCompile(`^(CVSS:\d\.\d/)?AV:[NALP]/`)
)

var severityRanks = map[string]int{
	SeverityCritical: 5,
	SeverityHigh:     4,
	SeverityMedium:   3,
	SeverityLow:      2,
	SeverityInfo:     1,
	SeverityUnknown:  0,
}

// SeverityRank orders normalized severities for sorting; higher is worse.
func SeverityRank(severity string) int {
	return severityRanks[severity]
}

// Severities returns the normalized severity vocabulary from worst to least.
func Severities() []string {
	return []string{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo, SeverityUnknown}
}

// Statuses returns the normalized status vocabulary.
func Statuses() []string {
	return []string{StatusOpen, StatusInProgress, StatusSuppressed, StatusNotAffected, StatusFixed}
}

// Classes returns the normalized observation classes.
func Classes() []string {
	return []string{ClassPackage, ClassContainerImage, ClassHost, ClassCode, ClassWebApplication, ClassCloudConfig, ClassOther}
}

// OpenStatus reports whether a normalized status still needs remediation.
func OpenStatus(status string) bool {
	return status == StatusOpen || status == StatusInProgress
}

var severityLabels = map[string]string{
	"critical": SeverityCritical, "crit": SeverityCritical, "urgent": SeverityCritical, "p0": SeverityCritical, "very high": SeverityCritical, "very_high": SeverityCritical, "blocker": SeverityCritical,
	"high": SeverityHigh, "important": SeverityHigh, "severe": SeverityHigh, "major": SeverityHigh, "p1": SeverityHigh, "error": SeverityHigh,
	"medium": SeverityMedium, "moderate": SeverityMedium, "med": SeverityMedium, "warning": SeverityMedium, "p2": SeverityMedium,
	"low": SeverityLow, "minor": SeverityLow, "note": SeverityLow, "p3": SeverityLow, "trivial": SeverityLow,
	"info": SeverityInfo, "informational": SeverityInfo, "information": SeverityInfo, "none": SeverityInfo, "negligible": SeverityInfo, "p4": SeverityInfo,
	"unknown": SeverityUnknown, "unspecified": SeverityUnknown, "unrated": SeverityUnknown,
}

// knownSeverityLabel reports whether a raw value is a recognized severity label.
func knownSeverityLabel(raw string) bool {
	_, ok := severityLabels[strings.ToLower(strings.TrimSpace(raw))]
	return ok
}

// NormalizeSeverity maps a raw source severity onto the normalized vocabulary.
// Explicit per-profile value maps win; numeric values follow the declared scale;
// CVSS scores are the fallback when the label is absent.
func NormalizeSeverity(raw string, scale string, overrides map[string]string, cvss *float64) string {
	value := strings.ToLower(strings.TrimSpace(raw))
	if value != "" {
		if mapped, ok := overrides[value]; ok && validSeverity(mapped) {
			return mapped
		}
		if mapped, ok := severityLabels[value]; ok {
			return mapped
		}
		if number, err := strconv.ParseFloat(value, 64); err == nil && !math.IsNaN(number) {
			if mapped := severityFromNumber(number, scale); mapped != "" {
				return mapped
			}
		}
	}
	if cvss != nil {
		return severityFromCVSS(*cvss)
	}
	return SeverityUnknown
}

func severityFromNumber(number float64, scale string) string {
	switch scale {
	case SeverityScaleZeroFour:
		switch {
		case number >= 4:
			return SeverityCritical
		case number >= 3:
			return SeverityHigh
		case number >= 2:
			return SeverityMedium
		case number >= 1:
			return SeverityLow
		default:
			return SeverityInfo
		}
	case SeverityScaleOneFive:
		switch {
		case number >= 5:
			return SeverityCritical
		case number >= 4:
			return SeverityHigh
		case number >= 3:
			return SeverityMedium
		case number >= 2:
			return SeverityLow
		default:
			return SeverityInfo
		}
	case SeverityScaleLabelOnly:
		return ""
	default:
		if number < 0 || number > 10 {
			return ""
		}
		return severityFromCVSS(number)
	}
}

func severityFromCVSS(score float64) string {
	switch {
	case score >= 9:
		return SeverityCritical
	case score >= 7:
		return SeverityHigh
	case score >= 4:
		return SeverityMedium
	case score > 0:
		return SeverityLow
	default:
		return SeverityInfo
	}
}

func validSeverity(value string) bool {
	_, ok := severityRanks[value]
	return ok
}

var statusLabels = map[string]string{
	"open": StatusOpen, "new": StatusOpen, "active": StatusOpen, "reopened": StatusOpen, "detected": StatusOpen, "unresolved": StatusOpen, "affected": StatusOpen, "confirmed": StatusOpen, "triage": StatusOpen, "to_do": StatusOpen, "todo": StatusOpen,
	"in_progress": StatusInProgress, "in progress": StatusInProgress, "investigating": StatusInProgress, "remediating": StatusInProgress, "under_investigation": StatusInProgress, "assigned": StatusInProgress, "acknowledged": StatusInProgress,
	"snoozed": StatusSuppressed, "ignored": StatusSuppressed, "suppressed": StatusSuppressed, "accepted": StatusSuppressed, "risk_accepted": StatusSuppressed, "risk accepted": StatusSuppressed, "dismissed": StatusSuppressed, "muted": StatusSuppressed, "false_positive": StatusSuppressed, "false positive": StatusSuppressed, "wont_fix": StatusSuppressed, "won't fix": StatusSuppressed, "deferred": StatusSuppressed, "exception": StatusSuppressed,
	"not_affected": StatusNotAffected, "not affected": StatusNotAffected, "not_applicable": StatusNotAffected, "unaffected": StatusNotAffected,
	"fixed": StatusFixed, "resolved": StatusFixed, "closed": StatusFixed, "remediated": StatusFixed, "mitigated": StatusFixed, "patched": StatusFixed, "done": StatusFixed, "inactive": StatusFixed,
}

func knownStatusLabel(raw string) bool {
	_, ok := statusLabels[strings.ToLower(strings.TrimSpace(raw))]
	return ok
}

// NormalizeStatus maps a raw source status onto the normalized vocabulary.
// Records without a status are open: scanners report what they currently see.
func NormalizeStatus(raw string, overrides map[string]string) string {
	value := strings.ToLower(strings.TrimSpace(raw))
	if value == "" {
		return StatusOpen
	}
	if mapped, ok := overrides[value]; ok && validStatus(mapped) {
		return mapped
	}
	if mapped, ok := statusLabels[value]; ok {
		return mapped
	}
	return StatusOpen
}

func validStatus(value string) bool {
	for _, status := range Statuses() {
		if status == value {
			return true
		}
	}
	return false
}

func validClass(value string) bool {
	for _, class := range Classes() {
		if class == value {
			return true
		}
	}
	return false
}

// NormalizeVulnerabilityIDs cleans, uppercases, dedupes, and orders
// vulnerability identifiers so CVE IDs come first, then GHSA, then everything
// else. Values that do not look like identifiers are dropped.
func NormalizeVulnerabilityIDs(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		for _, part := range strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ' ' || r == ';' || r == '\n' || r == '\t' }) {
			id := clean(part, 0)
			if !vulnIDTokenPattern.MatchString(id) {
				continue
			}
			upper := strings.ToUpper(id)
			if strings.HasPrefix(upper, "CVE-") || strings.HasPrefix(upper, "GHSA-") {
				id = upper
				if strings.HasPrefix(upper, "GHSA-") {
					id = "GHSA-" + strings.ToLower(upper[5:])
				}
			}
			if seen[id] {
				continue
			}
			seen[id] = true
			out = append(out, id)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return vulnIDRank(out[i]) < vulnIDRank(out[j]) })
	return out
}

func vulnIDRank(id string) int {
	switch {
	case strings.HasPrefix(id, "CVE-"):
		return 0
	case strings.HasPrefix(id, "GHSA-"):
		return 1
	default:
		return 2
	}
}

// ExtractVulnerabilityIDs finds CVE and GHSA identifiers in free text.
func ExtractVulnerabilityIDs(texts ...string) []string {
	found := []string{}
	for _, text := range texts {
		found = append(found, cvePattern.FindAllString(text, 8)...)
		found = append(found, ghsaPattern.FindAllString(text, 8)...)
	}
	return NormalizeVulnerabilityIDs(found)
}

// NormalizeCWEs returns CWE identifiers in the canonical CWE-<n> form.
func NormalizeCWEs(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		for _, part := range strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ' ' || r == ';' }) {
			part = strings.ToUpper(strings.TrimSpace(part))
			if !cwePattern.MatchString(part) {
				continue
			}
			if !strings.HasPrefix(part, "CWE-") {
				part = "CWE-" + part
			}
			if !seen[part] {
				seen[part] = true
				out = append(out, part)
			}
		}
	}
	return out
}
