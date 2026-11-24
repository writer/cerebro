package vulnpipeline

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/writer/cerebro/internal/ports"
)

const (
	maxAttributes          = 32
	maxAttributeValueBytes = 512
	maxShortFieldBytes     = 512
	maxTitleBytes          = 512
	maxDescriptionBytes    = 8192
	maxListItems           = 32
	maxReferenceItems      = 16
	maxFutureSkew          = 5 * time.Minute
)

// ResolutionSourceReported marks observations the source itself reported as
// fixed or not affected; ResolutionAbsentFromSnapshot marks observations a
// complete snapshot no longer contained.
const (
	ResolutionSourceReported     = "source_reported"
	ResolutionAbsentFromSnapshot = "absent_from_snapshot"
)

type finalizeContext struct {
	TenantID       string
	ProfileID      string
	SourceID       string
	Format         string
	BatchID        string
	MappingVersion int
	IngestedAt     time.Time
}

// finalizeDraft normalizes, bounds, identifies, and validates one draft. It
// returns a quarantine reason when the record cannot become an observation.
func finalizeDraft(draft Draft, ctx finalizeContext) (*ports.VulnerabilityObservation, string) {
	if draft.Problem != "" {
		return nil, draft.Problem
	}
	obs := draft.Observation
	if obs.CVSSScore != nil && !validScore(*obs.CVSSScore) {
		obs.CVSSScore = nil
	}
	obs.Title = clean(obs.Title, maxTitleBytes)
	obs.Description = clean(obs.Description, maxDescriptionBytes)
	obs.SourceRecordID = clean(obs.SourceRecordID, maxShortFieldBytes)
	obs.Scanner = clean(obs.Scanner, 128)
	obs.CVSSVector = clean(obs.CVSSVector, 256)
	obs.AssetType = strings.ToLower(clean(obs.AssetType, 64))
	obs.AssetIdentifier = clean(obs.AssetIdentifier, maxShortFieldBytes)
	obs.AssetName = clean(obs.AssetName, maxShortFieldBytes)
	obs.PackageEcosystem = strings.ToLower(clean(obs.PackageEcosystem, 64))
	obs.PackageName = clean(obs.PackageName, maxShortFieldBytes)
	obs.PackageVersion = clean(obs.PackageVersion, 128)
	obs.FixedVersion = clean(obs.FixedVersion, 128)
	obs.PackageURL = clean(obs.PackageURL, maxShortFieldBytes)
	obs.Location = clean(obs.Location, maxShortFieldBytes)

	obs.VulnerabilityIDs = boundList(NormalizeVulnerabilityIDs(obs.VulnerabilityIDs), maxListItems)
	if len(obs.VulnerabilityIDs) == 0 {
		obs.VulnerabilityIDs = ExtractVulnerabilityIDs(obs.Title)
	}
	if len(obs.VulnerabilityIDs) > 0 {
		obs.PrimaryVulnerabilityID = obs.VulnerabilityIDs[0]
	}
	if obs.Title == "" {
		obs.Title = obs.PrimaryVulnerabilityID
	}
	if obs.Title == "" {
		return nil, "record has no title or vulnerability identifier"
	}
	obs.CWEs = boundList(NormalizeCWEs(obs.CWEs), maxListItems)
	obs.References = boundList(httpReferences(obs.References), maxReferenceItems)

	obs.SourceSeverity = clean(draft.RawSeverity, 64)
	obs.Severity = NormalizeSeverity(draft.RawSeverity, draft.SeverityScale, draft.SeverityValues, obs.CVSSScore)
	obs.SourceStatus = clean(draft.RawStatus, 64)
	if validStatus(draft.RawStatus) {
		obs.Status = draft.RawStatus
	} else {
		obs.Status = NormalizeStatus(draft.RawStatus, draft.StatusValues)
	}

	obs.ImageDigest = digestFromText(obs.ImageDigest)
	if !validClass(obs.Class) {
		obs.Class = inferClass(obs)
	}

	firstSeen := parseTimestamp(draft.RawFirstSeen, ctx.IngestedAt)
	lastSeen := parseTimestamp(draft.RawLastSeen, ctx.IngestedAt)
	obs.FirstSeenAt = firstSeen
	obs.LastSeenAt = lastSeen
	observed := parseTimestamp(draft.RawObservedAt, ctx.IngestedAt)
	switch {
	case observed != nil:
		obs.ObservedAt = *observed
	case lastSeen != nil:
		obs.ObservedAt = *lastSeen
	default:
		obs.ObservedAt = ctx.IngestedAt
	}

	attributes := map[string]string{}
	for _, key := range sortedStringKeys(obs.Attributes) {
		if len(attributes) >= maxAttributes {
			break
		}
		name := clean(key, 128)
		if name == "" {
			continue
		}
		attributes[name] = clean(obs.Attributes[key], maxAttributeValueBytes)
	}
	if obs.SourceRecordID == "" {
		obs.SourceRecordID = "derived:" + shortHash(obs.PrimaryVulnerabilityID, strings.ToLower(obs.Title), obs.AssetIdentifier, obs.ImageDigest, obs.PackageName, obs.PackageVersion, obs.Location)
		attributes["cerebro.derived_record_id"] = "true"
	}
	obs.Attributes = attributes

	obs.TenantID = ctx.TenantID
	obs.ProfileID = ctx.ProfileID
	obs.SourceID = ctx.SourceID
	obs.Format = ctx.Format
	obs.BatchID = ctx.BatchID
	obs.MappingVersion = ctx.MappingVersion
	obs.IngestedAt = ctx.IngestedAt
	obs.ID = ObservationID(ctx.TenantID, ctx.ProfileID, obs.SourceRecordID)
	obs.CorrelationKey = CorrelationKey(obs)
	obs.ResolvedAt = nil
	obs.Resolution = ""
	if obs.Status == StatusFixed || obs.Status == StatusNotAffected {
		resolvedAt := obs.ObservedAt
		obs.ResolvedAt = &resolvedAt
		obs.Resolution = ResolutionSourceReported
	}
	// Postgres rejects NUL and invalid UTF-8 for the whole upsert chunk, so a
	// record that still carries either is quarantined on its own.
	if !storableText(obs) {
		return nil, "record contains NUL characters or invalid UTF-8"
	}
	return &obs, ""
}

func storableText(obs ports.VulnerabilityObservation) bool {
	values := []string{
		obs.SourceRecordID, obs.Title, obs.Description, obs.Class, obs.PrimaryVulnerabilityID,
		obs.Severity, obs.SourceSeverity, obs.CVSSVector, obs.Status, obs.SourceStatus,
		obs.AssetType, obs.AssetIdentifier, obs.AssetName, obs.ImageDigest,
		obs.PackageEcosystem, obs.PackageName, obs.PackageVersion, obs.FixedVersion, obs.PackageURL,
		obs.Location, obs.Scanner, obs.CorrelationKey,
	}
	values = append(values, obs.VulnerabilityIDs...)
	values = append(values, obs.CWEs...)
	values = append(values, obs.References...)
	for key, value := range obs.Attributes {
		values = append(values, key, value)
	}
	for _, value := range values {
		if strings.IndexByte(value, 0) >= 0 || !utf8.ValidString(value) {
			return false
		}
	}
	return true
}

// ObservationID is the stable identity of one source record inside one
// profile. Re-ingesting the same record updates it instead of duplicating it.
func ObservationID(tenantID string, profileID string, sourceRecordID string) string {
	return "vobs_" + shortHash(tenantID, profileID, sourceRecordID)
}

// CorrelationKey groups observations of the same vulnerability on the same
// subject across sources, so disagreement between scanners stays visible as
// several observations under one key.
func CorrelationKey(obs ports.VulnerabilityObservation) string {
	vulnerability := strings.ToLower(obs.PrimaryVulnerabilityID)
	if vulnerability == "" {
		vulnerability = "title:" + strings.Join(strings.Fields(strings.ToLower(obs.Title)), " ")
	}
	subject := strings.ToLower(firstNonEmpty(obs.ImageDigest, obs.AssetIdentifier))
	return "vcor_" + shortHash(vulnerability, subject, strings.ToLower(obs.PackageName))
}

func shortHash(parts ...string) string {
	hash := sha256.New()
	for _, part := range parts {
		_, _ = hash.Write([]byte(part))
		_, _ = hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))[:32]
}

func inferClass(obs ports.VulnerabilityObservation) string {
	identifier := strings.ToLower(obs.AssetIdentifier)
	switch {
	case obs.ImageDigest != "":
		return ClassContainerImage
	case obs.PackageName != "" || obs.PackageURL != "":
		return ClassPackage
	case strings.HasPrefix(identifier, "http://") || strings.HasPrefix(identifier, "https://"):
		return ClassWebApplication
	case obs.Location != "" && strings.ContainsAny(obs.Location, "/."):
		return ClassCode
	case obs.AssetIdentifier != "":
		return ClassHost
	default:
		return ClassOther
	}
}

var timestampLayouts = []string{
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02T15:04:05",
	"2006-01-02 15:04:05Z07:00",
	"2006-01-02 15:04:05",
	"2006-01-02",
	time.RFC1123Z,
	time.RFC1123,
}

// parseTimestamp accepts common scanner timestamp encodings, including unix
// seconds and milliseconds. Future times are clamped to the ingest time because
// observation time describes when a state was seen, never a deadline.
func parseTimestamp(raw string, now time.Time) *time.Time {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var parsed time.Time
	found := false
	for _, layout := range timestampLayouts {
		if value, err := time.Parse(layout, raw); err == nil {
			parsed, found = value, true
			break
		}
	}
	if !found {
		if number, err := strconv.ParseInt(raw, 10, 64); err == nil && number > 0 {
			switch {
			case number > 1e14:
				return nil
			case number > 1e11:
				parsed, found = time.UnixMilli(number), true
			default:
				parsed, found = time.Unix(number, 0), true
			}
		}
	}
	if !found || parsed.Year() < 1990 {
		return nil
	}
	parsed = parsed.UTC()
	if !now.IsZero() && parsed.After(now.Add(maxFutureSkew)) {
		parsed = now
	}
	return &parsed
}

func clean(value string, limit int) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if !utf8.ValidString(value) {
		value = strings.ToValidUTF8(value, "")
	}
	value = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return r
		}
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, value)
	return truncate(strings.TrimSpace(value), limit)
}

func truncate(value string, limit int) string {
	if limit <= 0 || len(value) <= limit {
		return value
	}
	for end := limit; end > 0; end-- {
		if utf8.ValidString(value[:end]) {
			return value[:end]
		}
	}
	return ""
}

func boundList(values []string, limit int) []string {
	if len(values) > limit {
		return values[:limit]
	}
	return values
}

func httpReferences(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		value = clean(value, 1024)
		lower := strings.ToLower(value)
		if !strings.HasPrefix(lower, "https://") && !strings.HasPrefix(lower, "http://") {
			continue
		}
		if !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	return out
}

func sortedKeys(values map[string]any) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sortedStringKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
