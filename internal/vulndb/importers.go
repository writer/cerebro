package vulndb

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	SourceOSV     = "osv"
	SourceCISAKEV = "cisa-kev"
	SourceEPSS    = "epss"
	SourceNVD     = "nvd"
)

// ImportResult summarizes imported feed records.
type ImportResult struct {
	Vulnerabilities  int
	AffectedPackages int
	Enrichments      int
}

// ImportOSV reads OSV JSON or JSONL advisories into the store.
func ImportOSV(ctx context.Context, store Store, reader io.Reader) (ImportResult, error) {
	if store == nil {
		return ImportResult{}, fmt.Errorf("vulnerability store is required")
	}
	data, err := io.ReadAll(reader)
	if err != nil {
		return ImportResult{}, err
	}
	var advisories []osvAdvisory
	if err := json.Unmarshal(data, &advisories); err == nil {
		return importOSVAdvisories(ctx, store, advisories)
	}
	var advisory osvAdvisory
	if err := json.Unmarshal(data, &advisory); err == nil && NormalizeIdentifier(advisory.ID) != "" {
		return importOSVAdvisories(ctx, store, []osvAdvisory{advisory})
	}

	var result ImportResult
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return ImportResult{}, err
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var advisory osvAdvisory
		if err := json.Unmarshal([]byte(line), &advisory); err != nil {
			return ImportResult{}, err
		}
		imported, err := importOSVAdvisory(ctx, store, advisory)
		if err != nil {
			return ImportResult{}, err
		}
		result.Vulnerabilities += imported.Vulnerabilities
		result.AffectedPackages += imported.AffectedPackages
	}
	if err := scanner.Err(); err != nil {
		return ImportResult{}, err
	}
	return result, recordSyncSuccess(ctx, store, SourceOSV)
}

// ImportCISAKEV reads the CISA Known Exploited Vulnerabilities catalog into the store.
func ImportCISAKEV(ctx context.Context, store Store, reader io.Reader) (ImportResult, error) {
	if store == nil {
		return ImportResult{}, fmt.Errorf("vulnerability store is required")
	}
	var catalog kevCatalog
	if err := json.NewDecoder(reader).Decode(&catalog); err != nil {
		return ImportResult{}, err
	}
	var result ImportResult
	now := time.Now().UTC()
	for _, entry := range catalog.Vulnerabilities {
		if err := ctx.Err(); err != nil {
			return ImportResult{}, err
		}
		id := NormalizeIdentifier(entry.CVEID)
		if id == "" {
			continue
		}
		vulnerability, ok, err := store.FindVulnerability(ctx, id)
		if err != nil {
			return ImportResult{}, err
		}
		if !ok {
			vulnerability = Vulnerability{ID: id, Source: SourceCISAKEV}
			result.Vulnerabilities++
		}
		if vulnerability.Summary == "" {
			vulnerability.Summary = strings.TrimSpace(entry.VulnerabilityName)
		}
		if vulnerability.Details == "" {
			vulnerability.Details = strings.TrimSpace(entry.ShortDescription)
		}
		dueDate, _ := parseDate(entry.DueDate)
		updatedAt, _ := parseDate(firstNonEmpty(entry.DateUpdated, entry.DateAdded))
		if updatedAt.IsZero() {
			updatedAt = now
		}
		vulnerability.KEV = &KEV{
			Listed:                     true,
			KnownRansomwareCampaignUse: strings.TrimSpace(entry.KnownRansomwareCampaignUse),
			RequiredAction:             strings.TrimSpace(entry.RequiredAction),
			DueDate:                    dueDate,
			UpdatedAt:                  updatedAt,
			Notes:                      strings.TrimSpace(entry.Notes),
		}
		if err := store.UpsertVulnerability(ctx, vulnerability); err != nil {
			return ImportResult{}, err
		}
		result.Enrichments++
	}
	return result, recordSyncSuccess(ctx, store, SourceCISAKEV)
}

// ImportEPSS reads FIRST EPSS CSV data into the store.
func ImportEPSS(ctx context.Context, store Store, reader io.Reader) (ImportResult, error) {
	if store == nil {
		return ImportResult{}, fmt.Errorf("vulnerability store is required")
	}
	csvReader := csv.NewReader(skipCommentLines(reader))
	csvReader.TrimLeadingSpace = true
	header, err := csvReader.Read()
	if err != nil {
		return ImportResult{}, err
	}
	indexes := csvIndexes(header)
	cveIndex, ok := indexes["cve"]
	if !ok {
		return ImportResult{}, fmt.Errorf("epss csv missing cve column")
	}
	epssIndex, ok := indexes["epss"]
	if !ok {
		return ImportResult{}, fmt.Errorf("epss csv missing epss column")
	}
	percentileIndex, ok := indexes["percentile"]
	if !ok {
		return ImportResult{}, fmt.Errorf("epss csv missing percentile column")
	}
	requiredIndex := maxInt(cveIndex, epssIndex, percentileIndex)
	var result ImportResult
	now := time.Now().UTC()
	for {
		if err := ctx.Err(); err != nil {
			return ImportResult{}, err
		}
		record, err := csvReader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return ImportResult{}, err
		}
		if len(record) <= requiredIndex {
			continue
		}
		id := NormalizeIdentifier(record[cveIndex])
		if id == "" {
			continue
		}
		score, err := strconv.ParseFloat(strings.TrimSpace(record[epssIndex]), 64)
		if err != nil {
			return ImportResult{}, err
		}
		percentile, err := strconv.ParseFloat(strings.TrimSpace(record[percentileIndex]), 64)
		if err != nil {
			return ImportResult{}, err
		}
		vulnerability, ok, err := store.FindVulnerability(ctx, id)
		if err != nil {
			return ImportResult{}, err
		}
		if !ok {
			vulnerability = Vulnerability{ID: id, Source: SourceEPSS}
			result.Vulnerabilities++
		}
		vulnerability.EPSS = &EPSS{Score: score, Percentile: percentile, UpdatedAt: now}
		if err := store.UpsertVulnerability(ctx, vulnerability); err != nil {
			return ImportResult{}, err
		}
		result.Enrichments++
	}
	return result, recordSyncSuccess(ctx, store, SourceEPSS)
}

// ImportNVD reads NVD 2.0 CVE JSON data into the store.
func ImportNVD(ctx context.Context, store Store, reader io.Reader) (ImportResult, error) {
	if store == nil {
		return ImportResult{}, fmt.Errorf("vulnerability store is required")
	}
	var feed nvdFeed
	if err := json.NewDecoder(reader).Decode(&feed); err != nil {
		return ImportResult{}, err
	}
	var result ImportResult
	for _, item := range feed.Vulnerabilities {
		if err := ctx.Err(); err != nil {
			return ImportResult{}, err
		}
		id := NormalizeIdentifier(item.CVE.ID)
		if id == "" {
			continue
		}
		vulnerability := Vulnerability{
			ID:          id,
			Summary:     nvdEnglishDescription(item.CVE.Descriptions),
			Details:     nvdEnglishDescription(item.CVE.Descriptions),
			Source:      SourceNVD,
			PublishedAt: parseTime(item.CVE.Published),
			ModifiedAt:  parseTime(item.CVE.LastModified),
			References:  nvdReferences(item.CVE.References),
		}
		vulnerability.CVSSScore, vulnerability.Severity, vulnerability.CVSSVector = nvdCVSS(item.CVE.Metrics)
		if existing, ok, err := store.FindVulnerability(ctx, id); err != nil {
			return ImportResult{}, err
		} else if ok {
			vulnerability.Aliases = existing.Aliases
			vulnerability.EPSS = existing.EPSS
			vulnerability.KEV = existing.KEV
			if vulnerability.Summary == "" {
				vulnerability.Summary = existing.Summary
			}
			if vulnerability.Details == "" {
				vulnerability.Details = existing.Details
			}
		}
		if err := store.UpsertVulnerability(ctx, vulnerability); err != nil {
			return ImportResult{}, err
		}
		result.Vulnerabilities++
		for _, affected := range nvdAffectedPackages(id, item.CVE.Configurations) {
			if err := store.UpsertAffectedPackage(ctx, affected); err != nil {
				return ImportResult{}, err
			}
			result.AffectedPackages++
		}
	}
	return result, recordSyncSuccess(ctx, store, SourceNVD)
}

// ValidateFeedURL enforces transport policy for remote feed sync.
func ValidateFeedURL(rawURL string, allowInsecureHTTP bool) error {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return err
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("feed URL must be absolute")
	}
	switch strings.ToLower(parsed.Scheme) {
	case "https":
		return nil
	case "http":
		if allowInsecureHTTP {
			return nil
		}
		return fmt.Errorf("insecure http feed URL requires allow-insecure-http")
	default:
		return fmt.Errorf("unsupported feed URL scheme %q", parsed.Scheme)
	}
}

func importOSVAdvisories(ctx context.Context, store Store, advisories []osvAdvisory) (ImportResult, error) {
	var result ImportResult
	for _, advisory := range advisories {
		imported, err := importOSVAdvisory(ctx, store, advisory)
		if err != nil {
			return ImportResult{}, err
		}
		result.Vulnerabilities += imported.Vulnerabilities
		result.AffectedPackages += imported.AffectedPackages
	}
	return result, recordSyncSuccess(ctx, store, SourceOSV)
}

func importOSVAdvisory(ctx context.Context, store Store, advisory osvAdvisory) (ImportResult, error) {
	if err := ctx.Err(); err != nil {
		return ImportResult{}, err
	}
	id := NormalizeIdentifier(advisory.ID)
	if id == "" {
		return ImportResult{}, nil
	}
	vulnerability := Vulnerability{
		ID:          id,
		Aliases:     advisory.Aliases,
		Summary:     strings.TrimSpace(advisory.Summary),
		Details:     strings.TrimSpace(advisory.Details),
		Source:      SourceOSV,
		PublishedAt: parseTime(advisory.Published),
		ModifiedAt:  parseTime(advisory.Modified),
		WithdrawnAt: parseTime(advisory.Withdrawn),
		References:  make([]Reference, 0, len(advisory.References)),
	}
	if existing, ok, err := store.FindVulnerability(ctx, id); err != nil {
		return ImportResult{}, err
	} else if ok {
		vulnerability.EPSS = existing.EPSS
		vulnerability.KEV = existing.KEV
		if len(vulnerability.Aliases) == 0 {
			vulnerability.Aliases = existing.Aliases
		}
	}
	if len(advisory.Severity) > 0 {
		vulnerability.CVSSVector = strings.TrimSpace(advisory.Severity[0].Score)
		vulnerability.Severity = strings.TrimSpace(advisory.Severity[0].Type)
	}
	for _, reference := range advisory.References {
		vulnerability.References = append(vulnerability.References, Reference{
			URL:  strings.TrimSpace(reference.URL),
			Type: strings.TrimSpace(reference.Type),
		})
	}
	if err := store.UpsertVulnerability(ctx, vulnerability); err != nil {
		return ImportResult{}, err
	}
	result := ImportResult{Vulnerabilities: 1}
	for _, affected := range advisory.Affected {
		ecosystem := normalizeEcosystem(affected.Package.Ecosystem)
		name := strings.TrimSpace(affected.Package.Name)
		if ecosystem == "" || name == "" {
			continue
		}
		for _, version := range affected.Versions {
			if strings.TrimSpace(version) == "" {
				continue
			}
			if err := store.UpsertAffectedPackage(ctx, AffectedPackage{
				VulnerabilityID:   id,
				Ecosystem:         ecosystem,
				PackageName:       name,
				VulnerableVersion: strings.TrimSpace(version),
			}); err != nil {
				return ImportResult{}, err
			}
			result.AffectedPackages++
		}
		for _, affectedRange := range affected.Ranges {
			events := affectedRange.Events
			row := AffectedPackage{
				VulnerabilityID: id,
				Ecosystem:       ecosystem,
				PackageName:     name,
				RangeType:       strings.TrimSpace(affectedRange.Type),
			}
			for _, event := range events {
				if event.Introduced != "" {
					row.Introduced = strings.TrimSpace(event.Introduced)
				}
				if event.Fixed != "" {
					row.Fixed = strings.TrimSpace(event.Fixed)
				}
				if event.LastAffected != "" {
					row.LastAffected = strings.TrimSpace(event.LastAffected)
				}
			}
			if row.Introduced == "" && row.Fixed == "" && row.LastAffected == "" {
				continue
			}
			if err := store.UpsertAffectedPackage(ctx, row); err != nil {
				return ImportResult{}, err
			}
			result.AffectedPackages++
		}
	}
	return result, nil
}

type osvAdvisory struct {
	ID         string         `json:"id"`
	Aliases    []string       `json:"aliases"`
	Summary    string         `json:"summary"`
	Details    string         `json:"details"`
	Modified   string         `json:"modified"`
	Published  string         `json:"published"`
	Withdrawn  string         `json:"withdrawn"`
	Severity   []osvSeverity  `json:"severity"`
	References []osvReference `json:"references"`
	Affected   []osvAffected  `json:"affected"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type osvAffected struct {
	Package  osvPackage `json:"package"`
	Ranges   []osvRange `json:"ranges"`
	Versions []string   `json:"versions"`
}

type osvPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	PURL      string `json:"purl"`
}

type osvRange struct {
	Type   string     `json:"type"`
	Events []osvEvent `json:"events"`
}

type osvEvent struct {
	Introduced   string `json:"introduced"`
	Fixed        string `json:"fixed"`
	LastAffected string `json:"last_affected"`
}

type kevCatalog struct {
	Vulnerabilities []kevEntry `json:"vulnerabilities"`
}

type kevEntry struct {
	CVEID                      string `json:"cveID"`
	VulnerabilityName          string `json:"vulnerabilityName"`
	ShortDescription           string `json:"shortDescription"`
	RequiredAction             string `json:"requiredAction"`
	DueDate                    string `json:"dueDate"`
	DateAdded                  string `json:"dateAdded"`
	DateUpdated                string `json:"dateUpdated"`
	KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
	Notes                      string `json:"notes"`
}

type nvdFeed struct {
	Vulnerabilities []nvdVulnerability `json:"vulnerabilities"`
}

type nvdVulnerability struct {
	CVE nvdCVE `json:"cve"`
}

type nvdCVE struct {
	ID             string             `json:"id"`
	Published      string             `json:"published"`
	LastModified   string             `json:"lastModified"`
	Descriptions   []nvdDescription   `json:"descriptions"`
	Metrics        nvdMetrics         `json:"metrics"`
	References     []nvdReference     `json:"references"`
	Configurations []nvdConfiguration `json:"configurations"`
}

type nvdDescription struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type nvdReference struct {
	URL    string   `json:"url"`
	Source string   `json:"source"`
	Tags   []string `json:"tags"`
}

type nvdMetrics struct {
	CVSSMetricV40 []nvdCVSSMetric `json:"cvssMetricV40"`
	CVSSMetricV31 []nvdCVSSMetric `json:"cvssMetricV31"`
	CVSSMetricV30 []nvdCVSSMetric `json:"cvssMetricV30"`
	CVSSMetricV2  []nvdCVSSMetric `json:"cvssMetricV2"`
}

type nvdCVSSMetric struct {
	CVSSData nvdCVSSData `json:"cvssData"`
}

type nvdCVSSData struct {
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
	VectorString string  `json:"vectorString"`
}

type nvdConfiguration struct {
	Nodes []nvdNode `json:"nodes"`
}

type nvdNode struct {
	CPEMatch []nvdCPEMatch `json:"cpeMatch"`
	Children []nvdNode     `json:"children"`
}

type nvdCPEMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionStartExcluding string `json:"versionStartExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
	MatchCriteriaID       string `json:"matchCriteriaId"`
}

func parseTime(value string) time.Time {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.000", "2006-01-02T15:04:05", "2006-01-02"} {
		t, err := time.Parse(layout, value)
		if err == nil {
			return t
		}
	}
	return time.Time{}
}

func parseDate(value string) (time.Time, bool) {
	t := parseTime(value)
	return t, !t.IsZero()
}

func nvdEnglishDescription(descriptions []nvdDescription) string {
	for _, description := range descriptions {
		if strings.EqualFold(strings.TrimSpace(description.Lang), "en") && strings.TrimSpace(description.Value) != "" {
			return strings.TrimSpace(description.Value)
		}
	}
	for _, description := range descriptions {
		if strings.TrimSpace(description.Value) != "" {
			return strings.TrimSpace(description.Value)
		}
	}
	return ""
}

func nvdReferences(references []nvdReference) []Reference {
	if len(references) == 0 {
		return nil
	}
	out := make([]Reference, 0, len(references))
	for _, reference := range references {
		refType := ""
		if len(reference.Tags) > 0 {
			refType = strings.Join(reference.Tags, ",")
		} else {
			refType = strings.TrimSpace(reference.Source)
		}
		out = append(out, Reference{URL: strings.TrimSpace(reference.URL), Type: refType})
	}
	return out
}

func nvdCVSS(metrics nvdMetrics) (float64, string, string) {
	for _, candidates := range [][]nvdCVSSMetric{
		metrics.CVSSMetricV40,
		metrics.CVSSMetricV31,
		metrics.CVSSMetricV30,
		metrics.CVSSMetricV2,
	} {
		if len(candidates) == 0 {
			continue
		}
		data := candidates[0].CVSSData
		return data.BaseScore, strings.TrimSpace(data.BaseSeverity), strings.TrimSpace(data.VectorString)
	}
	return 0, "", ""
}

func nvdAffectedPackages(vulnerabilityID string, configurations []nvdConfiguration) []AffectedPackage {
	rows := []AffectedPackage{}
	for _, configuration := range configurations {
		for _, node := range configuration.Nodes {
			rows = append(rows, nvdNodeAffectedPackages(vulnerabilityID, node)...)
		}
	}
	return rows
}

func nvdNodeAffectedPackages(vulnerabilityID string, node nvdNode) []AffectedPackage {
	rows := make([]AffectedPackage, 0, len(node.CPEMatch))
	for _, match := range node.CPEMatch {
		row, ok := nvdCPEAffectedPackage(vulnerabilityID, match)
		if ok {
			rows = append(rows, row)
		}
	}
	for _, child := range node.Children {
		rows = append(rows, nvdNodeAffectedPackages(vulnerabilityID, child)...)
	}
	return rows
}

func nvdCPEAffectedPackage(vulnerabilityID string, match nvdCPEMatch) (AffectedPackage, bool) {
	if !match.Vulnerable {
		return AffectedPackage{}, false
	}
	cpe, ok := parseCPE23(match.Criteria)
	if !ok {
		return AffectedPackage{}, false
	}
	row := AffectedPackage{
		VulnerabilityID: vulnerabilityID,
		Ecosystem:       cpeEcosystem(cpe.Part),
		PackageName:     cpePackageName(cpe.Vendor, cpe.Product),
		RangeType:       "CPE",
		Introduced:      firstNonEmpty(match.VersionStartIncluding, match.VersionStartExcluding),
		Fixed:           strings.TrimSpace(match.VersionEndExcluding),
		LastAffected:    strings.TrimSpace(match.VersionEndIncluding),
	}
	if row.Introduced == "" && row.Fixed == "" && row.LastAffected == "" && cpe.Version != "" && cpe.Version != "*" && cpe.Version != "-" {
		row.VulnerableVersion = cpe.Version
	}
	if row.Ecosystem == "" || row.PackageName == "" {
		return AffectedPackage{}, false
	}
	return row, true
}

type cpe23 struct {
	Part    string
	Vendor  string
	Product string
	Version string
}

func parseCPE23(criteria string) (cpe23, bool) {
	fields := splitCPE23(criteria)
	if len(fields) < 6 || fields[0] != "cpe" || fields[1] != "2.3" {
		return cpe23{}, false
	}
	return cpe23{
		Part:    strings.TrimSpace(fields[2]),
		Vendor:  cleanCPEComponent(fields[3]),
		Product: cleanCPEComponent(fields[4]),
		Version: cleanCPEComponent(fields[5]),
	}, true
}

func splitCPE23(value string) []string {
	var fields []string
	var current strings.Builder
	escaped := false
	for _, r := range strings.TrimSpace(value) {
		if escaped {
			current.WriteRune(r)
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if r == ':' {
			fields = append(fields, current.String())
			current.Reset()
			continue
		}
		current.WriteRune(r)
	}
	if escaped {
		current.WriteRune('\\')
	}
	fields = append(fields, current.String())
	return fields
}

func cleanCPEComponent(value string) string {
	value = strings.TrimSpace(value)
	if value == "*" || value == "-" {
		return ""
	}
	return strings.NewReplacer("\\:", ":", "\\_", "_", "\\\\", "\\").Replace(value)
}

func cpeEcosystem(part string) string {
	switch strings.ToLower(strings.TrimSpace(part)) {
	case "a":
		return "cpe:application"
	case "o":
		return "cpe:operating-system"
	case "h":
		return "cpe:hardware"
	default:
		return ""
	}
}

func cpePackageName(vendor string, product string) string {
	vendor = strings.TrimSpace(vendor)
	product = strings.TrimSpace(product)
	if product == "" {
		return ""
	}
	if vendor == "" {
		return product
	}
	return vendor + ":" + product
}

func csvIndexes(header []string) map[string]int {
	indexes := make(map[string]int, len(header))
	for i, column := range header {
		indexes[strings.ToLower(strings.TrimSpace(column))] = i
	}
	return indexes
}

func skipCommentLines(reader io.Reader) io.Reader {
	scanner := bufio.NewScanner(reader)
	var builder strings.Builder
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		builder.WriteString(line)
		builder.WriteByte('\n')
	}
	return strings.NewReader(builder.String())
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func maxInt(values ...int) int {
	max := 0
	for _, value := range values {
		if value > max {
			max = value
		}
	}
	return max
}
