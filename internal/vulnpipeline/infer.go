package vulnpipeline

import (
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
)

var timeZero time.Time

const (
	maxInferenceSamples   = 200
	minFieldConfidence    = 0.45
	activationConfidence  = 0.6
	maxUnmappedPathReport = 40
)

// FieldInference explains how one target field was learned.
type FieldInference struct {
	Path       string  `json:"path"`
	Confidence float64 `json:"confidence"`
	Coverage   float64 `json:"coverage"`
	Reason     string  `json:"reason"`
}

// InferenceReport is the reviewable explanation of a learned mapping.
type InferenceReport struct {
	DetectedFormat  string                    `json:"detected_format"`
	RecordsPath     string                    `json:"records_path"`
	SampleSize      int                       `json:"sample_size"`
	Fields          map[string]FieldInference `json:"fields"`
	SeverityValues  map[string]string         `json:"severity_values,omitempty"`
	StatusValues    map[string]string         `json:"status_values,omitempty"`
	Confidence      float64                   `json:"confidence"`
	ReadyToActivate bool                      `json:"ready_to_activate"`
	UnmappedPaths   []string                  `json:"unmapped_paths,omitempty"`
	Warnings        []string                  `json:"warnings,omitempty"`
}

type fieldSpec struct {
	exact      []string
	partial    []string
	shape      func(string) bool
	shapeOnly  bool
	unique     bool
	weight     float64
	listTarget bool
}

// fieldSpecs describe how each target field is recognized: key synonyms,
// value shape, and whether a distinctive shape is enough on its own.
var fieldSpecs = map[string]fieldSpec{
	FieldSourceRecordID:   {exact: []string{"id", "uuid", "findingid", "issueid", "alertid", "recordid", "guid", "key", "resultid", "detectionid", "occurrenceid"}, partial: []string{"findingid", "issueid"}, shape: idShape, unique: true, weight: 0.8},
	FieldTitle:            {exact: []string{"title", "name", "summary", "rulename", "pluginname", "checkname", "headline", "issuetitle", "findingtitle", "vulnerabilityname", "message"}, partial: []string{"title", "name"}, shape: titleShape, weight: 1},
	FieldDescription:      {exact: []string{"description", "details", "detail", "synopsis", "body", "longdescription", "explanation", "solution"}, partial: []string{"description", "detail"}, shape: descriptionShape, weight: 0.4},
	FieldVulnerabilityIDs: {exact: []string{"cve", "cves", "cveid", "cveids", "vulnid", "vulnerabilityid", "advisoryid", "ghsa", "aliases", "identifiers", "cvelist"}, partial: []string{"cve", "advisory"}, shape: vulnIDShape, shapeOnly: true, weight: 1, listTarget: true},
	FieldCWEs:             {exact: []string{"cwe", "cwes", "cweid", "cweids"}, partial: []string{"cwe"}, shape: cweShape, weight: 0.3, listTarget: true},
	FieldSeverity:         {exact: []string{"severity", "risk", "riskfactor", "level", "priority", "criticality", "severitylevel", "impact", "rating", "risklevel", "severityname"}, partial: []string{"severity", "risk"}, shape: severityShape, weight: 1},
	FieldCVSSScore:        {exact: []string{"cvss", "cvssscore", "cvss3score", "cvss3basescore", "cvssbasescore", "basescore", "cvssv3", "cvssv3score", "cvss31score"}, partial: []string{"cvss"}, shape: cvssShape, weight: 0.5},
	FieldCVSSVector:       {exact: []string{"vector", "cvssvector", "cvss3vector", "vectorstring", "cvssv3vector"}, partial: []string{"vector"}, shape: vectorShape, shapeOnly: true, weight: 0.3},
	FieldStatus:           {exact: []string{"status", "state", "findingstatus", "lifecyclestate", "resolution", "workflowstatus"}, partial: []string{"status", "state"}, shape: statusShape, weight: 0.6},
	FieldAssetIdentifier:  {exact: []string{"target", "asset", "host", "hostname", "ip", "ipv4", "ipaddress", "fqdn", "url", "resource", "resourceid", "assetid", "instanceid", "arn", "image", "repository", "repo", "endpoint", "uri", "assetname", "hostfqdn", "netbiosname"}, partial: []string{"host", "asset", "target", "resource"}, shape: nonEmptyShape, weight: 0.9},
	FieldAssetName:        {exact: []string{"displayname", "resourcename", "hostdisplayname", "assetlabel"}, partial: []string{"displayname"}, shape: nonEmptyShape, weight: 0.2},
	FieldAssetType:        {exact: []string{"assettype", "resourcetype", "targettype", "artifacttype"}, partial: []string{"assettype", "resourcetype"}, shape: nonEmptyShape, weight: 0.2},
	FieldImageDigest:      {exact: []string{"digest", "imagedigest", "repodigest", "manifestdigest"}, partial: []string{"digest"}, shape: digestShape, shapeOnly: true, weight: 0.4},
	FieldPackageName:      {exact: []string{"package", "packagename", "pkgname", "library", "dependency", "artifact", "module", "componentname", "component", "pkg"}, partial: []string{"package", "pkgname"}, shape: nonEmptyShape, weight: 0.6},
	FieldPackageVersion:   {exact: []string{"version", "installedversion", "currentversion", "pkgversion", "packageversion", "componentversion"}, partial: []string{"installedversion"}, shape: versionShape, weight: 0.4},
	FieldFixedVersion:     {exact: []string{"fixedversion", "fixversion", "fixedin", "patchedversion", "remediationversion", "fixedversions", "patchedversions", "upgradeto"}, partial: []string{"fixed", "patched"}, shape: versionShape, weight: 0.4},
	FieldPackageEcosystem: {exact: []string{"ecosystem", "packagemanager", "pkgtype", "packagetype"}, partial: []string{"ecosystem"}, shape: nonEmptyShape, weight: 0.2},
	FieldPackageURL:       {exact: []string{"purl", "packageurl"}, partial: []string{"purl"}, shape: purlShape, shapeOnly: true, weight: 0.3},
	FieldLocation:         {exact: []string{"file", "path", "filepath", "location", "manifestpath", "filename", "sourcefile"}, partial: []string{"file", "path"}, shape: nonEmptyShape, weight: 0.3},
	FieldReferences:       {exact: []string{"references", "refs", "links", "urls", "seealso", "referenceurls"}, partial: []string{"reference", "link"}, shape: urlShape, weight: 0.2, listTarget: true},
	FieldScanner:          {exact: []string{"scanner", "tool", "toolname", "engine", "detector", "scannername", "product"}, partial: []string{"scanner", "tool"}, shape: nonEmptyShape, weight: 0.2},
	FieldClass:            {exact: []string{"findingtype", "category", "class", "kind", "findingclass"}, partial: []string{"findingtype"}, shape: classShape, weight: 0.2},
	FieldFirstSeenAt:      {exact: []string{"firstseen", "firstseenat", "firstfound", "firstdetected", "firstobserved", "createdat", "created", "discoveredat", "detectedat", "openedat", "firstdiscovered"}, partial: []string{"first", "created", "discovered"}, shape: timestampShape, weight: 0.4},
	FieldLastSeenAt:       {exact: []string{"lastseen", "lastseenat", "lastfound", "lastdetected", "lastobserved", "updatedat", "updated", "modifiedat", "lastmodified"}, partial: []string{"last", "updated", "modified"}, shape: timestampShape, weight: 0.4},
	FieldObservedAt:       {exact: []string{"observedat", "scantime", "scannedat", "scandate", "timestamp", "time", "eventtime"}, partial: []string{"scan", "observed"}, shape: timestampShape, weight: 0.2},
}

type candidateScore struct {
	field    string
	path     string
	score    float64
	coverage float64
	reason   string
}

// inferMapping learns a draft mapping from a sample document. The result is a
// proposal: the pipeline stores it as a draft and only applies it once an
// operator activates it.
func inferMapping(document any) (*Mapping, InferenceReport) {
	report := InferenceReport{DetectedFormat: detectFormat(document), Fields: map[string]FieldInference{}}
	recordsPath, records := locateRecords(document)
	report.RecordsPath = recordsPath
	if len(records) > maxInferenceSamples {
		records = records[:maxInferenceSamples]
	}
	report.SampleSize = len(records)
	mapping := &Mapping{RecordsPath: recordsPath, Fields: map[string]FieldRule{}}
	if len(records) == 0 {
		report.Warnings = append(report.Warnings, "no JSON object records were found in the sample")
		return mapping, report
	}
	flattened := make([]map[string][]string, 0, len(records))
	allPaths := map[string]bool{}
	for _, record := range records {
		flat := flattenRecord(record)
		flattened = append(flattened, flat)
		for path := range flat {
			allPaths[path] = true
		}
	}
	paths := make([]string, 0, len(allPaths))
	for path := range allPaths {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	candidates := []candidateScore{}
	for field, spec := range fieldSpecs {
		for _, path := range paths {
			if candidate, ok := scoreCandidate(field, spec, path, flattened); ok {
				candidates = append(candidates, candidate)
			}
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].score != candidates[j].score {
			return candidates[i].score > candidates[j].score
		}
		if fieldSpecs[candidates[i].field].weight != fieldSpecs[candidates[j].field].weight {
			return fieldSpecs[candidates[i].field].weight > fieldSpecs[candidates[j].field].weight
		}
		if len(candidates[i].path) != len(candidates[j].path) {
			return len(candidates[i].path) < len(candidates[j].path)
		}
		return candidates[i].path < candidates[j].path
	})
	usedPaths := map[string]bool{}
	for _, candidate := range candidates {
		if _, assigned := report.Fields[candidate.field]; assigned || usedPaths[candidate.path] {
			continue
		}
		usedPaths[candidate.path] = true
		mapping.Fields[candidate.field] = FieldRule{Paths: []string{candidate.path}}
		report.Fields[candidate.field] = FieldInference{Path: candidate.path, Confidence: round2(candidate.score), Coverage: round2(candidate.coverage), Reason: candidate.reason}
	}

	if inference, ok := report.Fields[FieldSeverity]; ok {
		mapping.SeverityScale, mapping.SeverityValues = learnSeverity(flattened, inference.Path)
		report.SeverityValues = mapping.SeverityValues
	}
	if inference, ok := report.Fields[FieldStatus]; ok {
		mapping.StatusValues = learnStatus(flattened, inference.Path)
		report.StatusValues = mapping.StatusValues
	}
	for _, path := range paths {
		if !usedPaths[path] && len(report.UnmappedPaths) < maxUnmappedPathReport {
			report.UnmappedPaths = append(report.UnmappedPaths, path)
		}
	}
	report.Confidence, report.ReadyToActivate, report.Warnings = assessInference(report)
	return mapping, report
}

func scoreCandidate(field string, spec fieldSpec, path string, records []map[string][]string) (candidateScore, bool) {
	key := normalizeKey(lastPathKey(path))
	if key == "" {
		return candidateScore{}, false
	}
	listPath := strings.Contains(path, "[*]")
	if listPath && !spec.listTarget {
		return candidateScore{}, false
	}
	nameScore := 0.0
	reason := ""
	for _, synonym := range spec.exact {
		if key == synonym {
			nameScore, reason = 1, "key name matches"
			break
		}
	}
	if nameScore == 0 {
		for _, fragment := range spec.partial {
			if strings.Contains(key, fragment) {
				nameScore, reason = 0.6, "key name contains "+fragment
				break
			}
		}
	}
	present, matching, total := 0, 0, 0
	distinct := map[string]bool{}
	for _, record := range records {
		values := record[path]
		if len(values) == 0 {
			continue
		}
		present++
		for _, value := range values {
			total++
			if spec.shape == nil || spec.shape(value) {
				matching++
			}
			distinct[value] = true
		}
	}
	if present == 0 || total == 0 {
		return candidateScore{}, false
	}
	coverage := float64(present) / float64(len(records))
	shapeScore := float64(matching) / float64(total)
	if spec.unique && present > 1 && float64(len(distinct)) < 0.9*float64(present) {
		return candidateScore{}, false
	}
	if nameScore == 0 {
		if !spec.shapeOnly || shapeScore < 0.9 {
			return candidateScore{}, false
		}
		reason = "values match the expected shape"
	}
	if shapeScore < 0.5 {
		return candidateScore{}, false
	}
	score := 0.5*nameScore + 0.35*shapeScore + 0.15*coverage
	if nameScore == 0 {
		score = 0.3 + 0.35*shapeScore + 0.15*coverage
	}
	if score < minFieldConfidence {
		return candidateScore{}, false
	}
	return candidateScore{field: field, path: path, score: score, coverage: coverage, reason: reason}, true
}

func assessInference(report InferenceReport) (float64, bool, []string) {
	warnings := []string{}
	_, hasTitle := report.Fields[FieldTitle]
	_, hasIDs := report.Fields[FieldVulnerabilityIDs]
	if !hasTitle && !hasIDs {
		warnings = append(warnings, "no title or vulnerability identifier field was recognized")
	}
	if _, ok := report.Fields[FieldSeverity]; !ok {
		warnings = append(warnings, "no severity field was recognized; observations will be unknown severity unless a CVSS score is mapped")
	}
	if _, ok := report.Fields[FieldAssetIdentifier]; !ok {
		warnings = append(warnings, "no affected asset field was recognized; observations cannot be correlated across sources")
	}
	if _, ok := report.Fields[FieldSourceRecordID]; !ok {
		warnings = append(warnings, "no stable record ID was recognized; identity will be derived from vulnerability, asset, and package fields")
	}
	weighted, totalWeight := 0.0, 0.0
	for _, field := range []string{FieldTitle, FieldVulnerabilityIDs, FieldSeverity, FieldAssetIdentifier, FieldSourceRecordID, FieldStatus} {
		weight := fieldSpecs[field].weight
		totalWeight += weight
		if inference, ok := report.Fields[field]; ok {
			weighted += weight * inference.Confidence * math.Max(inference.Coverage, 0.25)
		}
	}
	confidence := 0.0
	if totalWeight > 0 {
		confidence = round2(weighted / totalWeight)
	}
	ready := (hasTitle || hasIDs) && confidence >= activationConfidence
	if !ready && (hasTitle || hasIDs) {
		warnings = append(warnings, "mapping confidence is below the activation threshold; review the field paths before activating")
	}
	return confidence, ready, warnings
}

// locateRecords finds the record list in a sample. A top-level array is the
// record list; otherwise the largest array of objects within three levels wins,
// and a lone object is treated as one record.
func locateRecords(document any) (string, []any) {
	if list, ok := document.([]any); ok {
		return "", objectsOnly(list)
	}
	root, ok := document.(map[string]any)
	if !ok {
		return "", nil
	}
	bestPath, bestRecords := "", []any(nil)
	var walk func(prefix string, value map[string]any, depth int)
	walk = func(prefix string, value map[string]any, depth int) {
		if depth > 3 {
			return
		}
		for _, key := range sortedKeys(value) {
			if strings.ContainsAny(key, ".[]") || key == "" {
				continue
			}
			path := key
			if prefix != "" {
				path = prefix + "." + key
			}
			switch child := value[key].(type) {
			case []any:
				objects := objectsOnly(child)
				if len(objects) > len(bestRecords) || (len(objects) == len(bestRecords) && len(objects) > 0 && preferredRecordKey(key) && !preferredRecordKey(lastPathKey(bestPath))) {
					bestPath, bestRecords = path, objects
				}
			case map[string]any:
				walk(path, child, depth+1)
			}
		}
	}
	walk("", root, 1)
	if len(bestRecords) == 0 {
		return "", []any{root}
	}
	return bestPath, bestRecords
}

func preferredRecordKey(key string) bool {
	switch normalizeKey(key) {
	case "items", "results", "data", "findings", "vulnerabilities", "vulns", "issues", "records", "matches", "alerts", "observations", "detections":
		return true
	default:
		return false
	}
}

func objectsOnly(values []any) []any {
	out := []any{}
	for _, value := range values {
		if _, ok := value.(map[string]any); ok {
			out = append(out, value)
		}
	}
	return out
}

func learnSeverity(records []map[string][]string, path string) (string, map[string]string) {
	values := map[string]bool{}
	numeric := true
	integers := true
	maxNumber := 0.0
	for _, record := range records {
		for _, value := range record[path] {
			lower := strings.ToLower(strings.TrimSpace(value))
			if lower == "" {
				continue
			}
			values[lower] = true
			number, err := strconv.ParseFloat(lower, 64)
			if err != nil {
				numeric = false
				continue
			}
			if number != math.Trunc(number) {
				integers = false
			}
			maxNumber = math.Max(maxNumber, number)
		}
	}
	scale := ""
	if numeric && len(values) > 0 {
		switch {
		case integers && maxNumber <= 4:
			scale = SeverityScaleZeroFour
		case integers && maxNumber <= 5:
			scale = SeverityScaleOneFive
		default:
			scale = SeverityScaleCVSS
		}
	}
	learned := map[string]string{}
	for value := range values {
		if _, err := strconv.ParseFloat(value, 64); err == nil {
			continue
		}
		if !knownSeverityLabel(value) {
			learned[value] = SeverityUnknown
		}
	}
	if len(learned) == 0 {
		learned = nil
	}
	return scale, learned
}

func learnStatus(records []map[string][]string, path string) map[string]string {
	learned := map[string]string{}
	for _, record := range records {
		for _, value := range record[path] {
			lower := strings.ToLower(strings.TrimSpace(value))
			if lower == "" || knownStatusLabel(lower) {
				continue
			}
			learned[lower] = StatusOpen
		}
	}
	if len(learned) == 0 {
		return nil
	}
	return learned
}

func round2(value float64) float64 {
	return math.Round(value*100) / 100
}

func idShape(value string) bool {
	value = strings.TrimSpace(value)
	return value != "" && len(value) <= 256 && !strings.ContainsAny(value, " \n\t")
}

func titleShape(value string) bool {
	length := len(strings.TrimSpace(value))
	if length < 3 || length > 400 {
		return false
	}
	lower := strings.ToLower(value)
	return !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://")
}

func descriptionShape(value string) bool {
	return len(strings.TrimSpace(value)) >= 20
}

func vulnIDShape(value string) bool {
	for _, part := range strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ' ' || r == ';' }) {
		if !vulnIDPattern.MatchString(strings.TrimSpace(part)) {
			return false
		}
	}
	return strings.TrimSpace(value) != ""
}

func cweShape(value string) bool {
	for _, part := range strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ' ' || r == ';' }) {
		if !cwePattern.MatchString(strings.TrimSpace(part)) {
			return false
		}
	}
	return strings.TrimSpace(value) != ""
}

func severityShape(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	if knownSeverityLabel(lower) {
		return true
	}
	number, err := strconv.ParseFloat(lower, 64)
	return err == nil && number >= 0 && number <= 10
}

func cvssShape(value string) bool {
	number, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
	return err == nil && number >= 0 && number <= 10
}

func vectorShape(value string) bool {
	return vectorPattern.MatchString(strings.TrimSpace(value))
}

func statusShape(value string) bool {
	return knownStatusLabel(value)
}

func nonEmptyShape(value string) bool {
	trimmed := strings.TrimSpace(value)
	return trimmed != "" && len(trimmed) <= 1024
}

func digestShape(value string) bool {
	return digestFromText(value) != ""
}

func versionShape(value string) bool {
	trimmed := strings.TrimSpace(value)
	return trimmed != "" && len(trimmed) <= 128 && strings.ContainsAny(trimmed, "0123456789")
}

func purlShape(value string) bool {
	return strings.HasPrefix(strings.TrimSpace(value), "pkg:")
}

func urlShape(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	return strings.HasPrefix(lower, "https://") || strings.HasPrefix(lower, "http://")
}

func timestampShape(value string) bool {
	return parseTimestamp(value, timeZero) != nil
}

func classShape(value string) bool {
	return validClass(strings.ToLower(strings.TrimSpace(value)))
}
