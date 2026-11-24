package vulnpipeline

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Formats a profile can declare. FormatAuto detects the format per delivery;
// FormatGeneric applies the profile's learned or edited mapping.
const (
	FormatAuto      = "auto"
	FormatNative    = "cerebro"
	FormatStrix     = "strix"
	FormatSARIF     = "sarif"
	FormatCycloneDX = "cyclonedx"
	FormatOSV       = "osv_scanner"
	FormatTrivy     = "trivy"
	FormatGrype     = "grype"
	FormatGeneric   = "generic"
)

// NativeSchema identifies the Cerebro generic vulnerability ingest document.
const NativeSchema = "cerebro.vulnerability/v1"

// Formats returns every declarable profile format.
func Formats() []string {
	return []string{FormatAuto, FormatNative, FormatStrix, FormatSARIF, FormatCycloneDX, FormatOSV, FormatTrivy, FormatGrype, FormatGeneric}
}

func validFormat(format string) bool {
	for _, candidate := range Formats() {
		if candidate == format {
			return true
		}
	}
	return false
}

// detectFormat recognizes well-known scanner documents. It returns
// FormatGeneric when no builtin adapter claims the document.
func detectFormat(document any) string {
	switch typed := document.(type) {
	case map[string]any:
		if text(typed, "schema") == NativeSchema {
			return FormatNative
		}
		if _, ok := typed["runs"].([]any); ok && (strings.HasPrefix(text(typed, "version"), "2.") || strings.Contains(strings.ToLower(text(typed, "$schema")), "sarif")) {
			return FormatSARIF
		}
		if strings.EqualFold(text(typed, "bomFormat"), "CycloneDX") {
			return FormatCycloneDX
		}
		if _, ok := typed["Results"]; ok && (typed["SchemaVersion"] != nil || typed["ArtifactName"] != nil) {
			return FormatTrivy
		}
		if _, ok := typed["matches"].([]any); ok {
			if descriptor, ok := typed["descriptor"].(map[string]any); ok && strings.EqualFold(text(descriptor, "name"), "grype") {
				return FormatGrype
			}
		}
		if results, ok := typed["results"].([]any); ok && len(results) > 0 {
			if first, ok := results[0].(map[string]any); ok {
				if _, hasPackages := first["packages"].([]any); hasPackages {
					return FormatOSV
				}
			}
		}
		if items, ok := typed["items"].([]any); ok && len(items) > 0 && strixRecord(items[0]) {
			return FormatStrix
		}
		if strixRecord(typed) {
			return FormatStrix
		}
	case []any:
		if len(typed) > 0 && strixRecord(typed[0]) {
			return FormatStrix
		}
	}
	return FormatGeneric
}

func strixRecord(value any) bool {
	record, ok := value.(map[string]any)
	if !ok {
		return false
	}
	_, hasDisplay := record["display_number"]
	findingType := text(record, "finding_type")
	return record["scan_id"] != nil && (hasDisplay || findingType == "live_pentest" || findingType == "code" || findingType == "dependency")
}

// normalizeBuiltin runs the builtin adapter for a detected or declared format.
func normalizeBuiltin(format string, document any) ([]Draft, error) {
	switch format {
	case FormatNative:
		return normalizeNative(document)
	case FormatStrix:
		return normalizeStrix(document), nil
	case FormatSARIF:
		return normalizeSARIF(document), nil
	case FormatCycloneDX:
		return normalizeCycloneDX(document), nil
	case FormatOSV:
		return normalizeOSVScanner(document), nil
	case FormatTrivy:
		return normalizeTrivy(document), nil
	case FormatGrype:
		return normalizeGrype(document), nil
	default:
		return nil, fmt.Errorf("format %q has no builtin adapter", format)
	}
}

var nativeMapping = &Mapping{
	RecordsPath: "observations",
	Fields: map[string]FieldRule{
		FieldSourceRecordID:   {Paths: []string{"id"}},
		FieldTitle:            {Paths: []string{"title"}},
		FieldDescription:      {Paths: []string{"description"}},
		FieldVulnerabilityIDs: {Paths: []string{"vulnerability_ids"}},
		FieldCWEs:             {Paths: []string{"cwes"}},
		FieldSeverity:         {Paths: []string{"severity"}},
		FieldCVSSScore:        {Paths: []string{"cvss_score"}},
		FieldCVSSVector:       {Paths: []string{"cvss_vector"}},
		FieldStatus:           {Paths: []string{"status"}},
		FieldClass:            {Paths: []string{"class"}},
		FieldAssetType:        {Paths: []string{"asset.type"}},
		FieldAssetIdentifier:  {Paths: []string{"asset.identifier"}},
		FieldAssetName:        {Paths: []string{"asset.name"}},
		FieldImageDigest:      {Paths: []string{"asset.image_digest"}},
		FieldPackageEcosystem: {Paths: []string{"package.ecosystem"}},
		FieldPackageName:      {Paths: []string{"package.name"}},
		FieldPackageVersion:   {Paths: []string{"package.version"}},
		FieldFixedVersion:     {Paths: []string{"package.fixed_version"}},
		FieldPackageURL:       {Paths: []string{"package.purl"}},
		FieldLocation:         {Paths: []string{"location"}},
		FieldReferences:       {Paths: []string{"references"}},
		FieldScanner:          {Paths: []string{"scanner"}},
		FieldFirstSeenAt:      {Paths: []string{"first_seen_at"}},
		FieldLastSeenAt:       {Paths: []string{"last_seen_at"}},
		FieldObservedAt:       {Paths: []string{"observed_at"}},
	},
	SeverityScale: SeverityScaleLabelOnly,
}

func normalizeNative(document any) ([]Draft, error) {
	root, _ := document.(map[string]any)
	if root == nil {
		return nil, fmt.Errorf("%s document must be a JSON object", NativeSchema)
	}
	if _, ok := root["observations"].([]any); !ok {
		return nil, fmt.Errorf("%s document requires an observations array", NativeSchema)
	}
	scanner := text(root, "scanner")
	drafts := nativeMapping.apply(document)
	for i := range drafts {
		if drafts[i].Observation.Scanner == "" {
			drafts[i].Observation.Scanner = scanner
		}
		if record, ok := drafts[i].Raw.(map[string]any); ok {
			if attributes, ok := record["attributes"].(map[string]any); ok {
				drafts[i].Observation.Attributes = stringAttributes(attributes)
			}
		}
	}
	return drafts, nil
}

func normalizeStrix(document any) []Draft {
	records := []any{}
	switch typed := document.(type) {
	case map[string]any:
		if items, ok := typed["items"].([]any); ok {
			records = items
		} else {
			records = []any{typed}
		}
	case []any:
		records = typed
	}
	drafts := make([]Draft, 0, len(records))
	for _, value := range records {
		record, ok := value.(map[string]any)
		if !ok {
			drafts = append(drafts, Draft{Raw: value, Problem: "record is not a JSON object"})
			continue
		}
		findingType := text(record, "finding_type")
		obs := Draft{Raw: record, SeverityScale: SeverityScaleLabelOnly}
		obs.Observation.SourceRecordID = text(record, "id")
		obs.Observation.Title = text(record, "title")
		obs.Observation.Description = firstText(record, "description", "summary", "impact")
		obs.Observation.Scanner = "strix"
		obs.Observation.AssetIdentifier = text(record, "target")
		obs.Observation.VulnerabilityIDs = scalarStrings(record["cve"])
		obs.Observation.CWEs = scalarStrings(record["cwe"])
		obs.Observation.CVSSScore = number(record["cvss"])
		obs.RawSeverity = text(record, "severity")
		obs.RawStatus = text(record, "status")
		obs.RawFirstSeen = text(record, "created_at")
		obs.RawObservedAt = firstText(record, "status_changed_at", "created_at")
		if adjustment, ok := record["cvss_adjustment"].(map[string]any); ok {
			obs.Observation.CVSSVector = text(adjustment, "vector")
		}
		if obs.Observation.CVSSVector == "" {
			obs.Observation.CVSSVector = text(record, "cvss_vector")
		}
		switch findingType {
		case "dependency":
			obs.Observation.Class = ClassPackage
			obs.Observation.AssetType = "repository"
		case "code":
			obs.Observation.Class = ClassCode
			obs.Observation.AssetType = "repository"
		default:
			obs.Observation.Class = ClassWebApplication
			obs.Observation.AssetType = "url"
		}
		if metadata, ok := record["dependency_metadata"].(map[string]any); ok {
			obs.Observation.PackageName = firstText(metadata, "package", "package_name", "name")
			obs.Observation.PackageEcosystem = text(metadata, "ecosystem")
			obs.Observation.PackageVersion = firstText(metadata, "installed_version", "version")
			obs.Observation.FixedVersion = text(metadata, "fixed_version")
			obs.Observation.Location = text(metadata, "manifest_path")
		}
		if obs.Observation.Location == "" {
			obs.Observation.Location = firstText(record, "endpoint", "file_path", "location")
		}
		attributes := map[string]string{}
		if value := text(record, "scan_id"); value != "" {
			attributes["strix.scan_id"] = value
		}
		if value := text(record, "display_number"); value != "" {
			attributes["strix.display_id"] = "STRIX-" + value
		}
		if findingType != "" {
			attributes["strix.finding_type"] = findingType
		}
		if retest, ok := record["latest_retest"].(map[string]any); ok {
			if outcome := text(retest, "outcome"); outcome != "" {
				attributes["strix.latest_retest"] = outcome
			}
		}
		obs.Observation.Attributes = attributes
		drafts = append(drafts, obs)
	}
	return drafts
}

func normalizeSARIF(document any) []Draft {
	root, _ := document.(map[string]any)
	drafts := []Draft{}
	for _, runValue := range list(root, "runs") {
		run, _ := runValue.(map[string]any)
		if run == nil {
			continue
		}
		tool, _ := run["tool"].(map[string]any)
		driver, _ := tool["driver"].(map[string]any)
		scanner := text(driver, "name")
		rules := sarifRules(tool)
		repository := ""
		for _, provenance := range list(run, "versionControlProvenance") {
			if entry, ok := provenance.(map[string]any); ok {
				repository = text(entry, "repositoryUri")
				break
			}
		}
		for _, resultValue := range list(run, "results") {
			result, _ := resultValue.(map[string]any)
			if result == nil {
				drafts = append(drafts, Draft{Raw: resultValue, Problem: "result is not a JSON object"})
				continue
			}
			ruleID := text(result, "ruleId")
			rule := rules[ruleID]
			if index, ok := result["ruleIndex"].(json.Number); ok {
				if position, err := strconv.Atoi(index.String()); err == nil {
					if byIndex := sarifRuleAt(driver, position); byIndex != nil {
						rule = byIndex
					}
				}
			}
			message, _ := result["message"].(map[string]any)
			obs := Draft{Raw: result}
			obs.Observation.Scanner = scanner
			obs.Observation.Class = ClassCode
			obs.Observation.Title = firstNonEmpty(nestedText(rule, "shortDescription", "text"), text(rule, "name"), text(message, "text"), ruleID)
			obs.Observation.Description = firstNonEmpty(text(message, "text"), nestedText(rule, "fullDescription", "text"))
			ruleProperties, _ := rule["properties"].(map[string]any)
			resultProperties, _ := result["properties"].(map[string]any)
			tags := append(scalarStrings(ruleProperties["tags"]), scalarStrings(resultProperties["tags"])...)
			obs.Observation.CWEs = sarifCWEs(tags)
			obs.Observation.VulnerabilityIDs = append(ExtractVulnerabilityIDs(ruleID), ExtractVulnerabilityIDs(tags...)...)
			if score := firstNonEmpty(text(resultProperties, "security-severity"), text(ruleProperties, "security-severity")); score != "" {
				obs.RawSeverity = score
				if value, err := strconv.ParseFloat(score, 64); err == nil && value >= 0 && value <= 10 {
					obs.Observation.CVSSScore = &value
				}
			} else {
				level := text(result, "level")
				if level == "" {
					if configuration, ok := rule["defaultConfiguration"].(map[string]any); ok {
						level = text(configuration, "level")
					}
				}
				obs.RawSeverity = firstNonEmpty(level, "warning")
			}
			uri, line := sarifLocation(result)
			obs.Observation.Location = uri
			if line != "" {
				obs.Observation.Location = uri + ":" + line
			}
			obs.Observation.AssetIdentifier = firstNonEmpty(repository, uri)
			obs.Observation.AssetType = "repository"
			if repository == "" {
				obs.Observation.AssetType = "file"
			}
			obs.Observation.SourceRecordID = firstNonEmpty(text(result, "guid"), sarifFingerprint(result))
			if helpURI := text(rule, "helpUri"); helpURI != "" {
				obs.Observation.References = []string{helpURI}
			}
			if suppressions := list(result, "suppressions"); len(suppressions) > 0 {
				obs.RawStatus = "suppressed"
			} else if text(result, "baselineState") == "absent" {
				obs.RawStatus = "fixed"
			}
			obs.Observation.Attributes = map[string]string{"sarif.rule_id": ruleID}
			drafts = append(drafts, obs)
		}
	}
	return drafts
}

func sarifRules(tool map[string]any) map[string]map[string]any {
	rules := map[string]map[string]any{}
	components := []any{tool["driver"]}
	components = append(components, list(tool, "extensions")...)
	for _, componentValue := range components {
		component, _ := componentValue.(map[string]any)
		for _, ruleValue := range list(component, "rules") {
			if rule, ok := ruleValue.(map[string]any); ok {
				if id := text(rule, "id"); id != "" {
					rules[id] = rule
				}
			}
		}
	}
	return rules
}

func sarifRuleAt(driver map[string]any, index int) map[string]any {
	rules := list(driver, "rules")
	if index < 0 || index >= len(rules) {
		return nil
	}
	rule, _ := rules[index].(map[string]any)
	return rule
}

func sarifCWEs(tags []string) []string {
	out := []string{}
	for _, tag := range tags {
		lower := strings.ToLower(tag)
		if index := strings.LastIndex(lower, "cwe-"); index >= 0 {
			out = append(out, tag[index+4:])
		}
	}
	return NormalizeCWEs(out)
}

func sarifLocation(result map[string]any) (string, string) {
	for _, locationValue := range list(result, "locations") {
		location, _ := locationValue.(map[string]any)
		physical, _ := location["physicalLocation"].(map[string]any)
		artifact, _ := physical["artifactLocation"].(map[string]any)
		region, _ := physical["region"].(map[string]any)
		if uri := text(artifact, "uri"); uri != "" {
			return uri, text(region, "startLine")
		}
	}
	return "", ""
}

func sarifFingerprint(result map[string]any) string {
	for _, key := range []string{"fingerprints", "partialFingerprints"} {
		if fingerprints, ok := result[key].(map[string]any); ok {
			for _, name := range sortedKeys(fingerprints) {
				if value := text(fingerprints, name); value != "" {
					return name + ":" + value
				}
			}
		}
	}
	return ""
}

func normalizeCycloneDX(document any) []Draft {
	root, _ := document.(map[string]any)
	components := map[string]map[string]any{}
	var collect func(values []any)
	collect = func(values []any) {
		for _, value := range values {
			component, _ := value.(map[string]any)
			if component == nil {
				continue
			}
			if ref := text(component, "bom-ref"); ref != "" {
				components[ref] = component
			}
			collect(list(component, "components"))
		}
	}
	collect(list(root, "components"))
	metadata, _ := root["metadata"].(map[string]any)
	subject, _ := metadata["component"].(map[string]any)
	subjectID := firstNonEmpty(text(subject, "purl"), text(subject, "name"), text(subject, "bom-ref"))
	subjectDigest := digestFromText(text(subject, "purl"), text(subject, "version"))
	scanner := ""
	if tools, ok := metadata["tools"].(map[string]any); ok {
		for _, componentValue := range list(tools, "components") {
			if component, ok := componentValue.(map[string]any); ok {
				scanner = text(component, "name")
				break
			}
		}
	} else {
		for _, toolValue := range list(metadata, "tools") {
			if tool, ok := toolValue.(map[string]any); ok {
				scanner = text(tool, "name")
				break
			}
		}
	}
	drafts := []Draft{}
	for _, vulnValue := range list(root, "vulnerabilities") {
		vuln, _ := vulnValue.(map[string]any)
		if vuln == nil {
			drafts = append(drafts, Draft{Raw: vulnValue, Problem: "vulnerability is not a JSON object"})
			continue
		}
		id := text(vuln, "id")
		ids := []string{id}
		for _, reference := range list(vuln, "references") {
			if ref, ok := reference.(map[string]any); ok {
				ids = append(ids, text(ref, "id"))
			}
		}
		severity, score, vector := cyclonedxRating(list(vuln, "ratings"))
		analysis, _ := vuln["analysis"].(map[string]any)
		status := text(analysis, "state")
		affects := list(vuln, "affects")
		if len(affects) == 0 {
			affects = []any{map[string]any{}}
		}
		for _, affectValue := range affects {
			affect, _ := affectValue.(map[string]any)
			ref := text(affect, "ref")
			component := components[ref]
			obs := Draft{Raw: vuln, SeverityScale: SeverityScaleLabelOnly}
			obs.Observation.Scanner = scanner
			obs.Observation.Class = ClassPackage
			obs.Observation.VulnerabilityIDs = ids
			obs.Observation.CWEs = scalarStrings(vuln["cwes"])
			obs.Observation.Title = firstNonEmpty(text(vuln, "description"), id)
			obs.Observation.Description = firstNonEmpty(text(vuln, "detail"), text(vuln, "description"))
			obs.Observation.CVSSScore = score
			obs.Observation.CVSSVector = vector
			obs.RawSeverity = severity
			obs.RawStatus = cyclonedxStatus(status)
			obs.RawFirstSeen = text(vuln, "created")
			obs.RawLastSeen = text(vuln, "updated")
			obs.Observation.PackageName = joinNonEmpty("/", text(component, "group"), text(component, "name"))
			obs.Observation.PackageVersion = text(component, "version")
			obs.Observation.PackageURL = text(component, "purl")
			obs.Observation.PackageEcosystem = ecosystemFromPURL(obs.Observation.PackageURL)
			obs.Observation.FixedVersion = cyclonedxFixedVersion(vuln)
			obs.Observation.AssetIdentifier = firstNonEmpty(subjectID, obs.Observation.PackageURL)
			obs.Observation.AssetType = text(subject, "type")
			obs.Observation.ImageDigest = subjectDigest
			if obs.Observation.ImageDigest != "" {
				obs.Observation.Class = ClassContainerImage
			}
			obs.Observation.SourceRecordID = joinNonEmpty("|", id, firstNonEmpty(ref, obs.Observation.PackageURL))
			if source, ok := vuln["source"].(map[string]any); ok {
				if url := text(source, "url"); url != "" {
					obs.Observation.References = []string{url}
				}
			}
			drafts = append(drafts, obs)
		}
	}
	return drafts
}

func cyclonedxRating(ratings []any) (string, *float64, string) {
	bestRank := -1
	severity, vector := "", ""
	var score *float64
	for _, ratingValue := range ratings {
		rating, _ := ratingValue.(map[string]any)
		label := text(rating, "severity")
		value := number(rating["score"])
		candidate := NormalizeSeverity(label, SeverityScaleLabelOnly, nil, value)
		if rank := SeverityRank(candidate); rank > bestRank {
			bestRank = rank
			severity = firstNonEmpty(label, candidate)
			score = value
			vector = text(rating, "vector")
		}
	}
	return severity, score, vector
}

func cyclonedxStatus(state string) string {
	switch strings.ToLower(state) {
	case "resolved", "resolved_with_pedigree":
		return StatusFixed
	case "false_positive":
		return StatusSuppressed
	case "not_affected":
		return StatusNotAffected
	case "in_triage":
		return StatusInProgress
	default:
		return ""
	}
}

func cyclonedxFixedVersion(vuln map[string]any) string {
	for _, affectValue := range list(vuln, "affects") {
		affect, _ := affectValue.(map[string]any)
		for _, versionValue := range list(affect, "versions") {
			version, _ := versionValue.(map[string]any)
			if strings.EqualFold(text(version, "status"), "unaffected") {
				return text(version, "version")
			}
		}
	}
	return ""
}

func normalizeOSVScanner(document any) []Draft {
	root, _ := document.(map[string]any)
	drafts := []Draft{}
	for _, resultValue := range list(root, "results") {
		result, _ := resultValue.(map[string]any)
		source, _ := result["source"].(map[string]any)
		sourcePath := text(source, "path")
		for _, packageValue := range list(result, "packages") {
			entry, _ := packageValue.(map[string]any)
			pkg, _ := entry["package"].(map[string]any)
			groupSeverity := map[string]string{}
			for _, groupValue := range list(entry, "groups") {
				group, _ := groupValue.(map[string]any)
				for _, id := range scalarStrings(group["ids"]) {
					groupSeverity[id] = text(group, "max_severity")
				}
			}
			for _, vulnValue := range list(entry, "vulnerabilities") {
				vuln, _ := vulnValue.(map[string]any)
				if vuln == nil {
					continue
				}
				id := text(vuln, "id")
				obs := Draft{Raw: vuln}
				obs.Observation.Scanner = "osv-scanner"
				obs.Observation.Class = ClassPackage
				obs.Observation.VulnerabilityIDs = append([]string{id}, scalarStrings(vuln["aliases"])...)
				obs.Observation.Title = firstNonEmpty(text(vuln, "summary"), id)
				obs.Observation.Description = text(vuln, "details")
				obs.Observation.PackageName = text(pkg, "name")
				obs.Observation.PackageVersion = text(pkg, "version")
				obs.Observation.PackageEcosystem = text(pkg, "ecosystem")
				obs.Observation.FixedVersion = osvFixedVersion(vuln, text(pkg, "name"))
				obs.Observation.Location = sourcePath
				obs.Observation.AssetIdentifier = sourcePath
				obs.Observation.AssetType = "manifest"
				if severity := groupSeverity[id]; severity != "" {
					obs.RawSeverity = severity
					obs.SeverityScale = SeverityScaleCVSS
					obs.Observation.CVSSScore = number(json.Number(severity))
				} else if specific, ok := vuln["database_specific"].(map[string]any); ok {
					obs.RawSeverity = text(specific, "severity")
				}
				for _, severityValue := range list(vuln, "severity") {
					if entry, ok := severityValue.(map[string]any); ok && strings.HasPrefix(text(entry, "score"), "CVSS:") {
						obs.Observation.CVSSVector = text(entry, "score")
						break
					}
				}
				obs.RawLastSeen = text(vuln, "modified")
				for _, referenceValue := range list(vuln, "references") {
					if reference, ok := referenceValue.(map[string]any); ok {
						obs.Observation.References = append(obs.Observation.References, text(reference, "url"))
					}
				}
				obs.Observation.SourceRecordID = joinNonEmpty("|", id, sourcePath, text(pkg, "ecosystem"), text(pkg, "name"), text(pkg, "version"))
				drafts = append(drafts, obs)
			}
		}
	}
	return drafts
}

func osvFixedVersion(vuln map[string]any, packageName string) string {
	for _, affectedValue := range list(vuln, "affected") {
		affected, _ := affectedValue.(map[string]any)
		pkg, _ := affected["package"].(map[string]any)
		if packageName != "" && text(pkg, "name") != "" && text(pkg, "name") != packageName {
			continue
		}
		for _, rangeValue := range list(affected, "ranges") {
			rng, _ := rangeValue.(map[string]any)
			for _, eventValue := range list(rng, "events") {
				if event, ok := eventValue.(map[string]any); ok {
					if fixed := text(event, "fixed"); fixed != "" {
						return fixed
					}
				}
			}
		}
	}
	return ""
}

func normalizeTrivy(document any) []Draft {
	root, _ := document.(map[string]any)
	artifact := text(root, "ArtifactName")
	artifactType := text(root, "ArtifactType")
	metadata, _ := root["Metadata"].(map[string]any)
	digest := ""
	for _, repoDigest := range scalarStrings(metadata["RepoDigests"]) {
		if digest = digestFromText(repoDigest); digest != "" {
			break
		}
	}
	class := ClassPackage
	// Older Trivy reports omit ArtifactType; a repo digest still identifies an image.
	if artifactType == "container_image" || digest != "" {
		class = ClassContainerImage
	}
	drafts := []Draft{}
	for _, resultValue := range list(root, "Results") {
		result, _ := resultValue.(map[string]any)
		target := text(result, "Target")
		for _, vulnValue := range list(result, "Vulnerabilities") {
			vuln, _ := vulnValue.(map[string]any)
			if vuln == nil {
				continue
			}
			id := text(vuln, "VulnerabilityID")
			obs := Draft{Raw: vuln, SeverityScale: SeverityScaleLabelOnly}
			obs.Observation.Scanner = "trivy"
			obs.Observation.Class = class
			obs.Observation.VulnerabilityIDs = []string{id}
			obs.Observation.Title = firstNonEmpty(text(vuln, "Title"), id)
			obs.Observation.Description = text(vuln, "Description")
			obs.Observation.CWEs = scalarStrings(vuln["CweIDs"])
			obs.Observation.PackageName = text(vuln, "PkgName")
			obs.Observation.PackageVersion = text(vuln, "InstalledVersion")
			obs.Observation.FixedVersion = text(vuln, "FixedVersion")
			if identifier, ok := vuln["PkgIdentifier"].(map[string]any); ok {
				obs.Observation.PackageURL = text(identifier, "PURL")
			}
			obs.Observation.PackageEcosystem = firstNonEmpty(ecosystemFromPURL(obs.Observation.PackageURL), text(result, "Type"))
			obs.Observation.Location = target
			obs.Observation.AssetIdentifier = firstNonEmpty(artifact, target)
			obs.Observation.AssetType = artifactType
			obs.Observation.ImageDigest = digest
			obs.RawSeverity = text(vuln, "Severity")
			obs.RawStatus = trivyStatus(text(vuln, "Status"))
			obs.RawLastSeen = text(vuln, "LastModifiedDate")
			obs.Observation.CVSSScore, obs.Observation.CVSSVector = trivyCVSS(vuln)
			obs.Observation.References = scalarStrings(vuln["References"])
			if primary := text(vuln, "PrimaryURL"); primary != "" {
				obs.Observation.References = append([]string{primary}, obs.Observation.References...)
			}
			obs.Observation.SourceRecordID = joinNonEmpty("|", artifact, target, id, firstNonEmpty(text(vuln, "PkgID"), obs.Observation.PackageName))
			drafts = append(drafts, obs)
		}
		for _, misconfigValue := range list(result, "Misconfigurations") {
			misconfig, _ := misconfigValue.(map[string]any)
			if misconfig == nil || !strings.EqualFold(text(misconfig, "Status"), "FAIL") {
				continue
			}
			id := firstNonEmpty(text(misconfig, "AVDID"), text(misconfig, "ID"))
			obs := Draft{Raw: misconfig, SeverityScale: SeverityScaleLabelOnly}
			obs.Observation.Scanner = "trivy"
			obs.Observation.Class = ClassCloudConfig
			obs.Observation.Title = firstNonEmpty(text(misconfig, "Title"), id)
			obs.Observation.Description = firstNonEmpty(text(misconfig, "Message"), text(misconfig, "Description"))
			obs.Observation.Location = target
			obs.Observation.AssetIdentifier = firstNonEmpty(artifact, target)
			obs.Observation.AssetType = artifactType
			obs.RawSeverity = text(misconfig, "Severity")
			obs.Observation.References = scalarStrings(misconfig["References"])
			obs.Observation.SourceRecordID = joinNonEmpty("|", artifact, target, id)
			obs.Observation.Attributes = map[string]string{"trivy.check_id": id}
			drafts = append(drafts, obs)
		}
	}
	return drafts
}

func trivyStatus(status string) string {
	switch strings.ToLower(status) {
	case "not_affected":
		return StatusNotAffected
	// Trivy's "fixed" means a fixed release exists, not that the installed
	// package is fixed, so the observation stays open.
	case "will_not_fix", "end_of_life", "fixed":
		return StatusOpen
	default:
		return ""
	}
}

func trivyCVSS(vuln map[string]any) (*float64, string) {
	cvss, _ := vuln["CVSS"].(map[string]any)
	for _, source := range append([]string{"nvd", "ghsa", "redhat"}, sortedKeys(cvss)...) {
		entry, _ := cvss[source].(map[string]any)
		if entry == nil {
			continue
		}
		if score := number(entry["V3Score"]); score != nil {
			return score, text(entry, "V3Vector")
		}
	}
	return nil, ""
}

func normalizeGrype(document any) []Draft {
	root, _ := document.(map[string]any)
	source, _ := root["source"].(map[string]any)
	target, _ := source["target"].(map[string]any)
	subject := firstNonEmpty(text(target, "userInput"), text(source, "target"))
	digest := digestFromText(text(target, "manifestDigest"))
	if digest == "" {
		for _, repoDigest := range scalarStrings(target["repoDigests"]) {
			if digest = digestFromText(repoDigest); digest != "" {
				break
			}
		}
	}
	class := ClassPackage
	if text(source, "type") == "image" {
		class = ClassContainerImage
	}
	drafts := []Draft{}
	for _, matchValue := range list(root, "matches") {
		match, _ := matchValue.(map[string]any)
		vuln, _ := match["vulnerability"].(map[string]any)
		artifact, _ := match["artifact"].(map[string]any)
		if vuln == nil {
			drafts = append(drafts, Draft{Raw: matchValue, Problem: "match has no vulnerability"})
			continue
		}
		id := text(vuln, "id")
		ids := []string{id}
		for _, relatedValue := range list(match, "relatedVulnerabilities") {
			if related, ok := relatedValue.(map[string]any); ok {
				ids = append(ids, text(related, "id"))
			}
		}
		obs := Draft{Raw: match, SeverityScale: SeverityScaleLabelOnly}
		obs.Observation.Scanner = "grype"
		obs.Observation.Class = class
		obs.Observation.VulnerabilityIDs = ids
		obs.Observation.Title = id
		obs.Observation.Description = text(vuln, "description")
		obs.Observation.PackageName = text(artifact, "name")
		obs.Observation.PackageVersion = text(artifact, "version")
		obs.Observation.PackageURL = text(artifact, "purl")
		obs.Observation.PackageEcosystem = firstNonEmpty(ecosystemFromPURL(obs.Observation.PackageURL), text(artifact, "type"))
		if fix, ok := vuln["fix"].(map[string]any); ok {
			if versions := scalarStrings(fix["versions"]); len(versions) > 0 {
				obs.Observation.FixedVersion = versions[0]
			}
		}
		for _, locationValue := range list(artifact, "locations") {
			if location, ok := locationValue.(map[string]any); ok {
				obs.Observation.Location = text(location, "path")
				break
			}
		}
		for _, cvssValue := range list(vuln, "cvss") {
			entry, _ := cvssValue.(map[string]any)
			metrics, _ := entry["metrics"].(map[string]any)
			if score := number(metrics["baseScore"]); score != nil {
				obs.Observation.CVSSScore = score
				obs.Observation.CVSSVector = text(entry, "vector")
				break
			}
		}
		obs.Observation.AssetIdentifier = firstNonEmpty(subject, obs.Observation.Location)
		obs.Observation.AssetType = text(source, "type")
		obs.Observation.ImageDigest = digest
		obs.RawSeverity = text(vuln, "severity")
		obs.Observation.References = scalarStrings(vuln["urls"])
		if dataSource := text(vuln, "dataSource"); dataSource != "" {
			obs.Observation.References = append([]string{dataSource}, obs.Observation.References...)
		}
		obs.Observation.SourceRecordID = joinNonEmpty("|", subject, id, firstNonEmpty(obs.Observation.PackageURL, obs.Observation.PackageName+"@"+obs.Observation.PackageVersion))
		drafts = append(drafts, obs)
	}
	return drafts
}

func digestFromText(values ...string) string {
	for _, value := range values {
		index := strings.Index(value, "sha256:")
		if index < 0 {
			continue
		}
		candidate := value[index:]
		if len(candidate) >= 71 {
			candidate = strings.ToLower(candidate[:71])
			if digestPattern.MatchString(candidate) {
				return candidate
			}
		}
	}
	return ""
}

func ecosystemFromPURL(purl string) string {
	if !strings.HasPrefix(purl, "pkg:") {
		return ""
	}
	rest := strings.TrimPrefix(purl, "pkg:")
	if index := strings.Index(rest, "/"); index > 0 {
		return strings.ToLower(rest[:index])
	}
	return ""
}

func text(object map[string]any, key string) string {
	if object == nil {
		return ""
	}
	values := scalarStrings(object[key])
	if len(values) == 0 {
		return ""
	}
	if _, isList := object[key].([]any); isList {
		return ""
	}
	return strings.TrimSpace(values[0])
}

func nestedText(object map[string]any, key string, child string) string {
	if object == nil {
		return ""
	}
	nested, _ := object[key].(map[string]any)
	return text(nested, child)
}

func firstText(object map[string]any, keys ...string) string {
	for _, key := range keys {
		if value := text(object, key); value != "" {
			return value
		}
	}
	return ""
}

func list(object map[string]any, key string) []any {
	if object == nil {
		return nil
	}
	values, _ := object[key].([]any)
	return values
}

func number(value any) *float64 {
	var parsed float64
	switch typed := value.(type) {
	case json.Number:
		number, err := typed.Float64()
		if err != nil {
			return nil
		}
		parsed = number
	case float64:
		parsed = typed
	case string:
		number, err := strconv.ParseFloat(strings.TrimSpace(typed), 64)
		if err != nil {
			return nil
		}
		parsed = number
	default:
		return nil
	}
	if parsed < 0 || parsed > 10 {
		return nil
	}
	return &parsed
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func joinNonEmpty(separator string, values ...string) string {
	parts := []string{}
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			parts = append(parts, trimmed)
		}
	}
	return strings.Join(parts, separator)
}

func stringAttributes(values map[string]any) map[string]string {
	out := map[string]string{}
	for _, key := range sortedKeys(values) {
		if len(out) >= maxAttributes {
			break
		}
		if rendered := scalarStrings(values[key]); len(rendered) == 1 {
			out[key] = truncate(rendered[0], maxAttributeValueBytes)
		}
	}
	return out
}
