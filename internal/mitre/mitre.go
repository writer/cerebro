package mitre

import (
	"regexp"
	"strings"

	cerebrourn "github.com/writer/cerebro/internal/urn"
)

const (
	AttackTacticEntityType      = "mitre.attack.tactic"
	AttackTechniqueEntityType   = "mitre.attack.technique"
	DefendTacticEntityType      = "mitre.defend.tactic"
	DefendTechniqueEntityType   = "mitre.defend.technique"
	DefendArtifactEntityType    = "mitre.defend.artifact"
	AttackTacticURNKind         = "mitre_attack_tactic"
	AttackTechniqueURNKind      = "mitre_attack_technique"
	AttackTechniqueLabelURNKind = "mitre_attack_technique_label"
	DefendTacticURNKind         = "mitre_defend_tactic"
	DefendTechniqueURNKind      = "mitre_defend_technique"
	DefendArtifactURNKind       = "mitre_defend_artifact"
)

var (
	attackTechniquePattern       = regexp.MustCompile(`(?i)\bT\d{4}(?:\.\d{3})?\b`)
	attackSubtechniqueURLPattern = regexp.MustCompile(`(?i)/techniques/(T\d{4})/(\d{3})(?:/|\b)`)
	attackTacticPattern          = regexp.MustCompile(`(?i)\bTA\d{4}\b`)
	whitespacePattern            = regexp.MustCompile(`\s+`)
)

type AttackTactic struct {
	ID          string
	Name        string
	SourceValue string
}

type AttackTechnique struct {
	ID          string
	Name        string
	SourceValue string
}

type DefendTactic struct {
	ID          string
	Name        string
	SourceValue string
}

type DefendTechnique struct {
	ID          string
	Name        string
	SourceValue string
}

type DefendArtifact struct {
	ID          string
	Name        string
	SourceValue string
}

var attackTactics = []AttackTactic{
	{ID: "TA0043", Name: "Reconnaissance"},
	{ID: "TA0042", Name: "Resource Development"},
	{ID: "TA0001", Name: "Initial Access"},
	{ID: "TA0002", Name: "Execution"},
	{ID: "TA0003", Name: "Persistence"},
	{ID: "TA0004", Name: "Privilege Escalation"},
	{ID: "TA0005", Name: "Defense Evasion"},
	{ID: "TA0006", Name: "Credential Access"},
	{ID: "TA0007", Name: "Discovery"},
	{ID: "TA0008", Name: "Lateral Movement"},
	{ID: "TA0009", Name: "Collection"},
	{ID: "TA0011", Name: "Command and Control"},
	{ID: "TA0010", Name: "Exfiltration"},
	{ID: "TA0040", Name: "Impact"},
}

var attackTacticByID = func() map[string]AttackTactic {
	out := make(map[string]AttackTactic, len(attackTactics))
	for _, tactic := range attackTactics {
		out[tactic.ID] = tactic
	}
	return out
}()

var attackTacticByName = func() map[string]AttackTactic {
	out := map[string]AttackTactic{}
	for _, tactic := range attackTactics {
		out[normalizeKey(tactic.Name)] = tactic
		out[normalizeKey(strings.ReplaceAll(tactic.Name, " and ", " "))] = tactic
	}
	return out
}()

func ExtractAttackTactics(values ...string) []AttackTactic {
	out := []AttackTactic{}
	seen := map[string]struct{}{}
	for _, raw := range splitValues(values...) {
		if raw == "" {
			continue
		}
		for _, id := range attackTacticPattern.FindAllString(raw, -1) {
			tactic := attackTacticByID[strings.ToUpper(id)]
			if tactic.ID == "" {
				tactic = AttackTactic{ID: strings.ToUpper(id), Name: strings.ToUpper(id)}
			}
			tactic.SourceValue = raw
			addAttackTactic(&out, seen, tactic)
		}
		if tactic, ok := attackTacticByName[normalizeKey(strings.TrimPrefix(raw, "attack."))]; ok {
			tactic.SourceValue = raw
			addAttackTactic(&out, seen, tactic)
		}
		if tacticName, _, ok := strings.Cut(raw, ":"); ok {
			if tactic, ok := attackTacticByName[normalizeKey(tacticName)]; ok {
				tactic.SourceValue = raw
				addAttackTactic(&out, seen, tactic)
			}
		}
	}
	return out
}

func ExtractAttackTechniques(values ...string) []AttackTechnique {
	return extractAttackTechniques(true, values...)
}

func ExtractAttackTechniqueIDs(values ...string) []AttackTechnique {
	return extractAttackTechniques(false, values...)
}

func extractAttackTechniques(allowLabels bool, values ...string) []AttackTechnique {
	out := []AttackTechnique{}
	seen := map[string]struct{}{}
	for _, raw := range splitValues(values...) {
		matchedID := false
		for _, match := range attackSubtechniqueURLPattern.FindAllStringSubmatch(raw, -1) {
			if len(match) != 3 {
				continue
			}
			matchedID = true
			technique := AttackTechnique{ID: strings.ToUpper(match[1] + "." + match[2]), Name: strings.ToUpper(match[1] + "." + match[2]), SourceValue: raw}
			addAttackTechnique(&out, seen, technique)
		}
		if matchedID {
			continue
		}
		for _, id := range attackTechniquePattern.FindAllString(raw, -1) {
			matchedID = true
			technique := AttackTechnique{ID: strings.ToUpper(id), Name: strings.ToUpper(id), SourceValue: raw}
			addAttackTechnique(&out, seen, technique)
		}
		if matchedID || !allowLabels {
			continue
		}
		label := strings.TrimSpace(raw)
		if label == "" || attackTacticPattern.MatchString(label) || attackTechniquePattern.MatchString(label) {
			continue
		}
		if _, ok := attackTacticByName[normalizeKey(label)]; ok {
			continue
		}
		addAttackTechnique(&out, seen, AttackTechnique{Name: label, SourceValue: raw})
	}
	return out
}

func ExtractDefendTactics(values ...string) []DefendTactic {
	out := []DefendTactic{}
	seen := map[string]struct{}{}
	for _, raw := range splitValues(values...) {
		id, name := defendIDAndName(raw)
		if id == "" && name == "" {
			continue
		}
		key := firstNonEmpty(id, normalizeKey(name))
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, DefendTactic{ID: id, Name: name, SourceValue: raw})
	}
	return out
}

func ExtractDefendTechniques(values ...string) []DefendTechnique {
	out := []DefendTechnique{}
	seen := map[string]struct{}{}
	for _, raw := range splitValues(values...) {
		id, name := defendIDAndName(raw)
		if id == "" && name == "" {
			continue
		}
		key := firstNonEmpty(id, normalizeKey(name))
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, DefendTechnique{ID: id, Name: name, SourceValue: raw})
	}
	return out
}

func ExtractDefendArtifacts(values ...string) []DefendArtifact {
	out := []DefendArtifact{}
	seen := map[string]struct{}{}
	for _, raw := range splitValues(values...) {
		id, name := defendIDAndName(raw)
		if id == "" && name == "" {
			continue
		}
		key := firstNonEmpty(id, normalizeKey(name))
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, DefendArtifact{ID: id, Name: name, SourceValue: raw})
	}
	return out
}

func AttackTacticURN(tenantID string, tactic AttackTactic) string {
	id := strings.TrimSpace(tactic.ID)
	if id == "" {
		id = normalizeKey(tactic.Name)
	}
	return mint(tenantID, AttackTacticURNKind, id)
}

func AttackTechniqueURN(tenantID string, technique AttackTechnique) string {
	if id := strings.TrimSpace(technique.ID); id != "" {
		return mint(tenantID, AttackTechniqueURNKind, id)
	}
	return mint(tenantID, AttackTechniqueLabelURNKind, normalizeKey(technique.Name))
}

func DefendTacticURN(tenantID string, tactic DefendTactic) string {
	return mint(tenantID, DefendTacticURNKind, firstNonEmpty(tactic.ID, normalizeKey(tactic.Name)))
}

func DefendTechniqueURN(tenantID string, technique DefendTechnique) string {
	return mint(tenantID, DefendTechniqueURNKind, firstNonEmpty(technique.ID, normalizeKey(technique.Name)))
}

func DefendArtifactURN(tenantID string, artifact DefendArtifact) string {
	return mint(tenantID, DefendArtifactURNKind, firstNonEmpty(artifact.ID, normalizeKey(artifact.Name)))
}

func AttackTacticAttributes(tactic AttackTactic) map[string]string {
	return compact(map[string]string{
		"mitre_domain":    "attack",
		"tactic_id":       tactic.ID,
		"tactic_name":     firstNonEmpty(tactic.Name, tactic.ID),
		"source_value":    tactic.SourceValue,
		"source_taxonomy": "mitre_attack",
	})
}

func AttackTechniqueAttributes(technique AttackTechnique) map[string]string {
	matchType := "technique_id"
	if strings.TrimSpace(technique.ID) == "" {
		matchType = "source_label"
	}
	return compact(map[string]string{
		"mitre_domain":    "attack",
		"technique_id":    technique.ID,
		"technique_name":  firstNonEmpty(technique.Name, technique.ID),
		"match_type":      matchType,
		"source_value":    technique.SourceValue,
		"source_taxonomy": "mitre_attack",
	})
}

func DefendTacticAttributes(tactic DefendTactic) map[string]string {
	return compact(map[string]string{
		"mitre_domain":    "defend",
		"tactic_id":       tactic.ID,
		"tactic_name":     firstNonEmpty(tactic.Name, tactic.ID),
		"source_value":    tactic.SourceValue,
		"source_taxonomy": "mitre_defend",
	})
}

func DefendTechniqueAttributes(technique DefendTechnique) map[string]string {
	return compact(map[string]string{
		"mitre_domain":    "defend",
		"technique_id":    technique.ID,
		"technique_name":  firstNonEmpty(technique.Name, technique.ID),
		"source_value":    technique.SourceValue,
		"source_taxonomy": "mitre_defend",
	})
}

func DefendArtifactAttributes(artifact DefendArtifact) map[string]string {
	return compact(map[string]string{
		"mitre_domain":    "defend",
		"artifact_id":     artifact.ID,
		"artifact_name":   firstNonEmpty(artifact.Name, artifact.ID),
		"source_value":    artifact.SourceValue,
		"source_taxonomy": "mitre_defend",
	})
}

func AttackTacticLabel(tactic AttackTactic) string {
	return firstNonEmpty(tactic.Name, tactic.ID)
}

func AttackTechniqueLabel(technique AttackTechnique) string {
	return firstNonEmpty(technique.ID, technique.Name)
}

func DefendTacticLabel(tactic DefendTactic) string {
	return firstNonEmpty(tactic.Name, tactic.ID)
}

func DefendTechniqueLabel(technique DefendTechnique) string {
	return firstNonEmpty(technique.Name, technique.ID)
}

func DefendArtifactLabel(artifact DefendArtifact) string {
	return firstNonEmpty(artifact.Name, artifact.ID)
}

func splitValues(values ...string) []string {
	out := []string{}
	for _, value := range values {
		for _, part := range strings.FieldsFunc(strings.TrimSpace(value), func(r rune) bool {
			return r == ',' || r == ';' || r == '\n' || r == '\t' || r == '|'
		}) {
			part = strings.TrimSpace(part)
			if part != "" {
				out = append(out, part)
			}
		}
	}
	return out
}

func addAttackTactic(out *[]AttackTactic, seen map[string]struct{}, tactic AttackTactic) {
	key := firstNonEmpty(tactic.ID, normalizeKey(tactic.Name))
	if key == "" {
		return
	}
	if _, ok := seen[key]; ok {
		return
	}
	seen[key] = struct{}{}
	*out = append(*out, tactic)
}

func addAttackTechnique(out *[]AttackTechnique, seen map[string]struct{}, technique AttackTechnique) {
	key := firstNonEmpty(technique.ID, normalizeKey(technique.Name))
	if key == "" {
		return
	}
	if _, ok := seen[key]; ok {
		return
	}
	seen[key] = struct{}{}
	*out = append(*out, technique)
}

func defendIDAndName(raw string) (string, string) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", ""
	}
	candidate := value
	candidate = strings.TrimRight(candidate, "#/")
	if idx := strings.LastIndexAny(candidate, "#/"); idx >= 0 && idx < len(candidate)-1 {
		candidate = candidate[idx+1:]
	}
	candidate = strings.TrimPrefix(candidate, "d3f:")
	candidate = strings.TrimPrefix(candidate, "D3F:")
	candidate = strings.TrimPrefix(candidate, "d3fend:")
	candidate = strings.TrimPrefix(candidate, "D3FEND:")
	candidate = strings.TrimSpace(candidate)
	if candidate == "" {
		return "", value
	}
	if strings.Contains(candidate, " ") {
		return "", value
	}
	return candidate, candidate
}

func normalizeKey(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	normalized = strings.TrimPrefix(normalized, "attack.")
	normalized = strings.TrimPrefix(normalized, "mitre-")
	normalized = strings.TrimPrefix(normalized, "mitre_")
	normalized = strings.ReplaceAll(normalized, "_", " ")
	normalized = strings.ReplaceAll(normalized, "-", " ")
	normalized = whitespacePattern.ReplaceAllString(normalized, " ")
	normalized = strings.TrimSpace(normalized)
	return strings.ReplaceAll(normalized, " ", "-")
}

func mint(tenantID string, kind string, value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	urn, err := cerebrourn.Mint(tenantID, kind, cerebrourn.EncodeSegment(value))
	if err != nil {
		return ""
	}
	return urn
}

func compact(values map[string]string) map[string]string {
	out := make(map[string]string, len(values))
	for key, value := range values {
		if strings.TrimSpace(key) != "" && strings.TrimSpace(value) != "" {
			out[key] = strings.TrimSpace(value)
		}
	}
	return out
}

func firstNonEmpty(values ...string) string {
	return firstFunc(values, func(value string) bool { return strings.TrimSpace(value) != "" })
}

func firstFunc(values []string, keep func(string) bool) string {
	for _, value := range values {
		if keep(value) {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
