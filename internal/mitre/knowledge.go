package mitre

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

const (
	KnowledgePackID               = "cerebro-mitre-core-v1"
	AttackDataSourceEntityType    = "mitre.attack.data_source"
	AttackDataComponentEntityType = "mitre.attack.data_component"
	AttackCoverageEntityType      = "mitre.attack.coverage"
	AttackDataSourceURNKind       = "mitre_attack_data_source"
	AttackDataComponentURNKind    = "mitre_attack_data_component"
	AttackCoverageURNKind         = "mitre_attack_coverage"
)

type AttackDataSource struct {
	ID          string
	Name        string
	Domain      string
	Description string
}

type AttackDataComponent struct {
	ID           string
	Name         string
	DataSourceID string
	Description  string
}

type AttackTechniqueKnowledge struct {
	ID               string
	Name             string
	TacticIDs        []string
	DataComponents   []AttackDataComponent
	DefendTechniques []DefendTechnique
	DefendArtifacts  []DefendArtifact
	References       []string
}

type CoverageState struct {
	State           string
	Status          string
	EvidenceSurface string
}

type KnowledgePack struct {
	ID string
}

func DefaultKnowledgePack() KnowledgePack {
	return KnowledgePack{ID: KnowledgePackID}
}

func AttackTechniqueKnowledgeFor(technique AttackTechnique) (AttackTechniqueKnowledge, bool) {
	return DefaultKnowledgePack().AttackTechniqueKnowledge(technique)
}

func (p KnowledgePack) AttackTechniqueKnowledge(technique AttackTechnique) (AttackTechniqueKnowledge, bool) {
	id := normalizedAttackTechniqueID(technique.ID)
	if id == "" {
		id = normalizedAttackTechniqueID(technique.Name)
	}
	if id == "" {
		return AttackTechniqueKnowledge{}, false
	}
	if knowledge, ok := attackTechniqueKnowledgeByID[id]; ok {
		return cloneAttackTechniqueKnowledge(knowledge), true
	}
	if parent, _, ok := strings.Cut(id, "."); ok {
		if knowledge, ok := attackTechniqueKnowledgeByID[parent]; ok {
			knowledge = cloneAttackTechniqueKnowledge(knowledge)
			knowledge.ID = id
			if strings.TrimSpace(technique.Name) != "" && !strings.EqualFold(technique.Name, id) {
				knowledge.Name = strings.TrimSpace(technique.Name)
			} else {
				knowledge.Name = id
			}
			return knowledge, true
		}
	}
	return AttackTechniqueKnowledge{}, false
}

func AttackDataSourceURN(tenantID string, source AttackDataSource) string {
	return mint(tenantID, AttackDataSourceURNKind, firstNonEmpty(source.ID, normalizeKey(source.Name)))
}

func AttackDataComponentURN(tenantID string, component AttackDataComponent) string {
	return mint(tenantID, AttackDataComponentURNKind, firstNonEmpty(component.ID, normalizeKey(component.DataSourceID+":"+component.Name), normalizeKey(component.Name)))
}

func AttackCoverageURN(tenantID string, anchorURN string, techniqueURN string) string {
	anchorURN = strings.TrimSpace(anchorURN)
	techniqueURN = strings.TrimSpace(techniqueURN)
	if anchorURN == "" || techniqueURN == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(anchorURN + "\n" + techniqueURN))
	return mint(tenantID, AttackCoverageURNKind, hex.EncodeToString(sum[:])[:24])
}

func AttackDataSourceAttributes(source AttackDataSource) map[string]string {
	return compact(map[string]string{
		"mitre_domain":      "attack",
		"data_source_id":    source.ID,
		"data_source_name":  firstNonEmpty(source.Name, source.ID),
		"domain":            source.Domain,
		"description":       source.Description,
		"source_taxonomy":   "mitre_attack",
		"knowledge_pack_id": KnowledgePackID,
	})
}

func AttackDataComponentAttributes(component AttackDataComponent) map[string]string {
	return compact(map[string]string{
		"mitre_domain":        "attack",
		"data_component_id":   component.ID,
		"data_component_name": firstNonEmpty(component.Name, component.ID),
		"data_source_id":      component.DataSourceID,
		"description":         component.Description,
		"source_taxonomy":     "mitre_attack",
		"knowledge_pack_id":   KnowledgePackID,
	})
}

func AttackCoverageAttributes(technique AttackTechnique, state CoverageState, anchorURN string, sourceValue string, extra map[string]string) map[string]string {
	attrs := map[string]string{
		"mitre_domain":      "attack",
		"technique_id":      strings.TrimSpace(technique.ID),
		"technique_name":    AttackTechniqueLabel(technique),
		"coverage_state":    NormalizeCoverageState(firstNonEmpty(state.State, state.Status)),
		"coverage_status":   strings.TrimSpace(state.Status),
		"evidence_surface":  strings.TrimSpace(state.EvidenceSurface),
		"anchor_urn":        strings.TrimSpace(anchorURN),
		"source_value":      strings.TrimSpace(sourceValue),
		"source_taxonomy":   "mitre_attack",
		"knowledge_pack_id": KnowledgePackID,
	}
	for key, value := range extra {
		if strings.TrimSpace(key) != "" {
			attrs[key] = strings.TrimSpace(value)
		}
	}
	return compact(attrs)
}

func NormalizeCoverageState(values ...string) string {
	for _, value := range values {
		normalized := normalizeKey(value)
		switch normalized {
		case "healthy", "complete", "covered", "implemented", "enabled", "proven":
			return "covered"
		case "observed", "detected", "runtime-observed", "finding-observed":
			return "observed"
		case "configured", "mapped", "supported":
			return "mapped"
		case "partial", "partially-covered":
			return "partial"
		case "gap", "missing", "uncovered", "unsupported", "unconfigured", "failed", "stale":
			return "gap"
		}
	}
	return "mapped"
}

func AttackTacticsForTechnique(technique AttackTechnique) []AttackTactic {
	knowledge, ok := AttackTechniqueKnowledgeFor(technique)
	if !ok {
		return nil
	}
	tactics := make([]AttackTactic, 0, len(knowledge.TacticIDs))
	for _, id := range knowledge.TacticIDs {
		if tactic, ok := attackTacticByID[strings.ToUpper(strings.TrimSpace(id))]; ok {
			tactics = append(tactics, tactic)
		}
	}
	return tactics
}

func cloneAttackTechniqueKnowledge(knowledge AttackTechniqueKnowledge) AttackTechniqueKnowledge {
	knowledge.TacticIDs = append([]string(nil), knowledge.TacticIDs...)
	knowledge.DataComponents = append([]AttackDataComponent(nil), knowledge.DataComponents...)
	knowledge.DefendTechniques = append([]DefendTechnique(nil), knowledge.DefendTechniques...)
	knowledge.DefendArtifacts = append([]DefendArtifact(nil), knowledge.DefendArtifacts...)
	knowledge.References = append([]string(nil), knowledge.References...)
	return knowledge
}

func normalizedAttackTechniqueID(value string) string {
	value = strings.ToUpper(strings.TrimSpace(value))
	if value == "" {
		return ""
	}
	if attackTechniquePattern.MatchString(value) {
		return attackTechniquePattern.FindString(value)
	}
	return ""
}

var attackTechniqueKnowledgeByID = map[string]AttackTechniqueKnowledge{
	"T1059": {
		ID:        "T1059",
		Name:      "Command and Scripting Interpreter",
		TacticIDs: []string{"TA0002"},
		DataComponents: []AttackDataComponent{
			{ID: "DS0017:Command Execution", Name: "Command Execution", DataSourceID: "DS0017", Description: "Command line and shell execution evidence."},
			{ID: "DS0009:Process Creation", Name: "Process Creation", DataSourceID: "DS0009", Description: "Process start evidence and command-line metadata."},
		},
		DefendTechniques: []DefendTechnique{{ID: "ProcessTermination", Name: "Process Termination"}},
		DefendArtifacts:  []DefendArtifact{{ID: "Process", Name: "Process"}},
		References:       []string{"https://attack.mitre.org/techniques/T1059/"},
	},
	"T1078": {
		ID:        "T1078",
		Name:      "Valid Accounts",
		TacticIDs: []string{"TA0001", "TA0003", "TA0004", "TA0005"},
		DataComponents: []AttackDataComponent{
			{ID: "DS0028:Logon Session Creation", Name: "Logon Session Creation", DataSourceID: "DS0028", Description: "Successful authentication and session creation evidence."},
			{ID: "DS0002:User Account Authentication", Name: "User Account Authentication", DataSourceID: "DS0002", Description: "Authentication attempts and account use evidence."},
		},
		DefendTechniques: []DefendTechnique{{ID: "Multi-factorAuthentication", Name: "Multi-factor Authentication"}, {ID: "CredentialTransmissionScoping", Name: "Credential Transmission Scoping"}, {ID: "LocalAccountMonitoring", Name: "Local Account Monitoring"}},
		DefendArtifacts:  []DefendArtifact{{ID: "UserAccount", Name: "User Account"}, {ID: "Credential", Name: "Credential"}},
		References:       []string{"https://attack.mitre.org/techniques/T1078/"},
	},
	"T1087": {
		ID:        "T1087",
		Name:      "Account Discovery",
		TacticIDs: []string{"TA0007"},
		DataComponents: []AttackDataComponent{
			{ID: "DS0017:Command Execution", Name: "Command Execution", DataSourceID: "DS0017", Description: "Directory and account enumeration command evidence."},
			{ID: "DS0002:User Account Metadata", Name: "User Account Metadata", DataSourceID: "DS0002", Description: "Account inventory and attribute evidence."},
		},
		DefendTechniques: []DefendTechnique{{ID: "LocalAccountMonitoring", Name: "Local Account Monitoring"}},
		DefendArtifacts:  []DefendArtifact{{ID: "UserAccount", Name: "User Account"}},
		References:       []string{"https://attack.mitre.org/techniques/T1087/"},
	},
	"T1098": {
		ID:        "T1098",
		Name:      "Account Manipulation",
		TacticIDs: []string{"TA0003", "TA0004"},
		DataComponents: []AttackDataComponent{
			{ID: "DS0002:User Account Modification", Name: "User Account Modification", DataSourceID: "DS0002", Description: "Account, group, credential, or permission change evidence."},
			{ID: "DS0028:Logon Session Creation", Name: "Logon Session Creation", DataSourceID: "DS0028", Description: "Session evidence following account changes."},
		},
		DefendTechniques: []DefendTechnique{{ID: "Multi-factorAuthentication", Name: "Multi-factor Authentication"}, {ID: "LocalAccountMonitoring", Name: "Local Account Monitoring"}},
		DefendArtifacts:  []DefendArtifact{{ID: "UserAccount", Name: "User Account"}, {ID: "Credential", Name: "Credential"}},
		References:       []string{"https://attack.mitre.org/techniques/T1098/"},
	},
	"T1190": {
		ID:        "T1190",
		Name:      "Exploit Public-Facing Application",
		TacticIDs: []string{"TA0001"},
		DataComponents: []AttackDataComponent{
			{ID: "DS0015:Application Log Content", Name: "Application Log Content", DataSourceID: "DS0015", Description: "Application request, error, and exploit-attempt evidence."},
			{ID: "DS0029:Network Traffic Content", Name: "Network Traffic Content", DataSourceID: "DS0029", Description: "Inbound request and payload evidence for public services."},
		},
		DefendTechniques: []DefendTechnique{{ID: "InboundTrafficFiltering", Name: "Inbound Traffic Filtering"}, {ID: "ApplicationConfigurationHardening", Name: "Application Configuration Hardening"}, {ID: "SoftwareUpdate", Name: "Software Update"}},
		DefendArtifacts:  []DefendArtifact{{ID: "WebServer", Name: "Web Server"}, {ID: "NetworkTraffic", Name: "Network Traffic"}, {ID: "Software", Name: "Software"}},
		References:       []string{"https://attack.mitre.org/techniques/T1190/"},
	},
	"T1486": {
		ID:        "T1486",
		Name:      "Data Encrypted for Impact",
		TacticIDs: []string{"TA0040"},
		DataComponents: []AttackDataComponent{
			{ID: "DS0022:File Modification", Name: "File Modification", DataSourceID: "DS0022", Description: "File changes consistent with encryption or destructive modification."},
			{ID: "DS0009:Process Creation", Name: "Process Creation", DataSourceID: "DS0009", Description: "Process starts associated with encryption tooling."},
		},
		DefendTechniques: []DefendTechnique{{ID: "FileBackup", Name: "File Backup"}, {ID: "ProcessTermination", Name: "Process Termination"}},
		DefendArtifacts:  []DefendArtifact{{ID: "File", Name: "File"}, {ID: "Process", Name: "Process"}},
		References:       []string{"https://attack.mitre.org/techniques/T1486/"},
	},
	"T1562": {
		ID:        "T1562",
		Name:      "Impair Defenses",
		TacticIDs: []string{"TA0005"},
		DataComponents: []AttackDataComponent{
			{ID: "DS0017:Command Execution", Name: "Command Execution", DataSourceID: "DS0017", Description: "Commands used to weaken or disable controls."},
			{ID: "DS0009:Process Creation", Name: "Process Creation", DataSourceID: "DS0009", Description: "Process starts that alter defensive tooling."},
		},
		DefendTechniques: []DefendTechnique{{ID: "ProcessTermination", Name: "Process Termination"}, {ID: "ApplicationConfigurationHardening", Name: "Application Configuration Hardening"}},
		DefendArtifacts:  []DefendArtifact{{ID: "Process", Name: "Process"}, {ID: "Configuration", Name: "Configuration"}},
		References:       []string{"https://attack.mitre.org/techniques/T1562/"},
	},
}

var attackDataSourcesByID = map[string]AttackDataSource{
	"DS0002": {ID: "DS0002", Name: "User Account", Domain: "enterprise-attack", Description: "Account identity, authentication, and attribute evidence."},
	"DS0009": {ID: "DS0009", Name: "Process", Domain: "enterprise-attack", Description: "Process execution and process metadata evidence."},
	"DS0015": {ID: "DS0015", Name: "Application Log", Domain: "enterprise-attack", Description: "Application event, request, and error evidence."},
	"DS0017": {ID: "DS0017", Name: "Command", Domain: "enterprise-attack", Description: "Command-line and shell execution evidence."},
	"DS0022": {ID: "DS0022", Name: "File", Domain: "enterprise-attack", Description: "File creation, access, and modification evidence."},
	"DS0028": {ID: "DS0028", Name: "Logon Session", Domain: "enterprise-attack", Description: "Authentication session evidence."},
	"DS0029": {ID: "DS0029", Name: "Network Traffic", Domain: "enterprise-attack", Description: "Network flow and payload evidence."},
}

func AttackDataSourceForComponent(component AttackDataComponent) (AttackDataSource, bool) {
	source, ok := attackDataSourcesByID[strings.ToUpper(strings.TrimSpace(component.DataSourceID))]
	return source, ok
}
