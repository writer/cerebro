package mitre

import "testing"

func TestAttackTechniqueKnowledgeForKnownTechnique(t *testing.T) {
	knowledge, ok := AttackTechniqueKnowledgeFor(AttackTechnique{ID: "T1190", SourceValue: "Initial Access:T1190"})
	if !ok {
		t.Fatal("AttackTechniqueKnowledgeFor(T1190) ok = false, want true")
	}
	if knowledge.ID != "T1190" {
		t.Fatalf("knowledge.ID = %q, want T1190", knowledge.ID)
	}
	if !stringSliceContains(knowledge.TacticIDs, "TA0001") {
		t.Fatalf("TacticIDs = %#v, want TA0001", knowledge.TacticIDs)
	}
	if !attackDataComponentsContain(knowledge.DataComponents, "DS0015", "Application Log Content") {
		t.Fatalf("DataComponents = %#v, want DS0015 Application Log Content", knowledge.DataComponents)
	}
	if !defendTechniquesContain(knowledge.DefendTechniques, "InboundTrafficFiltering") {
		t.Fatalf("DefendTechniques = %#v, want InboundTrafficFiltering", knowledge.DefendTechniques)
	}
	if !defendArtifactsContain(knowledge.DefendArtifacts, "WebServer") {
		t.Fatalf("DefendArtifacts = %#v, want WebServer", knowledge.DefendArtifacts)
	}
}

func TestAttackTechniqueKnowledgeUsesParentForSubtechnique(t *testing.T) {
	knowledge, ok := AttackTechniqueKnowledgeFor(AttackTechnique{ID: "T1562.001", Name: "Impair Defenses: Disable or Modify Tools"})
	if !ok {
		t.Fatal("AttackTechniqueKnowledgeFor(T1562.001) ok = false, want parent knowledge")
	}
	if knowledge.ID != "T1562.001" {
		t.Fatalf("knowledge.ID = %q, want subtechnique ID", knowledge.ID)
	}
	if !stringSliceContains(knowledge.TacticIDs, "TA0005") {
		t.Fatalf("TacticIDs = %#v, want TA0005 inherited from T1562", knowledge.TacticIDs)
	}
}

func TestAttackTechniqueKnowledgeUnknownTechnique(t *testing.T) {
	if _, ok := AttackTechniqueKnowledgeFor(AttackTechnique{ID: "T9999"}); ok {
		t.Fatal("AttackTechniqueKnowledgeFor(T9999) ok = true, want false")
	}
}

func TestAttackCoverageURNAndAttributes(t *testing.T) {
	anchorURN := "urn:cerebro:writer:security_tool:agent-gateway"
	techniqueURN := "urn:cerebro:writer:mitre_attack_technique:T1190"
	urn := AttackCoverageURN("writer", anchorURN, techniqueURN)
	if urn == "" {
		t.Fatal("AttackCoverageURN() = empty, want stable URN")
	}
	if urn != AttackCoverageURN("writer", anchorURN, techniqueURN) {
		t.Fatal("AttackCoverageURN() changed for same inputs")
	}
	attrs := AttackCoverageAttributes(AttackTechnique{ID: "T1190", Name: "Exploit Public-Facing Application"}, CoverageState{Status: "gap", EvidenceSurface: "endpoint"}, anchorURN, "T1190", map[string]string{"event_id": "evt-1"})
	if attrs["coverage_state"] != "gap" {
		t.Fatalf("coverage_state = %q, want gap", attrs["coverage_state"])
	}
	if attrs["evidence_surface"] != "endpoint" {
		t.Fatalf("evidence_surface = %q, want endpoint", attrs["evidence_surface"])
	}
	if attrs["knowledge_pack_id"] != KnowledgePackID {
		t.Fatalf("knowledge_pack_id = %q, want %q", attrs["knowledge_pack_id"], KnowledgePackID)
	}
}

func attackDataComponentsContain(components []AttackDataComponent, sourceID string, name string) bool {
	for _, component := range components {
		if component.DataSourceID == sourceID && component.Name == name {
			return true
		}
	}
	return false
}

func defendTechniquesContain(techniques []DefendTechnique, id string) bool {
	for _, technique := range techniques {
		if technique.ID == id {
			return true
		}
	}
	return false
}

func defendArtifactsContain(artifacts []DefendArtifact, id string) bool {
	for _, artifact := range artifacts {
		if artifact.ID == id {
			return true
		}
	}
	return false
}

func stringSliceContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
