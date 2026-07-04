package mitre

import "testing"

func TestExtractAttackTechniquesFromTagsAndURLs(t *testing.T) {
	techniques := ExtractAttackTechniqueIDs("github,attack.t1562.001", "https://attack.mitre.org/techniques/T1098/003/")
	if len(techniques) != 2 {
		t.Fatalf("len(techniques) = %d, want 2: %#v", len(techniques), techniques)
	}
	if techniques[0].ID != "T1562.001" {
		t.Fatalf("first technique ID = %q, want T1562.001", techniques[0].ID)
	}
	if techniques[1].ID != "T1098.003" {
		t.Fatalf("second technique ID = %q, want T1098.003", techniques[1].ID)
	}
}

func TestExtractAttackTacticsFromNamesAndTags(t *testing.T) {
	tactics := ExtractAttackTactics("Defense Evasion", "mitre-ta0011", "attack.initial-access", "Collection:T1530")
	if len(tactics) != 4 {
		t.Fatalf("len(tactics) = %d, want 4 unique tactics: %#v", len(tactics), tactics)
	}
	got := map[string]struct{}{}
	for _, tactic := range tactics {
		got[tactic.ID] = struct{}{}
	}
	for _, want := range []string{"TA0005", "TA0011", "TA0001", "TA0009"} {
		if _, ok := got[want]; !ok {
			t.Fatalf("tactics missing %q: %#v", want, tactics)
		}
	}
}

func TestAttackTechniqueURNUsesIDOrSourceLabel(t *testing.T) {
	if got := AttackTechniqueURN("writer", AttackTechnique{ID: "T1190"}); got != "urn:cerebro:writer:mitre_attack_technique:T1190" {
		t.Fatalf("AttackTechniqueURN(ID) = %q", got)
	}
	if got := AttackTechniqueURN("writer", AttackTechnique{Name: "Native API"}); got != "urn:cerebro:writer:mitre_attack_technique_label:native-api" {
		t.Fatalf("AttackTechniqueURN(label) = %q", got)
	}
}

func TestExtractDefendValuesNormalizeURLsAndPrefixes(t *testing.T) {
	techniques := ExtractDefendTechniques("https://d3fend.mitre.org/technique/ProcessScreenshot/", "d3f:ProcessTermination")
	if len(techniques) != 2 {
		t.Fatalf("len(techniques) = %d, want 2: %#v", len(techniques), techniques)
	}
	if techniques[0].ID != "ProcessScreenshot" || techniques[0].Name != "ProcessScreenshot" {
		t.Fatalf("first defend technique = %#v, want normalized URL segment", techniques[0])
	}
	if got := DefendTechniqueLabel(techniques[0]); got != "ProcessScreenshot" {
		t.Fatalf("DefendTechniqueLabel(URL) = %q, want ProcessScreenshot", got)
	}
	if techniques[1].ID != "ProcessTermination" || techniques[1].Name != "ProcessTermination" {
		t.Fatalf("second defend technique = %#v, want normalized prefixed value", techniques[1])
	}
	if got := DefendTechniqueURN("writer", techniques[0]); got != "urn:cerebro:writer:mitre_defend_technique:ProcessScreenshot" {
		t.Fatalf("DefendTechniqueURN(URL) = %q", got)
	}
}
