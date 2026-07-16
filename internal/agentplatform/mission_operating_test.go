package agentplatform

import "testing"

func TestMissionOperatingContractDefinesOneDurableControlLoop(t *testing.T) {
	contract := SecurityControlPlaneSnapshot().MissionOperating
	if contract.ID != "native-mission-operating-contract" || contract.SchemaVersion != "cerebro.control-kernel.v1" {
		t.Fatalf("mission operating contract = %+v", contract)
	}
	for _, recordID := range []string{"mandate", "mission", "belief", "plan_revision", "commitment", "wake_condition"} {
		found := false
		for _, record := range contract.DurableRecords {
			if record.ID == recordID && len(record.Required) > 0 {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("mission contract missing durable record %q: %+v", recordID, contract.DurableRecords)
		}
	}
	for _, directive := range []string{"request_decision", "execute", "verify", "wait", "blocked", "close"} {
		if !containsString(contract.SupervisorDirectives, directive) {
			t.Fatalf("mission contract missing directive %q: %+v", directive, contract.SupervisorDirectives)
		}
	}
	if len(contract.CloseConditions) < 5 || contract.FirstMandate == "" {
		t.Fatalf("mission contract missing closure or first mandate: %+v", contract)
	}
}

func TestMissionOperatingContractSnapshotIsDefensivelyCloned(t *testing.T) {
	first := SecurityControlPlaneSnapshot()
	first.MissionOperating.DurableRecords[0].Required[0] = "mutated"
	first.MissionOperating.ExecutionDepths[0] = "mutated"
	second := SecurityControlPlaneSnapshot()
	if second.MissionOperating.DurableRecords[0].Required[0] == "mutated" || second.MissionOperating.ExecutionDepths[0] == "mutated" {
		t.Fatalf("mission operating snapshot shares mutable slices: %+v", second.MissionOperating)
	}
}
