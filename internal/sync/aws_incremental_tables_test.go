package sync

import "testing"

func TestIncrementalTableModes(t *testing.T) {
	e := &SyncEngine{}
	tables := []TableSpec{
		e.securityHubFindingsTable(),
		e.guarddutyFindingsTable(),
		e.inspectorFindingTable(),
	}

	for _, table := range tables {
		if table.Mode != TableSyncModeIncremental {
			t.Fatalf("expected table %s to be incremental", table.Name)
		}
	}
}
