package sync

import (
	"testing"
	"time"
)

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

func TestIncrementalTablesDeclareDeltaWindows(t *testing.T) {
	e := &SyncEngine{}
	tables := []TableSpec{
		e.securityHubFindingsTable(),
		e.guarddutyFindingsTable(),
		e.inspectorFindingTable(),
	}

	for _, table := range tables {
		if table.IncrementalLookback <= 0 {
			t.Fatalf("expected table %s to declare incremental lookback", table.Name)
		}
	}
}

func TestAWSTableIncrementalLookbackCoverage(t *testing.T) {
	e := &SyncEngine{}
	tables := e.getAWSTables()

	expected := map[string]time.Duration{
		"aws_securityhub_findings":                           securityHubIncrementalLookback,
		"aws_guardduty_findings":                             guardDutyIncrementalLookback,
		"aws_inspector2_findings":                            inspectorIncrementalLookback,
		"aws_identitycenter_permission_set_permission_usage": awsIdentityCenterIncrementalLookback,
	}

	foundIncremental := make(map[string]struct{})
	for _, table := range tables {
		if table.Mode != TableSyncModeIncremental {
			if table.IncrementalLookback > 0 {
				t.Fatalf("non-incremental table %s should not declare incremental lookback", table.Name)
			}
			continue
		}

		want, ok := expected[table.Name]
		if !ok {
			t.Fatalf("incremental table %s missing expected delta-window rule", table.Name)
		}
		if table.IncrementalLookback != want {
			t.Fatalf("unexpected lookback for %s: got %s, want %s", table.Name, table.IncrementalLookback, want)
		}
		foundIncremental[table.Name] = struct{}{}
	}

	for name := range expected {
		if _, ok := foundIncremental[name]; !ok {
			t.Fatalf("expected incremental table %s to be registered", name)
		}
	}
}
