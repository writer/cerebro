package sync

import (
	"context"
	"testing"
	"time"
)

func TestReservedSSORolePrefix(t *testing.T) {
	prefix := reservedSSORolePrefix("Writer Admin Team")
	want := "AWSReservedSSO_Writer_Admin_Team_"
	if prefix != want {
		t.Fatalf("reservedSSORolePrefix() = %q, want %q", prefix, want)
	}
}

func TestExtractAllowActionsFromPolicyDocument(t *testing.T) {
	doc := `{
		"Version": "2012-10-17",
		"Statement": [
			{"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket"], "Resource": "*"},
			{"Effect": "Deny", "Action": "ec2:*", "Resource": "*"}
		]
	}`

	actions := extractAllowActionsFromPolicyDocument(doc)
	if len(actions) != 2 {
		t.Fatalf("expected 2 allow actions, got %d (%v)", len(actions), actions)
	}
	if actions[0] != "s3:GetObject" || actions[1] != "s3:ListBucket" {
		t.Fatalf("unexpected actions: %v", actions)
	}
}

func TestResolveTrackedActionUsageWildcard(t *testing.T) {
	older := time.Date(2025, 1, 5, 0, 0, 0, 0, time.UTC)
	newer := older.Add(24 * time.Hour)
	tracked := map[string]awsTrackedActionUsage{
		"s3:getobject":  {LastAccessedTime: older},
		"s3:listbucket": {LastAccessedTime: newer},
	}

	exact, exactWildcard := resolveTrackedActionUsage("s3:GetObject", tracked)
	if exactWildcard {
		t.Fatalf("expected exact action match not to be wildcard")
	}
	if !exact.LastAccessedTime.Equal(older) {
		t.Fatalf("exact action last access = %s, want %s", exact.LastAccessedTime, older)
	}

	wildcard, wildcardMatch := resolveTrackedActionUsage("s3:*", tracked)
	if !wildcardMatch {
		t.Fatalf("expected wildcard action match")
	}
	if !wildcard.LastAccessedTime.Equal(newer) {
		t.Fatalf("wildcard last access = %s, want %s", wildcard.LastAccessedTime, newer)
	}
}

func TestResolveTrackedActionUsageServiceNamespaceKeys(t *testing.T) {
	ts := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	tracked := map[string]awsTrackedActionUsage{
		"s3:getobject":          {LastAccessedTime: ts, LastAccessedRegion: "us-east-1"},
		"s3:putobject":          {LastAccessedTime: ts.Add(-48 * time.Hour)},
		"ec2:describeinstances": {LastAccessedTime: ts.Add(-24 * time.Hour)},
		"iam:createrole":        {},
	}

	tests := []struct {
		action       string
		wantTime     time.Time
		wantWildcard bool
		wantNoAccess bool
		wantRegion   string
	}{
		{action: "s3:GetObject", wantTime: ts, wantWildcard: false, wantRegion: "us-east-1"},
		{action: "s3:PutObject", wantTime: ts.Add(-48 * time.Hour), wantWildcard: false},
		{action: "ec2:DescribeInstances", wantTime: ts.Add(-24 * time.Hour), wantWildcard: false},
		{action: "iam:CreateRole", wantNoAccess: true, wantWildcard: false},
		{action: "s3:*", wantTime: ts, wantWildcard: true},
		{action: "ec2:*", wantTime: ts.Add(-24 * time.Hour), wantWildcard: true},
		{action: "iam:*", wantWildcard: true, wantNoAccess: true},
		{action: "*", wantTime: ts, wantWildcard: true},
		{action: "lambda:InvokeFunction", wantNoAccess: true, wantWildcard: false},
	}

	for _, tc := range tests {
		t.Run(tc.action, func(t *testing.T) {
			usage, wildcard := resolveTrackedActionUsage(tc.action, tracked)
			if wildcard != tc.wantWildcard {
				t.Fatalf("wildcard = %v, want %v", wildcard, tc.wantWildcard)
			}
			if tc.wantNoAccess {
				if !usage.LastAccessedTime.IsZero() {
					t.Fatalf("expected zero access time, got %s", usage.LastAccessedTime)
				}
				return
			}
			if !usage.LastAccessedTime.Equal(tc.wantTime) {
				t.Fatalf("last access = %s, want %s", usage.LastAccessedTime, tc.wantTime)
			}
			if tc.wantRegion != "" && usage.LastAccessedRegion != tc.wantRegion {
				t.Fatalf("region = %q, want %q", usage.LastAccessedRegion, tc.wantRegion)
			}
		})
	}
}

func TestResolveTrackedActionUsageGlobalWildcard(t *testing.T) {
	ts1 := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	ts2 := ts1.Add(time.Hour)
	tracked := map[string]awsTrackedActionUsage{
		"s3:getobject":     {LastAccessedTime: ts1},
		"ec2:runinstances": {LastAccessedTime: ts2},
	}

	usage, wildcard := resolveTrackedActionUsage("*", tracked)
	if !wildcard {
		t.Fatalf("expected wildcard match for *")
	}
	if !usage.LastAccessedTime.Equal(ts2) {
		t.Fatalf("global wildcard should return newest access: got %s, want %s", usage.LastAccessedTime, ts2)
	}
}

func TestResolveTrackedActionUsageEmptyTracked(t *testing.T) {
	tracked := map[string]awsTrackedActionUsage{}

	usage, wildcard := resolveTrackedActionUsage("s3:GetObject", tracked)
	if wildcard {
		t.Fatalf("expected no wildcard match on empty tracked map")
	}
	if !usage.LastAccessedTime.IsZero() {
		t.Fatalf("expected zero time on empty tracked map")
	}

	usage, wildcard = resolveTrackedActionUsage("*", tracked)
	if !wildcard {
		t.Fatalf("expected wildcard flag for * even with empty map")
	}
	if !usage.LastAccessedTime.IsZero() {
		t.Fatalf("expected zero time for wildcard on empty tracked map")
	}
}

func TestPermissionUsageWindowStart(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	lookback := 180

	startNoCursor := permissionUsageWindowStart(now, lookback, permissionUsageCursor{})
	wantLookback := now.Add(-time.Duration(lookback) * 24 * time.Hour)
	if !startNoCursor.Equal(wantLookback) {
		t.Fatalf("window start without cursor = %s, want %s", startNoCursor, wantLookback)
	}

	cursor := permissionUsageCursor{Time: now.Add(-24 * time.Hour)}
	startWithCursor := permissionUsageWindowStart(now, lookback, cursor)
	wantCursor := cursor.Time.Add(-permissionUsageCursorOverlap)
	if !startWithCursor.Equal(wantCursor) {
		t.Fatalf("window start with cursor = %s, want %s", startWithCursor, wantCursor)
	}

	oldCursor := permissionUsageCursor{Time: now.Add(-365 * 24 * time.Hour)}
	startWithOldCursor := permissionUsageWindowStart(now, lookback, oldCursor)
	if !startWithOldCursor.Equal(wantLookback) {
		t.Fatalf("window start with old cursor = %s, want %s", startWithOldCursor, wantLookback)
	}
}

func TestCursorAfter(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	current := permissionUsageCursor{Time: t0, ID: "b"}

	earler := permissionUsageCursor{Time: t0.Add(-time.Minute), ID: "z"}
	if got := cursorAfter(current, earler); got != current {
		t.Fatalf("cursorAfter should keep newer current cursor: got %+v, want %+v", got, current)
	}

	sameTimeLowerID := permissionUsageCursor{Time: t0, ID: "a"}
	if got := cursorAfter(current, sameTimeLowerID); got != current {
		t.Fatalf("cursorAfter should keep lexicographically newer id at same timestamp")
	}

	sameTimeHigherID := permissionUsageCursor{Time: t0, ID: "c"}
	if got := cursorAfter(current, sameTimeHigherID); got != sameTimeHigherID {
		t.Fatalf("cursorAfter should prefer higher id at same timestamp: got %+v, want %+v", got, sameTimeHigherID)
	}

	later := permissionUsageCursor{Time: t0.Add(time.Minute), ID: "a"}
	if got := cursorAfter(current, later); got != later {
		t.Fatalf("cursorAfter should prefer later timestamp: got %+v, want %+v", got, later)
	}
}

func TestDeleteStaleIdentityCenterUsageRowsNilSF(t *testing.T) {
	e := &SyncEngine{}
	ctx := context.Background()

	// nil sf: all variants must be no-ops without panic
	e.deleteStaleIdentityCenterUsageRows(ctx, "arn:ps", "arn:role", []string{"s3:GetObject"})
	e.deleteStaleIdentityCenterUsageRows(ctx, "arn:ps", "arn:role", nil)
	e.deleteStaleIdentityCenterUsageRows(ctx, "arn:ps", "arn:role", []string{})

	// empty scope params: must be no-ops
	e.deleteStaleIdentityCenterUsageRows(ctx, "", "arn:role", []string{"s3:GetObject"})
	e.deleteStaleIdentityCenterUsageRows(ctx, "arn:ps", "", []string{"s3:GetObject"})
}

func TestDeleteIdentityCenterUsageRowsByPermissionSetNilSF(t *testing.T) {
	e := &SyncEngine{}
	ctx := context.Background()

	// nil sf: must be no-op without panic
	e.deleteIdentityCenterUsageRowsByPermissionSet(ctx, "arn:ps", "123456789012")

	// empty scope params: must be no-ops
	e.deleteIdentityCenterUsageRowsByPermissionSet(ctx, "", "123456789012")
	e.deleteIdentityCenterUsageRowsByPermissionSet(ctx, "arn:ps", "")
}

func TestPermissionUsageTablesRegistered(t *testing.T) {
	awsTables := (&SyncEngine{}).getAWSTables()
	if !containsAWSTable(awsTables, awsIdentityCenterPermissionUsageTable) {
		t.Fatalf("expected %s to be registered", awsIdentityCenterPermissionUsageTable)
	}

	gcpTables := (&GCPSyncEngine{}).getGCPTables()
	if !containsGCPTable(gcpTables, gcpIAMGroupPermissionUsageTable) {
		t.Fatalf("expected %s to be registered", gcpIAMGroupPermissionUsageTable)
	}
}

func containsAWSTable(tables []TableSpec, tableName string) bool {
	for _, table := range tables {
		if table.Name == tableName {
			return true
		}
	}
	return false
}

func containsGCPTable(tables []GCPTableSpec, tableName string) bool {
	for _, table := range tables {
		if table.Name == tableName {
			return true
		}
	}
	return false
}
