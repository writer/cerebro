package app

import "testing"

func TestAvailableTablesSnapshotClonesCachedTables(t *testing.T) {
	application := &App{}

	source := []string{"aws_s3_buckets", "aws_iam_roles"}
	application.SetAvailableTables(source)
	source[0] = "mutated"

	snapshot := application.AvailableTablesSnapshot()
	if len(snapshot) != 2 || snapshot[0] != "aws_s3_buckets" || snapshot[1] != "aws_iam_roles" {
		t.Fatalf("unexpected snapshot contents: %#v", snapshot)
	}

	snapshot[1] = "changed"
	fresh := application.AvailableTablesSnapshot()
	if fresh[1] != "aws_iam_roles" {
		t.Fatalf("expected cached tables to remain unchanged, got %#v", fresh)
	}
}
