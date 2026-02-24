package sync

import (
	"context"
	"strings"
	"testing"
)

func TestScopeWhereClauseRegional(t *testing.T) {
	e := &SyncEngine{accountID: "123456789012"}
	where, args := e.scopeWhereClause("us-east-1", true, true, false)

	if where != " WHERE ACCOUNT_ID = ? AND REGION = ?" {
		t.Fatalf("unexpected where clause: %s", where)
	}
	if len(args) != 2 || args[0] != "123456789012" || args[1] != "us-east-1" {
		t.Fatalf("unexpected args: %v", args)
	}
}

func TestScopeWhereClauseGlobal(t *testing.T) {
	e := &SyncEngine{accountID: "123456789012"}
	where, args := e.scopeWhereClause("us-east-1", true, true, true)

	if where != " WHERE ACCOUNT_ID = ?" {
		t.Fatalf("unexpected where clause: %s", where)
	}
	if len(args) != 1 || args[0] != "123456789012" {
		t.Fatalf("unexpected args: %v", args)
	}
}

func TestNormalizeAWSTableSpecSetsGlobalScope(t *testing.T) {
	global := normalizeAWSTableSpec(TableSpec{Name: "aws_iam_users", Columns: []string{"arn"}})
	if global.Scope != TableRegionScopeGlobal {
		t.Fatalf("expected global scope for aws_iam_users")
	}

	regional := normalizeAWSTableSpec(TableSpec{Name: "aws_ec2_instances", Columns: []string{"arn"}})
	if regional.Scope != TableRegionScopeRegional {
		t.Fatalf("expected regional scope for aws_ec2_instances")
	}
}

func TestDeleteScopedRows_RefusesUnscopedDeleteForGlobalTable(t *testing.T) {
	e := &SyncEngine{}
	err := e.deleteScopedRows(context.Background(), "aws_iam_users", "", false, false, true)
	if err == nil {
		t.Fatalf("expected unscoped global delete to be refused")
	}
	if !strings.Contains(err.Error(), "refusing unscoped delete") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDeleteRowsByID_RefusesUnscopedDeleteForGlobalTable(t *testing.T) {
	e := &SyncEngine{}
	err := e.deleteRowsByID(context.Background(), "aws_iam_users", map[string]string{"id-1": "hash"}, "", false, false, true)
	if err == nil {
		t.Fatalf("expected unscoped delete-by-id to be refused")
	}
	if !strings.Contains(err.Error(), "refusing unscoped delete-by-id") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRequiresScopedDelete(t *testing.T) {
	if requiresScopedDelete(false, false, false) {
		t.Fatalf("did not expect scoped delete requirement for unscoped table")
	}
	if !requiresScopedDelete(true, false, false) {
		t.Fatalf("expected regional table to require scoped delete")
	}
	if !requiresScopedDelete(false, true, false) {
		t.Fatalf("expected account-scoped table to require scoped delete")
	}
	if !requiresScopedDelete(false, false, true) {
		t.Fatalf("expected global-scope table to require scoped delete")
	}
}
