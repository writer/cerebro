package sync

import "testing"

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
