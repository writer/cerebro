package providers

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/writerinternal/cerebro/internal/snowflake"
)

type fakeSnowflakeResult struct{}

func (fakeSnowflakeResult) LastInsertId() (int64, error) { return 0, nil }
func (fakeSnowflakeResult) RowsAffected() (int64, error) { return 0, nil }

type fakeSnowflakeClient struct {
	execErr    error
	queryErr   error
	queryReply *snowflake.QueryResult
}

func (f *fakeSnowflakeClient) Exec(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	if f.execErr != nil {
		return nil, f.execErr
	}
	return fakeSnowflakeResult{}, nil
}

func (f *fakeSnowflakeClient) Query(ctx context.Context, query string, args ...interface{}) (*snowflake.QueryResult, error) {
	if f.queryErr != nil {
		return nil, f.queryErr
	}
	if f.queryReply != nil {
		return f.queryReply, nil
	}
	return &snowflake.QueryResult{Rows: []map[string]interface{}{}}, nil
}

func TestEnsureProviderTable_PropagatesColumnError(t *testing.T) {
	client := &fakeSnowflakeClient{queryErr: errors.New("query failed")}

	err := ensureProviderTable(context.Background(), client, "okta_users", []string{"id"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "get existing columns") {
		t.Fatalf("error = %q, want get existing columns", err.Error())
	}
}
