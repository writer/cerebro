package snowflake

import (
	"errors"
	"testing"
)

func TestValidateReadOnlyQuery(t *testing.T) {
	tests := []struct {
		name    string
		query   string
		wantErr error
	}{
		{name: "valid select", query: "SELECT * FROM users", wantErr: nil},
		{name: "valid with cte", query: "WITH recent AS (SELECT * FROM events) SELECT * FROM recent", wantErr: nil},
		{name: "valid trailing semicolon", query: "SELECT * FROM users;", wantErr: nil},
		{name: "empty query", query: "", wantErr: ErrEmptyQuery},
		{name: "non read only query", query: "UPDATE users SET admin=true", wantErr: ErrNonSelectQuery},
		{name: "inline comment rejected", query: "SELECT * FROM users -- test", wantErr: ErrSQLInjection},
		{name: "block comment rejected", query: "SELECT /* test */ * FROM users", wantErr: ErrSQLInjection},
		{name: "statement chaining rejected", query: "SELECT * FROM users; DROP TABLE users;", wantErr: ErrSQLInjection},
		{name: "forbidden keyword rejected", query: "WITH x AS (SELECT * FROM users) DELETE FROM users", wantErr: ErrSQLInjection},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateReadOnlyQuery(tt.query)
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				return
			}

			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("expected error %v, got %v", tt.wantErr, err)
			}
		})
	}
}
