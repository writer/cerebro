package api

import "testing"

func TestValidateReadOnlyQuery(t *testing.T) {
	tests := []struct {
		name    string
		query   string
		wantErr bool
	}{
		// Valid queries
		{"simple select", "SELECT * FROM users", false},
		{"select with where", "SELECT id, name FROM users WHERE active = true", false},
		{"select with join", "SELECT u.id, r.name FROM users u JOIN roles r ON u.role_id = r.id", false},
		{"select with limit", "SELECT * FROM assets LIMIT 100", false},
		{"with cte", "WITH recent AS (SELECT * FROM users) SELECT * FROM recent", false},
		{"select with trailing semicolon", "SELECT * FROM users;", false},
		{"lowercase select", "select * from users", false},
		{"mixed case", "Select * From Users", false},

		// Invalid queries - non-SELECT
		{"insert", "INSERT INTO users (name) VALUES ('test')", true},
		{"update", "UPDATE users SET name = 'test'", true},
		{"delete", "DELETE FROM users", true},
		{"drop table", "DROP TABLE users", true},
		{"truncate", "TRUNCATE TABLE users", true},
		{"alter table", "ALTER TABLE users ADD COLUMN test VARCHAR(255)", true},
		{"create table", "CREATE TABLE test (id INT)", true},
		{"grant", "GRANT SELECT ON users TO role", true},
		{"revoke", "REVOKE SELECT ON users FROM role", true},
		{"call procedure", "CALL sp_test()", true},
		{"execute procedure", "EXECUTE sp_test", true},

		// Invalid queries - injection attempts
		{"union with delete", "SELECT * FROM users UNION DELETE FROM users", true},
		{"select with drop", "SELECT * FROM users; DROP TABLE users", true},
		{"comment injection", "SELECT * FROM users -- drop table users", true},
		{"block comment", "SELECT * FROM users /* DROP TABLE users */", true},
		{"multiple statements", "SELECT * FROM users; SELECT * FROM roles", true},

		// Edge cases
		{"empty query", "", true},
		{"whitespace only", "   ", true},
		{"starts with space", "  SELECT * FROM users", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateReadOnlyQuery(tt.query)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateReadOnlyQuery(%q) error = %v, wantErr %v", tt.query, err, tt.wantErr)
			}
		})
	}
}
