package warehouse

import "testing"

func TestPostgresDatabaseNameFromDSN(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		dsn  string
		want string
	}{
		{
			name: "url path",
			dsn:  "postgres://user:pass@localhost:5432/cerebro_app?sslmode=disable",
			want: "cerebro_app",
		},
		{
			name: "url query dbname fallback",
			dsn:  "postgres://user:pass@localhost:5432/?dbname=cerebro_jobs&sslmode=disable",
			want: "cerebro_jobs",
		},
		{
			name: "keyword dbname",
			dsn:  "host=localhost port=5432 user=postgres dbname=cerebro_jobs sslmode=disable",
			want: "cerebro_jobs",
		},
		{
			name: "keyword quoted database",
			dsn:  "host=localhost user=postgres database='cerebro app' sslmode=disable",
			want: "cerebro app",
		},
		{
			name: "missing database",
			dsn:  "host=localhost port=5432 user=postgres sslmode=disable",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := postgresDatabaseNameFromDSN(tt.dsn); got != tt.want {
				t.Fatalf("postgresDatabaseNameFromDSN(%q) = %q, want %q", tt.dsn, got, tt.want)
			}
		})
	}
}
