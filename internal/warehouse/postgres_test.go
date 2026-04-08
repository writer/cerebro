package warehouse

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

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

func TestPreparePostgresDSN(t *testing.T) {
	serviceFilePath := filepath.Join(t.TempDir(), "pg_service.conf")
	if err := os.WriteFile(serviceFilePath, []byte("[warehouse]\nhost=pg.example.com\ndbname=cerebro_jobs\nsslrootcert=system\n"), 0o600); err != nil {
		t.Fatalf("write service file: %v", err)
	}

	tests := []struct {
		name string
		dsn  string
		env  map[string]string
		want map[string]string
	}{
		{
			name: "url adds prefer sslmode",
			dsn:  "postgres://user:pass@localhost:5432/cerebro_app",
			want: map[string]string{
				"database": "cerebro_app",
				"host":     "localhost",
				"password": "pass",
				"port":     "5432",
				"sslmode":  "prefer",
				"user":     "user",
			},
		},
		{
			name: "sslrootcert system forces verify full",
			dsn:  "postgres://user:pass@localhost:5432/cerebro_app?sslmode=disable&sslrootcert=system",
			want: map[string]string{
				"database":    "cerebro_app",
				"host":        "localhost",
				"password":    "pass",
				"port":        "5432",
				"sslmode":     "verify-full",
				"sslrootcert": "system",
				"user":        "user",
			},
		},
		{
			name: "keyword adds prefer sslmode",
			dsn:  "host=localhost port=5432 user=postgres dbname=cerebro_jobs",
			want: map[string]string{
				"database": "cerebro_jobs",
				"host":     "localhost",
				"port":     "5432",
				"sslmode":  "prefer",
				"user":     "postgres",
			},
		},
		{
			name: "connection string servicefile expands and strips service keys",
			dsn: postgresKeywordDSNFromSettings(map[string]string{
				"service":     "warehouse",
				"servicefile": serviceFilePath,
				"user":        "postgres",
			}),
			want: map[string]string{
				"database":    "cerebro_jobs",
				"host":        "pg.example.com",
				"sslmode":     "verify-full",
				"sslrootcert": "system",
				"user":        "postgres",
			},
		},
		{
			name: "environment service expands before sslmode defaulting",
			dsn:  "user=postgres",
			env: map[string]string{
				"PGSERVICE":     "warehouse",
				"PGSERVICEFILE": serviceFilePath,
			},
			want: map[string]string{
				"database":    "cerebro_jobs",
				"host":        "pg.example.com",
				"sslmode":     "verify-full",
				"sslrootcert": "system",
				"user":        "postgres",
			},
		},
		{
			name: "environment sslrootcert system forces verify full",
			dsn:  "user=postgres",
			env: map[string]string{
				"PGSSLROOTCERT": "system",
				"PGSSLMODE":     "disable",
			},
			want: map[string]string{
				"sslmode": "verify-full",
				"user":    "postgres",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for key, value := range tt.env {
				t.Setenv(key, value)
			}

			got, err := PreparePostgresDSN(tt.dsn)
			if err != nil {
				t.Fatalf("PreparePostgresDSN(%q) error = %v", tt.dsn, err)
			}

			gotSettings, err := parsePostgresDSNSettings(got)
			if err != nil {
				t.Fatalf("parsePostgresDSNSettings(%q) error = %v", got, err)
			}

			if !reflect.DeepEqual(gotSettings, tt.want) {
				t.Fatalf("PreparePostgresDSN(%q) settings = %#v, want %#v", tt.dsn, gotSettings, tt.want)
			}
		})
	}
}
