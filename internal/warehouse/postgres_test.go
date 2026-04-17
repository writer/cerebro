package warehouse

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/lib/pq"
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
		{
			name: "multi-host url preserves trailing default port slot",
			dsn:  "postgres://user:pass@pg-a:5433,pg-b/cerebro_app?target_session_attrs=read-write",
			want: map[string]string{
				"database":             "cerebro_app",
				"host":                 "pg-a,pg-b",
				"password":             "pass",
				"port":                 "5433,",
				"sslmode":              "prefer",
				"target_session_attrs": "read-write",
				"user":                 "user",
			},
		},
		{
			name: "multi-host url preserves leading default port slot",
			dsn:  "postgres://user:pass@pg-a,pg-b:6432/cerebro_app",
			want: map[string]string{
				"database": "cerebro_app",
				"host":     "pg-a,pg-b",
				"password": "pass",
				"port":     ",6432",
				"sslmode":  "prefer",
				"user":     "user",
			},
		},
		{
			name: "unix socket url decodes host path",
			dsn:  "postgres://user:pass@%2Ftmp%2Fpostgres/cerebro_app",
			want: map[string]string{
				"database": "cerebro_app",
				"host":     "/tmp/postgres",
				"password": "pass",
				"sslmode":  "prefer",
				"user":     "user",
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
			if gotSettings["service"] == "" {
				delete(gotSettings, "service")
			}

			if !reflect.DeepEqual(gotSettings, tt.want) {
				t.Fatalf("PreparePostgresDSN(%q) settings = %#v, want %#v", tt.dsn, gotSettings, tt.want)
			}
		})
	}
}

func TestPreparePostgresDSNNeutralizesAmbientServiceOverrides(t *testing.T) {
	serviceFilePath := filepath.Join(t.TempDir(), "pg_service.conf")
	if err := os.WriteFile(serviceFilePath, []byte("[warehouse]\nhost=service.example.com\ndbname=service_db\nuser=service-user\n"), 0o600); err != nil {
		t.Fatalf("write service file: %v", err)
	}

	t.Setenv("PGSERVICE", "warehouse")
	t.Setenv("PGSERVICEFILE", serviceFilePath)

	prepared, err := PreparePostgresDSN("host=dsn.example.com dbname=dsn_db user=dsn-user")
	if err != nil {
		t.Fatalf("PreparePostgresDSN() error = %v", err)
	}

	connector, err := pq.NewConnector(prepared)
	if err != nil {
		t.Fatalf("pq.NewConnector() error = %v", err)
	}

	cfg := reflect.ValueOf(connector).Elem().FieldByName("cfg")
	if got := cfg.FieldByName("Service").String(); got != "" {
		t.Fatalf("pq connector service = %q, want empty to neutralize ambient PGSERVICE", got)
	}
	if got := cfg.FieldByName("Host").String(); got != "dsn.example.com" {
		t.Fatalf("pq connector host = %q, want dsn.example.com", got)
	}
	if got := cfg.FieldByName("Database").String(); got != "dsn_db" {
		t.Fatalf("pq connector database = %q, want dsn_db", got)
	}
	if got := cfg.FieldByName("User").String(); got != "dsn-user" {
		t.Fatalf("pq connector user = %q, want dsn-user", got)
	}
}

func TestPreparePostgresDSNUnescapesGeneralKeywordEscapes(t *testing.T) {
	got, err := PreparePostgresDSN(`user=space\ man sslrootcert=/tmp/with\ space/root.crt`)
	if err != nil {
		t.Fatalf("PreparePostgresDSN() error = %v", err)
	}

	settings, err := parsePostgresDSNSettings(got)
	if err != nil {
		t.Fatalf("parsePostgresDSNSettings(%q) error = %v", got, err)
	}
	if settings["user"] != "space man" {
		t.Fatalf("user = %q, want %q", settings["user"], "space man")
	}
	if settings["sslrootcert"] != "/tmp/with space/root.crt" {
		t.Fatalf("sslrootcert = %q, want %q", settings["sslrootcert"], "/tmp/with space/root.crt")
	}
}
