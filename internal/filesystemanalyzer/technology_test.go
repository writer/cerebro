package filesystemanalyzer

import (
	"context"
	"path/filepath"
	"testing"
)

func TestAnalyzerDetectsTechnologyStackFromFilesystemArtifacts(t *testing.T) {
	root := t.TempDir()
	mustWriteFile(t, filepath.Join(root, "srv", "app", "package.json"), `{"name":"web","engines":{"node":"20.11.1"}}`)
	mustWriteFile(t, filepath.Join(root, "srv", "worker", "go.mod"), "module example.com/worker\n\ngo 1.22.3\n")
	mustWriteFile(t, filepath.Join(root, "etc", "nginx", "nginx.conf"), "events {}\nhttp { server { listen 80; } }\n")
	mustWriteFile(t, filepath.Join(root, "var", "lib", "postgresql", "data", "PG_VERSION"), "16\n")
	mustWriteFile(t, filepath.Join(root, "etc", "redis", "redis.conf"), "port 6379\n")
	mustWriteFile(t, filepath.Join(root, "src", "App.csproj"), "<Project><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>")

	report, err := New(Options{}).Analyze(context.Background(), root)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if report.Summary.TechnologyCount != 6 {
		t.Fatalf("expected 6 detected technologies, got %#v", report.Technologies)
	}

	techs := make(map[string]TechnologyRecord, len(report.Technologies))
	for _, tech := range report.Technologies {
		techs[tech.Category+"|"+tech.Name] = tech
	}

	if got, ok := techs["runtime|nodejs"]; !ok || got.Version != "20.11.1" || got.Path != "srv/app/package.json" {
		t.Fatalf("expected nodejs runtime detection, got %#v", got)
	}
	if got, ok := techs["runtime|go"]; !ok || got.Version != "1.22.3" || got.Path != "srv/worker/go.mod" {
		t.Fatalf("expected go runtime detection, got %#v", got)
	}
	if got, ok := techs["web_server|nginx"]; !ok || got.Path != "etc/nginx/nginx.conf" {
		t.Fatalf("expected nginx detection, got %#v", got)
	}
	if got, ok := techs["database|postgresql"]; !ok || got.Version != "16" || got.Path != "var/lib/postgresql/data/PG_VERSION" {
		t.Fatalf("expected postgresql detection, got %#v", got)
	}
	if got, ok := techs["cache|redis"]; !ok || got.Path != "etc/redis/redis.conf" {
		t.Fatalf("expected redis detection, got %#v", got)
	}
	if got, ok := techs["runtime|dotnet"]; !ok || got.Version != "8.0" || got.Path != "src/App.csproj" {
		t.Fatalf("expected dotnet detection, got %#v", got)
	}
}

func TestAnalyzerDetectsExtendedTechnologySignals(t *testing.T) {
	root := t.TempDir()
	mustWriteFile(t, filepath.Join(root, "srv", "java", "pom.xml"), "<project></project>")
	mustWriteFile(t, filepath.Join(root, "srv", "python", "requirements.txt"), "flask==3.0.0\n")
	mustWriteFile(t, filepath.Join(root, "etc", "caddy", "Caddyfile"), ":80 {\n respond \"ok\"\n}\n")
	mustWriteFile(t, filepath.Join(root, "etc", "rabbitmq", "rabbitmq.conf"), "listeners.tcp.default = 5672\n")
	mustWriteFile(t, filepath.Join(root, "etc", "kafka", "server.properties"), "broker.id=1\n")
	mustWriteFile(t, filepath.Join(root, "etc", "nats", "nats-server.conf"), "port: 4222\n")
	mustWriteFile(t, filepath.Join(root, "etc", "prometheus", "prometheus.yml"), "global:\n  scrape_interval: 15s\n")
	mustWriteFile(t, filepath.Join(root, "etc", "mysql", "my.cnf"), "[mysqld]\nport=3306\n")
	mustWriteFile(t, filepath.Join(root, "etc", "mongodb", "mongod.conf"), "storage:\n  dbPath: /var/lib/mongo\n")
	mustWriteFile(t, filepath.Join(root, "etc", "grafana", "grafana-agent.yaml"), "server:\n  log_level: info\n")

	report, err := New(Options{}).Analyze(context.Background(), root)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	techs := make(map[string]TechnologyRecord, len(report.Technologies))
	for _, tech := range report.Technologies {
		techs[tech.Category+"|"+tech.Name] = tech
	}

	for key, expectedPath := range map[string]string{
		"runtime|java":             "srv/java/pom.xml",
		"runtime|python":           "srv/python/requirements.txt",
		"web_server|caddy":         "etc/caddy/Caddyfile",
		"message_queue|rabbitmq":   "etc/rabbitmq/rabbitmq.conf",
		"message_queue|kafka":      "etc/kafka/server.properties",
		"message_queue|nats":       "etc/nats/nats-server.conf",
		"monitoring|prometheus":    "etc/prometheus/prometheus.yml",
		"database|mysql":           "etc/mysql/my.cnf",
		"database|mongodb":         "etc/mongodb/mongod.conf",
		"monitoring|grafana_agent": "etc/grafana/grafana-agent.yaml",
	} {
		got, ok := techs[key]
		if !ok || got.Path != expectedPath {
			t.Fatalf("expected %s detection at %s, got %#v", key, expectedPath, got)
		}
	}
}
