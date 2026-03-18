package filesystemanalyzer

import (
	"encoding/json"
	"encoding/xml"
	"io/fs"
	"path"
	"regexp"
	"strings"
)

var dotnetTargetFrameworkPattern = regexp.MustCompile(`(?i)^net(?:coreapp)?([0-9]+(?:\.[0-9]+)?)`)

func shouldInspectTechnologyFile(filePath string, mode fs.FileMode, size int64, maxBytes int64) bool {
	if mode&fs.ModeSymlink != 0 || mode.IsDir() {
		return false
	}
	if size <= 0 || size > maxBytes {
		return false
	}
	lowerPath := strings.ToLower(strings.TrimSpace(filePath))
	if lowerPath == "" {
		return false
	}
	for _, segment := range []string{"/node_modules/", "/vendor/", "/testdata/", "/fixtures/", "/examples/"} {
		if strings.Contains(lowerPath, segment) {
			return false
		}
	}
	base := path.Base(lowerPath)
	switch base {
	case "package.json", "go.mod", "nginx.conf", "redis.conf", "pg_version", "pom.xml", "build.gradle",
		"build.gradle.kts", "requirements.txt", "pyproject.toml", "pipfile", "gemfile", "composer.json",
		"apache2.conf", "httpd.conf", "caddyfile", "mysql.cnf", "my.cnf", "mongod.conf", "rabbitmq.conf",
		"nats.conf", "nats-server.conf", "prometheus.yml", "prometheus.yaml", "grafana-agent.yaml",
		"grafana-agent.yml":
		return true
	}
	switch {
	case strings.HasSuffix(lowerPath, ".csproj"),
		strings.HasSuffix(lowerPath, ".fsproj"),
		strings.HasSuffix(lowerPath, ".vbproj"):
		return true
	case strings.Contains(lowerPath, "/kafka/") && base == "server.properties":
		return true
	case strings.Contains(lowerPath, "/datadog/") && base == "datadog.yaml":
		return true
	case strings.Contains(lowerPath, "/newrelic/") && (base == "newrelic-infra.yml" || base == "newrelic.yml"):
		return true
	default:
		return false
	}
}

func detectTechnologies(filePath string, data []byte) []TechnologyRecord {
	lowerPath := strings.ToLower(strings.TrimSpace(filePath))
	base := path.Base(lowerPath)
	switch {
	case base == "package.json":
		return detectNodeJSTechnology(filePath, data)
	case base == "go.mod":
		if tech := detectGoTechnology(filePath, data); tech != nil {
			return []TechnologyRecord{*tech}
		}
	case base == "nginx.conf":
		return []TechnologyRecord{{Name: "nginx", Category: "web_server", Path: filePath}}
	case base == "redis.conf":
		return []TechnologyRecord{{Name: "redis", Category: "cache", Path: filePath}}
	case base == "pg_version":
		if tech := detectPostgreSQLTechnology(filePath, data); tech != nil {
			return []TechnologyRecord{*tech}
		}
	case strings.HasSuffix(lowerPath, ".csproj"), strings.HasSuffix(lowerPath, ".fsproj"), strings.HasSuffix(lowerPath, ".vbproj"):
		if tech := detectDotNetTechnology(filePath, data); tech != nil {
			return []TechnologyRecord{*tech}
		}
	case base == "pom.xml":
		return []TechnologyRecord{{Name: "java", Category: "runtime", Path: filePath}}
	case base == "build.gradle", base == "build.gradle.kts":
		return []TechnologyRecord{{Name: "java", Category: "runtime", Path: filePath}}
	case base == "requirements.txt", base == "pyproject.toml", base == "pipfile":
		return []TechnologyRecord{{Name: "python", Category: "runtime", Path: filePath}}
	case base == "gemfile":
		return []TechnologyRecord{{Name: "ruby", Category: "runtime", Path: filePath}}
	case base == "composer.json":
		return []TechnologyRecord{{Name: "php", Category: "runtime", Path: filePath}}
	case base == "apache2.conf", base == "httpd.conf":
		return []TechnologyRecord{{Name: "apache", Category: "web_server", Path: filePath}}
	case base == "caddyfile":
		return []TechnologyRecord{{Name: "caddy", Category: "web_server", Path: filePath}}
	case base == "mysql.cnf", base == "my.cnf":
		return []TechnologyRecord{{Name: "mysql", Category: "database", Path: filePath}}
	case base == "mongod.conf":
		return []TechnologyRecord{{Name: "mongodb", Category: "database", Path: filePath}}
	case base == "rabbitmq.conf":
		return []TechnologyRecord{{Name: "rabbitmq", Category: "message_queue", Path: filePath}}
	case strings.Contains(lowerPath, "/kafka/") && base == "server.properties":
		return []TechnologyRecord{{Name: "kafka", Category: "message_queue", Path: filePath}}
	case base == "nats.conf", base == "nats-server.conf":
		return []TechnologyRecord{{Name: "nats", Category: "message_queue", Path: filePath}}
	case base == "prometheus.yml", base == "prometheus.yaml":
		return []TechnologyRecord{{Name: "prometheus", Category: "monitoring", Path: filePath}}
	case base == "grafana-agent.yaml", base == "grafana-agent.yml":
		return []TechnologyRecord{{Name: "grafana_agent", Category: "monitoring", Path: filePath}}
	case strings.Contains(lowerPath, "/datadog/") && base == "datadog.yaml":
		return []TechnologyRecord{{Name: "datadog", Category: "monitoring", Path: filePath}}
	case strings.Contains(lowerPath, "/newrelic/") && (base == "newrelic-infra.yml" || base == "newrelic.yml"):
		return []TechnologyRecord{{Name: "newrelic", Category: "monitoring", Path: filePath}}
	}
	return nil
}

func detectNodeJSTechnology(filePath string, data []byte) []TechnologyRecord {
	var pkg struct {
		Engines map[string]string `json:"engines"`
	}
	tech := TechnologyRecord{
		Name:     "nodejs",
		Category: "runtime",
		Path:     filePath,
	}
	if err := json.Unmarshal(data, &pkg); err == nil && pkg.Engines != nil {
		tech.Version = strings.TrimSpace(pkg.Engines["node"])
	}
	return []TechnologyRecord{tech}
}

func detectGoTechnology(filePath string, data []byte) *TechnologyRecord {
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "go ") {
			continue
		}
		version := strings.TrimSpace(strings.TrimPrefix(line, "go "))
		if version == "" {
			continue
		}
		return &TechnologyRecord{Name: "go", Category: "runtime", Version: version, Path: filePath}
	}
	return &TechnologyRecord{Name: "go", Category: "runtime", Path: filePath}
}

func detectPostgreSQLTechnology(filePath string, data []byte) *TechnologyRecord {
	version := strings.TrimSpace(string(data))
	return &TechnologyRecord{Name: "postgresql", Category: "database", Version: version, Path: filePath}
}

func detectDotNetTechnology(filePath string, data []byte) *TechnologyRecord {
	type propertyGroup struct {
		TargetFramework  string `xml:"TargetFramework"`
		TargetFrameworks string `xml:"TargetFrameworks"`
	}
	type project struct {
		PropertyGroups []propertyGroup `xml:"PropertyGroup"`
	}
	version := ""
	var proj project
	if err := xml.Unmarshal(data, &proj); err == nil {
		for _, group := range proj.PropertyGroups {
			for _, raw := range []string{group.TargetFramework, group.TargetFrameworks} {
				version = normalizeDotNetTargetFramework(raw)
				if version != "" {
					return &TechnologyRecord{Name: "dotnet", Category: "runtime", Version: version, Path: filePath}
				}
			}
		}
	}
	return &TechnologyRecord{Name: "dotnet", Category: "runtime", Path: filePath}
}

func normalizeDotNetTargetFramework(value string) string {
	for _, part := range strings.Split(strings.TrimSpace(value), ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		matches := dotnetTargetFrameworkPattern.FindStringSubmatch(part)
		if len(matches) == 2 {
			return matches[1]
		}
	}
	return ""
}

func normalizeTechnologyRecord(record TechnologyRecord) TechnologyRecord {
	record.Name = strings.TrimSpace(strings.ToLower(record.Name))
	record.Category = strings.TrimSpace(strings.ToLower(record.Category))
	record.Version = strings.TrimSpace(record.Version)
	record.Path = strings.TrimSpace(record.Path)
	if len(record.Attributes) == 0 {
		record.Attributes = nil
	}
	return record
}

func technologyKey(record TechnologyRecord) string {
	record = normalizeTechnologyRecord(record)
	if record.Name == "" || record.Category == "" {
		return ""
	}
	return strings.Join([]string{record.Category, record.Name, firstNonEmpty(record.Version, "unknown")}, "|")
}
