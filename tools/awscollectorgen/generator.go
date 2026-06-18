package main

import (
	"encoding/json"
	"fmt"
	"go/format"
	"regexp"
	"strings"
	"text/template"
)

// familyPattern constrains family identifiers to lower_snake_case so the
// derived Go identifiers, event kinds, and schema refs stay valid.
var familyPattern = regexp.MustCompile(`^[a-z][a-z0-9]*(_[a-z0-9]+)*$`)

// Sentinel markers identify the deterministic insertion points the generator
// edits. Each new family is inserted on the line directly above its sentinel.
const (
	sentinelFamilyConst     = "// awscollectorgen:family-const"
	sentinelFamilyRegister  = "// awscollectorgen:family-register"
	sentinelNormalize       = "// awscollectorgen:normalize-families"
	sentinelFixture         = "// awscollectorgen:fixture-families"
	sentinelProjector       = "// awscollectorgen:projector"
	sentinelEmittedKinds    = "# awscollectorgen:emitted-kinds"
	sentinelRuntimeFamilies = "# awscollectorgen:runtime-families"
	sentinelDimensions      = "# awscollectorgen:coverage-dimensions"
	sentinelDeployRuntimes  = "# awscollectorgen:deploy-runtimes"
)

// names holds every identifier derived from a snake_case family id.
type names struct {
	Family      string
	Pascal      string
	Camel       string
	Dashed      string
	FamilyConst string
	Struct      string
	ListFunc    string
	EventFunc   string
	Kind        string
	SchemaRef   string
	Label       string
	Title       string
	IDPrefix    string
}

func deriveNames(family, title string) (names, error) {
	family = strings.TrimSpace(family)
	if !familyPattern.MatchString(family) {
		return names{}, fmt.Errorf("family %q must be lower_snake_case matching %s", family, familyPattern.String())
	}
	pascal := pascalCase(family)
	title = strings.TrimSpace(title)
	if title == "" {
		title = "AWS " + strings.ReplaceAll(family, "_", " ")
	}
	return names{
		Family:      family,
		Pascal:      pascal,
		Camel:       lowerFirst(pascal),
		Dashed:      strings.ReplaceAll(family, "_", "-"),
		FamilyConst: "family" + pascal,
		Struct:      "aws" + pascal,
		ListFunc:    "list" + pascal,
		EventFunc:   lowerFirst(pascal) + "Event",
		Kind:        "aws." + family,
		SchemaRef:   "aws/" + family + "/v1",
		Label:       "aws " + strings.ReplaceAll(family, "_", " "),
		Title:       title,
		IDPrefix:    "aws-" + strings.ReplaceAll(family, "_", "-") + "-",
	}, nil
}

func pascalCase(family string) string {
	var b strings.Builder
	for _, part := range strings.Split(family, "_") {
		if part == "" {
			continue
		}
		b.WriteString(strings.ToUpper(part[:1]))
		b.WriteString(part[1:])
	}
	return b.String()
}

func lowerFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToLower(s[:1]) + s[1:]
}

var collectorTemplate = template.Must(template.New("collector").Parse(`package aws

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/primitives"
)

// {{.Struct}} is a placeholder record for the {{.Family}} family.
//
// TODO(awscollectorgen): replace these fields with the AWS SDK summary and
// detail types this collector enumerates.
type {{.Struct}} struct {
	ID   string
	Name string
}

// {{.ListFunc}} enumerates {{.Family}} resources for the configured account.
//
// TODO(awscollectorgen): call the appropriate AWS SDK API through clients and
// map each response into a {{.Struct}} value. The generated skeleton returns no
// records so the family is wired end to end without emitting events yet.
func {{.ListFunc}}(_ context.Context, _ awsClients, _ settings, cursor string, _ int) ([]{{.Struct}}, string, error) {
	if strings.TrimSpace(cursor) != "" {
		return nil, "", nil
	}
	return nil, "", nil
}

// {{.EventFunc}} normalizes a single {{.Family}} record into a source event.
func {{.EventFunc}}(settings settings, record {{.Struct}}) (*primitives.Event, error) {
	attributes := commonCloudAssetAttributes(settings, settings.region, {{.FamilyConst}}, record.ID, record.Name, {{printf "%q" .Family}}, map[string]string{})
	payload, err := json.Marshal(map[string]any{
		"account_id":    settings.accountID,
		"region":        settings.region,
		"resource_id":   record.ID,
		"resource_name": record.Name,
	})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, {{printf "%q" .IDPrefix}}+record.ID, {{printf "%q" .Kind}}, {{printf "%q" .SchemaRef}}, payload, attributes, time.Now().UTC())
}
`))

var testTemplate = template.Must(template.New("test").Parse(`package aws

import (
	"context"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
)

func Test{{.Pascal}}Skeleton(t *testing.T) {
	source := newTestSource(t, fakeAWS{})
	config := map[string]string{"account_id": "123456789012", "family": {{.FamilyConst}}}
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(config), nil)
	if err != nil {
		t.Fatalf("Read(%s) error = %v", {{.FamilyConst}}, err)
	}
	// TODO(awscollectorgen): supply fake AWS data and assert emitted events once
	// {{.ListFunc}} is implemented.
	if len(pull.Events) != 0 {
		t.Fatalf("Read(%s) returned %d events, want 0 for the generated skeleton", {{.FamilyConst}}, len(pull.Events))
	}
}
`))

var registerTemplate = template.Must(template.New("register").Parse(`		awsFamily(s.clients, awsFamilyOptions[{{.Struct}}]{
			Name:  {{.FamilyConst}},
			Label: {{printf "%q" .Label}},
			List:  {{.ListFunc}},
			Event: {{.EventFunc}},
			URN: func(settings settings, record {{.Struct}}) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:{{.Family}}:%s", settings.accountID, record.ID), nil
			},
			CursorFallback: func(record {{.Struct}}) string { return record.ID },
		}),`))

var dimensionTemplate = template.Must(template.New("dimension").Parse(`    - id: {{.Family}}
      type: entity_family
      title: {{.Title}}
      families: [{{.Family}}]
      support: supported
      high_value: false`))

var deployTemplate = template.Must(template.New("deploy").Parse(`  - localId: {{.Dashed}}
    config:
      account_id: env:AWS_ACCOUNT_ID
      family: {{.Family}}
      per_page: "100"
      region: env:AWS_REGION
      role_arn: env:AWS_ROLE_ARN`))

func renderTemplate(tmpl *template.Template, n names) (string, error) {
	var b strings.Builder
	if err := tmpl.Execute(&b, n); err != nil {
		return "", err
	}
	return b.String(), nil
}

func renderGoFile(tmpl *template.Template, n names) (string, error) {
	raw, err := renderTemplate(tmpl, n)
	if err != nil {
		return "", err
	}
	formatted, err := format.Source([]byte(raw))
	if err != nil {
		return "", fmt.Errorf("gofmt generated source: %w", err)
	}
	return string(formatted), nil
}

func renderCollector(n names) (string, error) { return renderGoFile(collectorTemplate, n) }
func renderTest(n names) (string, error)      { return renderGoFile(testTemplate, n) }

func renderDiscoverFixture(n names) (string, error) {
	urn := fmt.Sprintf("urn:cerebro:123456789012:%s:example-1", n.Family)
	encoded, err := json.Marshal([]string{urn})
	if err != nil {
		return "", err
	}
	return string(encoded) + "\n", nil
}

func renderReadFixture(n names) (string, error) {
	event := map[string]any{
		"id":          n.IDPrefix + "example-1",
		"tenant_id":   "123456789012",
		"source_id":   "aws",
		"kind":        n.Kind,
		"occurred_at": "2025-01-01T00:00:00Z",
		"schema_ref":  n.SchemaRef,
		"payload": map[string]any{
			"account_id":    "123456789012",
			"region":        "us-east-1",
			"resource_id":   "example-1",
			"resource_name": "example",
		},
		"attributes": map[string]string{
			"account_id":        "123456789012",
			"domain":            "123456789012",
			"family":            n.Family,
			"region":            "us-east-1",
			"resource_id":       "example-1",
			"resource_name":     "example",
			"resource_provider": "aws",
			"resource_type":     n.Family,
		},
	}
	encoded, err := json.Marshal([]any{event})
	if err != nil {
		return "", err
	}
	return string(encoded) + "\n", nil
}

// insertBeforeSentinel inserts snippet on its own line directly above the line
// that contains sentinel. The snippet should already carry its indentation.
func insertBeforeSentinel(content, sentinel, snippet string) (string, error) {
	idx := strings.Index(content, sentinel)
	if idx < 0 {
		return "", fmt.Errorf("sentinel %q not found", sentinel)
	}
	if strings.Count(content, sentinel) > 1 {
		return "", fmt.Errorf("sentinel %q appears more than once", sentinel)
	}
	lineStart := strings.LastIndex(content[:idx], "\n") + 1
	if !strings.HasSuffix(snippet, "\n") {
		snippet += "\n"
	}
	return content[:lineStart] + snippet + content[lineStart:], nil
}
