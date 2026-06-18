package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDeriveNames(t *testing.T) {
	n, err := deriveNames("ec2_transit_gateway", "AWS EC2: Transit gateways", "familyEC2TransitGateway", "awsEC2TransitGateway", "listEC2TransitGateways", "ec2TransitGatewayEvent", "aws ec2 transit gateways", "record.ID", "record.Name", "")
	if err != nil {
		t.Fatalf("deriveNames error = %v", err)
	}
	cases := map[string]string{
		"Pascal":      "Ec2TransitGateway",
		"FamilyConst": "familyEC2TransitGateway",
		"RecordType":  "awsEC2TransitGateway",
		"ListFunc":    "listEC2TransitGateways",
		"EventFunc":   "ec2TransitGatewayEvent",
		"Kind":        "aws.ec2_transit_gateway",
		"SchemaRef":   "aws/ec2_transit_gateway/v1",
		"TitleYAML":   `"AWS EC2: Transit gateways"`,
		"CursorExpr":  "record.Name",
		"Projector":   "awsCloudResourceProjections",
	}
	got := map[string]string{
		"Pascal": n.Pascal, "FamilyConst": n.FamilyConst, "RecordType": n.RecordType,
		"ListFunc": n.ListFunc, "EventFunc": n.EventFunc, "Kind": n.Kind,
		"SchemaRef": n.SchemaRef, "TitleYAML": n.TitleYAML, "CursorExpr": n.CursorExpr,
		"Projector": n.Projector,
	}
	for field, want := range cases {
		if got[field] != want {
			t.Errorf("%s = %q, want %q", field, got[field], want)
		}
	}
}

func TestDeriveNamesRejectsInvalid(t *testing.T) {
	for _, tt := range []struct {
		name string
		args []string
	}{
		{name: "family", args: []string{"EC2", "title", "familyEC2", "awsRecord", "listRecords", "recordEvent", "label", "record.ID", "", ""}},
		{name: "record type", args: []string{"ec2_gateway", "title", "familyEC2Gateway", "aws-record", "listRecords", "recordEvent", "label", "record.ID", "", ""}},
		{name: "list func", args: []string{"ec2_gateway", "title", "familyEC2Gateway", "awsRecord", "list-records", "recordEvent", "label", "record.ID", "", ""}},
		{name: "urn expr", args: []string{"ec2_gateway", "title", "familyEC2Gateway", "awsRecord", "listRecords", "recordEvent", "label", "record.ID; panic()", "", ""}},
		{name: "title newline", args: []string{"ec2_gateway", "bad\ntitle", "familyEC2Gateway", "awsRecord", "listRecords", "recordEvent", "label", "record.ID", "", ""}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := deriveNames(tt.args[0], tt.args[1], tt.args[2], tt.args[3], tt.args[4], tt.args[5], tt.args[6], tt.args[7], tt.args[8], tt.args[9]); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestRenderRegisterSnippet(t *testing.T) {
	n := mustNames(t)
	snippet, err := renderTemplate(registerTemplate, n)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"awsFamily(s.clients, awsFamilyOptions[awsDemoWidget]{",
		"Name:  familyDemoWidget,",
		"List:  listDemoWidgets,",
		"Event: demoWidgetEvent,",
		`urn:cerebro:%s:demo_widget:%s`,
		"record.ID",
		"CursorFallback: func(record awsDemoWidget) string { return record.Name }",
	} {
		if !strings.Contains(snippet, want) {
			t.Errorf("register snippet missing %q\n---\n%s", want, snippet)
		}
	}
}

func TestInsertBeforeLineSentinel(t *testing.T) {
	content := "list := []string{\n\t\"a\",\n\t// sentinel\n}\n"
	got, err := insertBeforeLineSentinel(content, "// sentinel", "\t\"b\",")
	if err != nil {
		t.Fatalf("insertBeforeLineSentinel error = %v", err)
	}
	want := "list := []string{\n\t\"a\",\n\t\"b\",\n\t// sentinel\n}\n"
	if got != want {
		t.Errorf("insertBeforeLineSentinel = %q, want %q", got, want)
	}
}

func TestInsertBeforeInlineTarget(t *testing.T) {
	content := "case familyA, familyZ: // sentinel\n"
	got, err := insertBeforeInlineTarget(content, "// sentinel", "familyZ:", "familyB, ")
	if err != nil {
		t.Fatalf("insertBeforeInlineTarget error = %v", err)
	}
	want := "case familyA, familyB, familyZ: // sentinel\n"
	if got != want {
		t.Errorf("insertBeforeInlineTarget = %q, want %q", got, want)
	}
	if _, err := insertBeforeInlineTarget(content, "missing", "familyZ:", "familyB, "); err == nil {
		t.Fatal("expected missing sentinel error")
	}
	if _, err := insertBeforeInlineTarget(content, "// sentinel", "familyY:", "familyB, "); err == nil {
		t.Fatal("expected missing target error")
	}
}

func TestEnsureNotAlreadyWiredDetectsFamilyValue(t *testing.T) {
	root := t.TempDir()
	awsDir := filepath.Join(root, "sources", "aws")
	if err := os.MkdirAll(awsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "internal", "sourceprojection"), 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(path, body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(awsDir, "source.go"), `package aws
const familyEC2Instance = "ec2_instance"
`)
	write(filepath.Join(awsDir, "fixture.go"), "package aws\n")
	write(filepath.Join(awsDir, "catalog.yaml"), "")
	write(filepath.Join(awsDir, "deploy.yaml"), "")
	write(filepath.Join(root, "internal", "sourceprojection", "registry.go"), "package sourceprojection\n")
	n, err := deriveNames("ec2_instance", "", "familyEc2Instance", "awsEC2Instance", "listEC2Instances", "ec2InstanceEvent", "", "record.ID", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := ensureNotAlreadyWired(root, awsDir, n); err == nil || !strings.Contains(err.Error(), "already appears") {
		t.Fatalf("ensureNotAlreadyWired error = %v, want already appears", err)
	}
}

func TestValidateFixtures(t *testing.T) {
	root := t.TempDir()
	testdata := filepath.Join(root, "sources", "aws", "testdata")
	if err := os.MkdirAll(testdata, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(testdata, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("discover_demo_widget.json", `["urn:cerebro:123456789012:demo_widget:demo-1"]`)
	write("read_demo_widget.json", `[{"id":"aws-demo-widget-demo-1","tenant_id":"123456789012","source_id":"aws","kind":"aws.demo_widget","occurred_at":"2025-01-01T00:00:00Z","schema_ref":"aws/demo_widget/v1","payload":{"id":"demo-1"},"attributes":{"resource_id":"demo-1"}}]`)
	if err := validateFixtures(root, mustNames(t)); err != nil {
		t.Fatalf("validateFixtures error = %v", err)
	}
}

func mustNames(t *testing.T) names {
	t.Helper()
	n, err := deriveNames("demo_widget", "AWS Demo: widgets", "familyDemoWidget", "awsDemoWidget", "listDemoWidgets", "demoWidgetEvent", "aws demo widgets", "record.ID", "record.Name", "")
	if err != nil {
		t.Fatal(err)
	}
	return n
}
