package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDeriveNames(t *testing.T) {
	n, err := deriveNames("ec2_transit_gateway", "")
	if err != nil {
		t.Fatalf("deriveNames error = %v", err)
	}
	cases := map[string]string{
		"Pascal":      "Ec2TransitGateway",
		"Camel":       "ec2TransitGateway",
		"FamilyConst": "familyEc2TransitGateway",
		"Struct":      "awsEc2TransitGateway",
		"ListFunc":    "listEc2TransitGateway",
		"EventFunc":   "ec2TransitGatewayEvent",
		"Kind":        "aws.ec2_transit_gateway",
		"SchemaRef":   "aws/ec2_transit_gateway/v1",
		"IDPrefix":    "aws-ec2-transit-gateway-",
		"Title":       "AWS ec2 transit gateway",
	}
	got := map[string]string{
		"Pascal": n.Pascal, "Camel": n.Camel, "FamilyConst": n.FamilyConst,
		"Struct": n.Struct, "ListFunc": n.ListFunc, "EventFunc": n.EventFunc,
		"Kind": n.Kind, "SchemaRef": n.SchemaRef, "IDPrefix": n.IDPrefix, "Title": n.Title,
	}
	for field, want := range cases {
		if got[field] != want {
			t.Errorf("%s = %q, want %q", field, got[field], want)
		}
	}
}

func TestDeriveNamesRejectsInvalid(t *testing.T) {
	for _, family := range []string{"", "EC2", "ec2-gateway", "_leading", "trailing_", "double__underscore"} {
		if _, err := deriveNames(family, ""); err == nil {
			t.Errorf("deriveNames(%q) expected error, got nil", family)
		}
	}
}

func TestRenderCollectorIsFormatted(t *testing.T) {
	n, err := deriveNames("ec2_transit_gateway", "")
	if err != nil {
		t.Fatal(err)
	}
	src, err := renderCollector(n)
	if err != nil {
		t.Fatalf("renderCollector error = %v", err)
	}
	for _, want := range []string{
		"func listEc2TransitGateway(",
		"type awsEc2TransitGateway struct",
		"func ec2TransitGatewayEvent(",
		`"aws.ec2_transit_gateway"`,
		`"aws/ec2_transit_gateway/v1"`,
		"commonCloudAssetAttributes(settings, settings.region, familyEc2TransitGateway",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("rendered collector missing %q\n---\n%s", want, src)
		}
	}
}

func TestRenderFixturesGolden(t *testing.T) {
	n, err := deriveNames("ec2_transit_gateway", "")
	if err != nil {
		t.Fatal(err)
	}
	discover, err := renderDiscoverFixture(n)
	if err != nil {
		t.Fatal(err)
	}
	wantDiscover := "[\"urn:cerebro:123456789012:ec2_transit_gateway:example-1\"]\n"
	if discover != wantDiscover {
		t.Errorf("discover fixture = %q, want %q", discover, wantDiscover)
	}
	read, err := renderReadFixture(n)
	if err != nil {
		t.Fatal(err)
	}
	wantRead := `[{"attributes":{"account_id":"123456789012","domain":"123456789012","family":"ec2_transit_gateway","region":"us-east-1","resource_id":"example-1","resource_name":"example","resource_provider":"aws","resource_type":"ec2_transit_gateway"},"id":"aws-ec2-transit-gateway-example-1","kind":"aws.ec2_transit_gateway","occurred_at":"2025-01-01T00:00:00Z","payload":{"account_id":"123456789012","region":"us-east-1","resource_id":"example-1","resource_name":"example"},"schema_ref":"aws/ec2_transit_gateway/v1","source_id":"aws","tenant_id":"123456789012"}]` + "\n"
	if read != wantRead {
		t.Errorf("read fixture = %q, want %q", read, wantRead)
	}
	var events []map[string]any
	if err := json.Unmarshal([]byte(read), &events); err != nil {
		t.Fatalf("read fixture is not valid JSON: %v", err)
	}
}

func TestInsertBeforeSentinel(t *testing.T) {
	content := "list := []string{\n\t\"a\",\n\t// sentinel\n}\n"
	got, err := insertBeforeSentinel(content, "// sentinel", "\t\"b\",")
	if err != nil {
		t.Fatalf("insertBeforeSentinel error = %v", err)
	}
	want := "list := []string{\n\t\"a\",\n\t\"b\",\n\t// sentinel\n}\n"
	if got != want {
		t.Errorf("insertBeforeSentinel = %q, want %q", got, want)
	}
	if _, err := insertBeforeSentinel(content, "// missing", "x"); err == nil {
		t.Error("expected error for missing sentinel")
	}
	dup := "// s\n// s\n"
	if _, err := insertBeforeSentinel(dup, "// s", "x"); err == nil {
		t.Error("expected error for duplicate sentinel")
	}
}

func TestRenderRegisterSnippet(t *testing.T) {
	n, err := deriveNames("ec2_transit_gateway", "")
	if err != nil {
		t.Fatal(err)
	}
	snippet, err := renderTemplate(registerTemplate, n)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"awsFamily(s.clients, awsFamilyOptions[awsEc2TransitGateway]{",
		"Name:  familyEc2TransitGateway,",
		"List:  listEc2TransitGateway,",
		"Event: ec2TransitGatewayEvent,",
		`urn:cerebro:%s:ec2_transit_gateway:%s`,
	} {
		if !strings.Contains(snippet, want) {
			t.Errorf("register snippet missing %q\n---\n%s", want, snippet)
		}
	}
}
