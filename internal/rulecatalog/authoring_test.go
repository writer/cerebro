package rulecatalog

import (
	"strings"
	"testing"
)

const sampleRuleYAML = `apiVersion: cerebro.writer.com/v1alpha1
kind: PolicyFindingRule
metadata:
  id: custom-s3-bucket-public-unencrypted
  name: Public S3 bucket without default encryption
  description: An S3 bucket is publicly readable and has no default encryption.
  tags: [aws, s3, exposure]
spec:
  severity: high
  effect: forbid
  resource: aws::s3::bucket
  match:
    conditionFormat: cel
    conditions:
      - cmp_eq(path(resource, "public_access"), true)
      - cmp_eq(path(resource, "default_encryption_enabled"), false)
  remediation:
    summary: Block public access and enable default SSE-KMS encryption.
    steps:
      - Enable S3 Block Public Access on the bucket.
      - Configure default encryption with a customer managed KMS key.
  frameworks:
    - name: SOC 2
      controls: [CC6.1]
  mitreAttack:
    - tactic: Collection
      technique: T1530
`

const sampleRuleJSON = `{
  "apiVersion": "cerebro.writer.com/v1alpha1",
  "kind": "PolicyFindingRule",
  "metadata": {
    "id": "custom-s3-bucket-public-unencrypted",
    "name": "Public S3 bucket without default encryption",
    "description": "An S3 bucket is publicly readable and has no default encryption.",
    "tags": ["aws", "s3", "exposure"]
  },
  "spec": {
    "severity": "high",
    "effect": "forbid",
    "resource": "aws::s3::bucket",
    "match": {
      "conditionFormat": "cel",
      "conditions": [
        "cmp_eq(path(resource, \"public_access\"), true)",
        "cmp_eq(path(resource, \"default_encryption_enabled\"), false)"
      ]
    },
    "remediation": {
      "summary": "Block public access and enable default SSE-KMS encryption.",
      "steps": [
        "Enable S3 Block Public Access on the bucket.",
        "Configure default encryption with a customer managed KMS key."
      ]
    },
    "frameworks": [{"name": "SOC 2", "controls": ["CC6.1"]}],
    "mitreAttack": [{"tactic": "Collection", "technique": "T1530"}]
  }
}`

func TestValidateYAMLAndJSONProduceSameCanonicalRule(t *testing.T) {
	fromYAML := Validate(FormatYAML, sampleRuleYAML)
	fromJSON := Validate(FormatJSON, sampleRuleJSON)
	for name, result := range map[string]ValidationResult{"yaml": fromYAML, "json": fromJSON} {
		if !result.Valid {
			t.Fatalf("%s validation failed: %+v", name, result.Issues)
		}
	}
	if fromYAML.YAML != fromJSON.YAML || fromYAML.JSON != fromJSON.JSON {
		t.Fatalf("canonical documents differ:\n%s\n---\n%s", fromYAML.YAML, fromJSON.YAML)
	}
	preview := fromYAML.Preview
	if preview == nil || preview.Origin != OriginCustom || preview.Domain != DomainPaaS || preview.Provider != "aws" || preview.Severity != "high" {
		t.Fatalf("unexpected preview: %+v", preview)
	}
	if preview.Remediation != "Block public access and enable default SSE-KMS encryption." || len(preview.RemediationSteps) != 2 {
		t.Fatalf("unexpected remediation: %q %v", preview.Remediation, preview.RemediationSteps)
	}
	if !strings.Contains(preview.AttackDescription, "Collection (T1530)") || !preview.Editable || !preview.Testable {
		t.Fatalf("unexpected preview authoring fields: %+v", preview)
	}
}

func TestValidateRejectsInvalidDocuments(t *testing.T) {
	cases := map[string]struct {
		format  string
		content string
		want    string
	}{
		"unknown yaml field": {FormatYAML, strings.Replace(sampleRuleYAML, "  severity: high", "  severity: high\n  surprise: true", 1), "invalid PolicyFindingRule YAML"},
		"unknown json field": {FormatJSON, strings.Replace(sampleRuleJSON, `"severity": "high",`, `"severity": "high", "surprise": true,`, 1), "invalid PolicyFindingRule JSON"},
		"bad severity":       {FormatYAML, strings.Replace(sampleRuleYAML, "severity: high", "severity: urgent", 1), "spec.severity"},
		"bad condition":      {FormatYAML, strings.Replace(sampleRuleYAML, `cmp_eq(path(resource, "public_access"), true)`, `cmp_eq(path(resource, `, 1), "spec.match.conditions[0]"},
		"builtin id":         {FormatYAML, strings.Replace(sampleRuleYAML, "custom-s3-bucket-public-unencrypted", "aws-user-inactive-admin-no-mfa", 1), "built-in rule"},
		"empty":              {FormatYAML, "  ", "document is empty"},
		"bad format":         {"toml", sampleRuleYAML, "format must be"},
		"too large":          {FormatYAML, strings.Repeat("a", MaxDocumentBytes+1), "exceeds"},
		"write cypher": {FormatYAML, `apiVersion: cerebro.writer.com/v1alpha1
kind: PolicyFindingRule
metadata: {id: custom-graph-write, name: Graph write, description: Attempts a write}
spec:
  severity: low
  graph:
    query: "MATCH (n) DETACH DELETE n RETURN n.urn AS primary_urn LIMIT 1"
`, "read-only"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			result := Validate(tc.format, tc.content)
			if result.Valid {
				t.Fatalf("expected validation failure")
			}
			found := false
			for _, issue := range result.Issues {
				if issue.Severity == "error" && strings.Contains(issue.Message, tc.want) {
					found = true
				}
			}
			if !found {
				t.Fatalf("issues %+v do not mention %q", result.Issues, tc.want)
			}
		})
	}
}

func TestTestEvaluatesSampleResource(t *testing.T) {
	matched := Test(FormatYAML, sampleRuleYAML, map[string]any{"public_access": true, "default_encryption_enabled": false})
	if !matched.Valid || !matched.Evaluated || !matched.Matched {
		t.Fatalf("expected match: %+v", matched)
	}
	passed := Test(FormatJSON, sampleRuleJSON, map[string]any{"public_access": true, "default_encryption_enabled": true})
	if !passed.Valid || !passed.Evaluated || passed.Matched {
		t.Fatalf("expected no match: %+v", passed)
	}
	invalid := Test(FormatYAML, "kind: nope", nil)
	if invalid.Valid || invalid.Evaluated {
		t.Fatalf("expected invalid document to skip evaluation: %+v", invalid)
	}
}

func TestTestExplainsUnsupportedGraphRules(t *testing.T) {
	result := Test(FormatYAML, `apiVersion: cerebro.writer.com/v1alpha1
kind: PolicyFindingRule
metadata: {id: custom-graph-read, name: Graph read, description: Reads the graph}
spec:
  severity: low
  graph:
    query: "MATCH (n:Resource) RETURN n.urn AS primary_urn, n.urn AS fingerprint_key, 'resource' AS summary ORDER BY primary_urn LIMIT 10"
  frameworks:
    - name: SOC 2
      controls: [CC7.1]
`, nil)
	if !result.Valid || result.Evaluated || !strings.Contains(result.Message, "CEL condition rules") {
		t.Fatalf("unexpected graph test result: %+v", result)
	}
}

func TestValidateClassifiesProviderlessGraphRuleAsCorrelation(t *testing.T) {
	result := Validate(FormatYAML, `apiVersion: cerebro.writer.com/v1alpha1
kind: PolicyFindingRule
metadata: {id: custom-graph-correlation, name: Graph correlation, description: Correlates graph facts}
spec:
  severity: high
  graph:
    query: "MATCH (n:Resource) RETURN n.urn AS primary_urn, n.urn AS fingerprint_key, 'resource' AS summary ORDER BY primary_urn LIMIT 10"
  frameworks:
    - name: SOC 2
      controls: [CC7.1]
`)
	if !result.Valid || result.Preview == nil {
		t.Fatalf("expected valid graph rule: %+v", result.Issues)
	}
	if result.Preview.Domain != DomainCorrelation || result.Preview.Posture != PostureCorrelation || result.Preview.Detection != DetectionCorrelation {
		t.Fatalf("graph rule without a provider should be correlation: %+v", result.Preview.Entry)
	}
}
