package scanner

import (
	"strings"
	"testing"
)

func TestParseTrivyConfigOutputMapsPathsAndLineNumbers(t *testing.T) {
	result, err := ParseTrivyConfigOutput([]byte(`{
  "Results": [
    {
      "Target": "infra/main.tf",
      "Class": "config",
      "Type": "terraform",
      "Misconfigurations": [
        {
          "ID": "AVD-AWS-0001",
          "AVDID": "AVD-AWS-0001",
          "Title": "Security group allows public ingress",
          "Description": "Ingress allows 0.0.0.0/0",
          "Resolution": "Scope ingress to trusted CIDRs",
          "Severity": "HIGH",
          "CauseMetadata": {
            "Resource": "aws_security_group.public",
            "StartLine": 3,
            "EndLine": 7
          }
        }
      ]
    },
    {
      "Target": "README.md",
      "Class": "config",
      "Type": "terraform",
      "Misconfigurations": [
        {
          "ID": "AVD-IGNORE-0001",
          "Title": "Ignored non-IaC finding",
          "Severity": "LOW"
        }
      ]
    }
  ]
}`))
	if err != nil {
		t.Fatalf("parse trivy config output: %v", err)
	}
	if len(result.Results) != 2 {
		t.Fatalf("expected 2 results, got %#v", result.Results)
	}

	finding := result.Results[0].Findings[0]
	if finding.ID != "AVD-AWS-0001" {
		t.Fatalf("expected finding id %q, got %#v", "AVD-AWS-0001", finding)
	}
	if finding.Path != "infra/main.tf" {
		t.Fatalf("expected path %q, got %#v", "infra/main.tf", finding)
	}
	if finding.StartLine != 3 || finding.EndLine != 7 {
		t.Fatalf("expected lines 3-7, got %#v", finding)
	}
	if finding.Resource != "aws_security_group.public" {
		t.Fatalf("expected resource address, got %#v", finding)
	}
	if got := strings.ToLower(finding.Format); got != "terraform" {
		t.Fatalf("expected terraform format, got %#v", finding)
	}
}
