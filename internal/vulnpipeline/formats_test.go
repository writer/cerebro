package vulnpipeline

import (
	"testing"
	"time"
)

func TestBuiltinFormatsDetectAndNormalize(t *testing.T) {
	cases := []struct {
		name     string
		format   string
		payload  string
		wantID   string
		severity string
		class    string
	}{
		{
			name:   "sarif",
			format: FormatSARIF,
			payload: `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"semgrep","rules":[{"id":"sqli","shortDescription":{"text":"SQL injection"},"properties":{"tags":["CWE-89"],"security-severity":"8.1"}}]}},
				"results":[{"ruleId":"sqli","ruleIndex":0,"level":"error","message":{"text":"User input reaches query"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"app/db.go"},"region":{"startLine":10}}}]}]}]}`,
			severity: SeverityHigh,
			class:    ClassCode,
		},
		{
			name:   "trivy",
			format: FormatTrivy,
			payload: `{"SchemaVersion":2,"ArtifactName":"ghcr.io/acme/api:1.0","Metadata":{"RepoDigests":["ghcr.io/acme/api@sha256:` + sha64 + `"]},
				"Results":[{"Target":"ghcr.io/acme/api:1.0 (alpine 3.19)","Class":"os-pkgs","Type":"alpine","Vulnerabilities":[{"VulnerabilityID":"CVE-2024-0727","PkgName":"openssl","InstalledVersion":"3.1.4-r2","FixedVersion":"3.1.4-r5","Severity":"MEDIUM","Status":"fixed"}]}]}`,
			wantID:   "CVE-2024-0727",
			severity: SeverityMedium,
			class:    ClassContainerImage,
		},
		{
			name:   "grype",
			format: FormatGrype,
			payload: `{"descriptor":{"name":"grype"},"source":{"type":"image","target":{"userInput":"acme/api:1.0","manifestDigest":"sha256:` + sha64 + `"}},
				"matches":[{"vulnerability":{"id":"GHSA-jfh8-c2jp-5v3q","severity":"Critical","fix":{"versions":["2.17.1"],"state":"fixed"}},"relatedVulnerabilities":[{"id":"CVE-2021-44228"}],"artifact":{"name":"log4j-core","version":"2.14.1","type":"java-archive","purl":"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}}]}`,
			wantID:   "CVE-2021-44228",
			severity: SeverityCritical,
			class:    ClassContainerImage,
		},
		{
			name:   "cyclonedx",
			format: FormatCycloneDX,
			payload: `{"bomFormat":"CycloneDX","specVersion":"1.5","metadata":{"component":{"name":"acme-web"}},"components":[{"bom-ref":"pkg:npm/lodash@4.17.15","name":"lodash","version":"4.17.15","purl":"pkg:npm/lodash@4.17.15"}],
				"vulnerabilities":[{"id":"CVE-2021-23337","ratings":[{"severity":"high","score":7.2,"method":"CVSSv31"}],"affects":[{"ref":"pkg:npm/lodash@4.17.15"}]}]}`,
			wantID:   "CVE-2021-23337",
			severity: SeverityHigh,
			class:    ClassPackage,
		},
		{
			name:   "osv-scanner",
			format: FormatOSV,
			payload: `{"results":[{"source":{"path":"/src/go.mod","type":"lockfile"},"packages":[{"package":{"name":"golang.org/x/net","version":"0.17.0","ecosystem":"Go"},
				"vulnerabilities":[{"id":"GO-2024-2687","aliases":["CVE-2023-45288"],"summary":"HTTP/2 CONTINUATION flood","database_specific":{"severity":"HIGH"},"affected":[{"package":{"name":"golang.org/x/net"},"ranges":[{"events":[{"introduced":"0"},{"fixed":"0.23.0"}]}]}]}]}]}]}`,
			wantID:   "CVE-2023-45288",
			class:    ClassPackage,
			severity: SeverityHigh,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			document, err := decodeDocument([]byte(tc.payload), "application/json")
			if err != nil {
				t.Fatal(err)
			}
			if got := detectFormat(document); got != tc.format {
				t.Fatalf("detectFormat() = %q, want %q", got, tc.format)
			}
			drafts, err := normalizeBuiltin(tc.format, document)
			if err != nil || len(drafts) != 1 {
				t.Fatalf("normalizeBuiltin() = %d drafts, %v", len(drafts), err)
			}
			observation, problem := finalizeDraft(drafts[0], finalizeContext{TenantID: "t", ProfileID: "p", SourceID: "s", Format: tc.format, IngestedAt: time.Now()})
			if problem != "" {
				t.Fatalf("finalize problem = %q", problem)
			}
			if tc.wantID != "" && observation.PrimaryVulnerabilityID != tc.wantID {
				t.Errorf("primary id = %q, want %q (ids %v)", observation.PrimaryVulnerabilityID, tc.wantID, observation.VulnerabilityIDs)
			}
			if observation.Severity != tc.severity {
				t.Errorf("severity = %q, want %q", observation.Severity, tc.severity)
			}
			if observation.Class != tc.class {
				t.Errorf("class = %q, want %q", observation.Class, tc.class)
			}
		})
	}
}

const sha64 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestNormalizeSeverityScales(t *testing.T) {
	score := 9.1
	cases := []struct {
		raw, scale string
		cvss       *float64
		want       string
	}{
		{"Critical", "", nil, SeverityCritical},
		{"MODERATE", "", nil, SeverityMedium},
		{"informational", "", nil, SeverityInfo},
		{"7.5", SeverityScaleCVSS, nil, SeverityHigh},
		{"4", SeverityScaleZeroFour, nil, SeverityCritical},
		{"1", SeverityScaleOneFive, nil, SeverityInfo},
		{"", "", &score, SeverityCritical},
		{"weird", "", nil, SeverityUnknown},
	}
	for _, tc := range cases {
		if got := NormalizeSeverity(tc.raw, tc.scale, nil, tc.cvss); got != tc.want {
			t.Errorf("NormalizeSeverity(%q, %q) = %q, want %q", tc.raw, tc.scale, got, tc.want)
		}
	}
	if got := NormalizeSeverity("P1", "", map[string]string{"p1": SeverityHigh}, nil); got != SeverityHigh {
		t.Errorf("override severity = %q", got)
	}
}

func TestInferMappingLowConfidenceIsNotReady(t *testing.T) {
	document, _ := decodeDocument([]byte(`[{"a":1,"b":"x"},{"a":2,"b":"y"}]`), "")
	_, report := inferMapping(document)
	if report.ReadyToActivate {
		t.Fatalf("an unrecognizable shape must not be ready to activate: %+v", report)
	}
}
