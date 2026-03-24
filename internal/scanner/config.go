package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

type ConfigScanner interface {
	ScanConfig(ctx context.Context, targetPath string) (*ConfigScanResult, error)
}

type ConfigScanResult struct {
	Results []ConfigScanTargetResult `json:"results,omitempty"`
}

type ConfigScanTargetResult struct {
	Path     string              `json:"path"`
	Format   string              `json:"format,omitempty"`
	Findings []ConfigScanFinding `json:"findings,omitempty"`
}

type ConfigScanFinding struct {
	ID          string `json:"id"`
	Type        string `json:"type,omitempty"`
	Severity    string `json:"severity,omitempty"`
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	Remediation string `json:"remediation,omitempty"`
	Path        string `json:"path,omitempty"`
	Resource    string `json:"resource,omitempty"`
	Format      string `json:"format,omitempty"`
	StartLine   int    `json:"start_line,omitempty"`
	EndLine     int    `json:"end_line,omitempty"`
}

type TrivyConfigScanner struct {
	binaryPath string
}

func NewTrivyConfigScanner(binaryPath string) *TrivyConfigScanner {
	if strings.TrimSpace(binaryPath) == "" {
		binaryPath = "trivy"
	}
	return &TrivyConfigScanner{binaryPath: binaryPath}
}

func (s *TrivyConfigScanner) ScanConfig(ctx context.Context, targetPath string) (*ConfigScanResult, error) {
	if strings.TrimSpace(s.binaryPath) == "" {
		return nil, fmt.Errorf("trivy binary path is required")
	}
	targetPath = strings.TrimSpace(targetPath)
	if targetPath == "" {
		return nil, fmt.Errorf("config scan path is required")
	}
	if strings.ContainsAny(targetPath, "\r\n") {
		return nil, fmt.Errorf("config scan path must not contain newlines")
	}
	absPath, err := filepath.Abs(targetPath)
	if err != nil {
		return nil, fmt.Errorf("resolve config scan path %s: %w", targetPath, err)
	}

	cmd := exec.CommandContext(ctx, s.binaryPath, "config", "--format", "json", absPath) // #nosec G204 -- fixed binary/arguments, no shell interpolation
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("trivy config scan failed: %w: %s", err, string(output))
	}
	return ParseTrivyConfigOutput(output)
}

func ParseTrivyConfigOutput(data []byte) (*ConfigScanResult, error) {
	var payload struct {
		Results []struct {
			Target            string `json:"Target"`
			Type              string `json:"Type"`
			Misconfigurations []struct {
				ID            string `json:"ID"`
				AVDID         string `json:"AVDID"`
				Type          string `json:"Type"`
				Severity      string `json:"Severity"`
				Title         string `json:"Title"`
				Description   string `json:"Description"`
				Resolution    string `json:"Resolution"`
				CauseMetadata struct {
					Resource  string `json:"Resource"`
					StartLine int    `json:"StartLine"`
					EndLine   int    `json:"EndLine"`
				} `json:"CauseMetadata"`
			} `json:"Misconfigurations"`
		} `json:"Results"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, err
	}

	result := &ConfigScanResult{
		Results: make([]ConfigScanTargetResult, 0, len(payload.Results)),
	}
	for _, item := range payload.Results {
		target := ConfigScanTargetResult{
			Path:   strings.TrimSpace(item.Target),
			Format: strings.TrimSpace(item.Type),
		}
		for _, finding := range item.Misconfigurations {
			target.Findings = append(target.Findings, ConfigScanFinding{
				ID:          firstNonEmpty(strings.TrimSpace(finding.ID), strings.TrimSpace(finding.AVDID)),
				Type:        firstNonEmpty(strings.TrimSpace(finding.Type), "misconfiguration"),
				Severity:    strings.TrimSpace(finding.Severity),
				Title:       strings.TrimSpace(finding.Title),
				Description: strings.TrimSpace(finding.Description),
				Remediation: strings.TrimSpace(finding.Resolution),
				Path:        strings.TrimSpace(item.Target),
				Resource:    strings.TrimSpace(finding.CauseMetadata.Resource),
				Format:      strings.TrimSpace(item.Type),
				StartLine:   finding.CauseMetadata.StartLine,
				EndLine:     finding.CauseMetadata.EndLine,
			})
		}
		result.Results = append(result.Results, target)
	}
	return result, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
