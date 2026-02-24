package compliance

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// AuditManifest describes metadata for an exported compliance artifact.
type AuditManifest struct {
	FrameworkID   string `json:"framework_id"`
	FrameworkName string `json:"framework_name"`
	Version       string `json:"version"`
	GeneratedAt   string `json:"generated_at"`
	GeneratedBy   string `json:"generated_by"`
}

// AuditControlEvidence describes control-level evidence included in an export.
type AuditControlEvidence struct {
	ControlID    string   `json:"control_id"`
	Title        string   `json:"title"`
	Description  string   `json:"description"`
	Status       string   `json:"status"`
	Policies     []string `json:"policies"`
	Findings     []string `json:"findings"`
	FindingCount int      `json:"finding_count"`
}

// AuditSummary contains aggregate control pass/fail information.
type AuditSummary struct {
	TotalControls   int `json:"total_controls"`
	PassingControls int `json:"passing_controls"`
	FailingControls int `json:"failing_controls"`
}

// AuditPackage is the exported compliance package payload.
type AuditPackage struct {
	Manifest AuditManifest          `json:"manifest"`
	Summary  AuditSummary           `json:"summary"`
	Controls []AuditControlEvidence `json:"controls"`
}

// BuildAuditPackage builds control evidence for a framework using finding counts by policy ID.
func BuildAuditPackage(framework *Framework, findingsByPolicy map[string]int, generatedAt time.Time) AuditPackage {
	if findingsByPolicy == nil {
		findingsByPolicy = map[string]int{}
	}

	pkg := AuditPackage{
		Manifest: AuditManifest{
			FrameworkID:   framework.ID,
			FrameworkName: framework.Name,
			Version:       framework.Version,
			GeneratedAt:   generatedAt.UTC().Format(time.RFC3339),
			GeneratedBy:   "cerebro",
		},
		Controls: make([]AuditControlEvidence, 0, len(framework.Controls)),
	}

	for _, ctrl := range framework.Controls {
		evidence := AuditControlEvidence{
			ControlID:   ctrl.ID,
			Title:       ctrl.Title,
			Description: ctrl.Description,
			Status:      "passing",
			Policies:    append([]string(nil), ctrl.PolicyIDs...),
			Findings:    make([]string, 0, len(ctrl.PolicyIDs)),
		}

		for _, policyID := range ctrl.PolicyIDs {
			if count := findingsByPolicy[policyID]; count > 0 {
				evidence.Status = "failing"
				evidence.Findings = append(evidence.Findings, policyID)
				evidence.FindingCount += count
			}
		}

		pkg.Controls = append(pkg.Controls, evidence)
		if evidence.Status == "failing" {
			pkg.Summary.FailingControls++
		} else {
			pkg.Summary.PassingControls++
		}
	}

	pkg.Summary.TotalControls = len(pkg.Controls)
	return pkg
}

// AuditPackageFilename returns a deterministic export filename.
func AuditPackageFilename(frameworkID string, generatedAt time.Time) string {
	cleanID := strings.TrimSpace(strings.ToLower(frameworkID))
	if cleanID == "" {
		cleanID = "framework"
	}
	cleanID = strings.ReplaceAll(cleanID, " ", "-")
	return fmt.Sprintf("cerebro-audit-%s-%s.zip", cleanID, generatedAt.UTC().Format("20060102T150405Z"))
}

// RenderAuditPackageZIP renders the package payload into a ZIP artifact.
func RenderAuditPackageZIP(pkg AuditPackage) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	if err := writeJSONZipEntry(zw, "manifest.json", pkg.Manifest); err != nil {
		_ = zw.Close()
		return nil, err
	}
	if err := writeJSONZipEntry(zw, "summary.json", pkg.Summary); err != nil {
		_ = zw.Close()
		return nil, err
	}
	if err := writeJSONZipEntry(zw, "controls.json", pkg.Controls); err != nil {
		_ = zw.Close()
		return nil, err
	}

	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("close zip writer: %w", err)
	}

	return buf.Bytes(), nil
}

func writeJSONZipEntry(zw *zip.Writer, name string, value interface{}) error {
	header := &zip.FileHeader{Name: name, Method: zip.Deflate}
	header.Modified = time.Unix(0, 0).UTC()
	header.SetMode(0644)

	w, err := zw.CreateHeader(header)
	if err != nil {
		return fmt.Errorf("create zip entry %s: %w", name, err)
	}

	payload, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal %s: %w", name, err)
	}
	if _, err := w.Write(payload); err != nil {
		return fmt.Errorf("write %s: %w", name, err)
	}
	if _, err := w.Write([]byte("\n")); err != nil {
		return fmt.Errorf("write newline %s: %w", name, err)
	}

	return nil
}
