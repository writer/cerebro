package remediation

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"
)

type DeliveryMode string

const (
	DeliveryModeRemoteApply DeliveryMode = "remote_apply"
	DeliveryModeTerraform   DeliveryMode = "terraform"
)

type TerraformArtifact struct {
	Kind            string   `json:"kind"`
	IaCType         string   `json:"iac_type"`
	Format          string   `json:"format"`
	Path            string   `json:"path"`
	ResourceType    string   `json:"resource_type"`
	ResourceAddress string   `json:"resource_address"`
	ImportID        string   `json:"import_id,omitempty"`
	Summary         string   `json:"summary"`
	Content         string   `json:"content"`
	Notes           []string `json:"notes,omitempty"`
	IaCFile         string   `json:"iac_file,omitempty"`
	IaCModule       string   `json:"iac_module,omitempty"`
	IaCStateID      string   `json:"iac_state_id,omitempty"`
}

var terraformIdentifierUnsafeChars = regexp.MustCompile(`[^0-9A-Za-z_]+`)

func actionDeliveryMode(action Action, entry CatalogEntry) DeliveryMode {
	raw := strings.ToLower(strings.TrimSpace(action.Config["delivery_mode"]))
	switch DeliveryMode(raw) {
	case DeliveryModeRemoteApply, DeliveryModeTerraform:
		return DeliveryMode(raw)
	}
	if entry.DefaultDeliveryMode != "" {
		return entry.DefaultDeliveryMode
	}
	return DeliveryModeRemoteApply
}

func catalogSupportsDeliveryMode(entry CatalogEntry, mode DeliveryMode) bool {
	if mode == "" {
		return false
	}
	if len(entry.SupportedDeliveryModes) == 0 {
		return mode == DeliveryModeRemoteApply
	}
	for _, candidate := range entry.SupportedDeliveryModes {
		if candidate == mode {
			return true
		}
	}
	return false
}

func renderTerraformBucketDefaultEncryptionArtifact(execution *Execution, sseAlgorithm, kmsMasterKeyID string, bucketKeyEnabled bool) (TerraformArtifact, error) {
	bucketName := bucketNameFromExecution(execution)
	if bucketName == "" {
		return TerraformArtifact{}, fmt.Errorf("missing bucket identifier for terraform artifact")
	}
	iacFile := ""
	iacModule := ""
	iacStateID := ""
	if execution != nil {
		iacFile = strings.TrimSpace(remediationMapValueToString(execution.TriggerData, "iac_file"))
		iacModule = firstNonEmpty(
			strings.TrimSpace(remediationMapValueToString(execution.TriggerData, "iac_module")),
			terraformModuleAddressFromStateID(strings.TrimSpace(remediationMapValueToString(execution.TriggerData, "iac_state_id"))),
		)
		iacStateID = strings.TrimSpace(remediationMapValueToString(execution.TriggerData, "iac_state_id"))
	}

	resourceName := terraformIdentifier(bucketName + "_default_encryption")
	address := "aws_s3_bucket_server_side_encryption_configuration." + resourceName
	path := terraformArtifactPath(execution, "cerebro_s3_bucket_default_encryption_"+terraformIdentifier(bucketName)+".tf")
	content := renderTerraformTemplate(terraformBucketDefaultEncryptionTemplate, map[string]string{
		"BucketName":        terraformString(bucketName),
		"ResourceName":      resourceName,
		"SSEAlgorithm":      terraformString(firstNonEmpty(strings.TrimSpace(sseAlgorithm), "AES256")),
		"KMSMasterKeyID":    terraformString(strings.TrimSpace(kmsMasterKeyID)),
		"BucketKeyEnabled":  fmt.Sprintf("%t", bucketKeyEnabled),
		"ImportAddress":     address,
		"ImportIdentifier":  terraformString(bucketName),
		"ExistingIaCFile":   iacFile,
		"ExistingIaCModule": iacModule,
	})

	notes := []string{
		"Run terraform plan before apply.",
		fmt.Sprintf("Import the existing encryption configuration before apply: terraform import %s %s", address, bucketName),
	}
	if iacFile != "" {
		notes = append(notes, fmt.Sprintf("Co-locate the generated resource with the existing IaC file %s if that file manages the bucket.", iacFile))
	} else if iacModule != "" {
		notes = append(notes, fmt.Sprintf("Place the generated resource in the Terraform module %s so it stays with the bucket definition.", iacModule))
	}

	return TerraformArtifact{
		Kind:            "terraform_hcl",
		IaCType:         "terraform",
		Format:          "hcl",
		Path:            path,
		ResourceType:    "bucket",
		ResourceAddress: address,
		ImportID:        bucketName,
		Summary:         fmt.Sprintf("Terraform patch for enabling default encryption on S3 bucket %s", bucketName),
		Content:         content,
		Notes:           notes,
		IaCFile:         iacFile,
		IaCModule:       iacModule,
		IaCStateID:      iacStateID,
	}, nil
}

func terraformArtifactMetadata(artifact TerraformArtifact) map[string]any {
	return compactAnyMap(map[string]any{
		"kind":             artifact.Kind,
		"iac_type":         artifact.IaCType,
		"format":           artifact.Format,
		"path":             artifact.Path,
		"resource_type":    artifact.ResourceType,
		"resource_address": artifact.ResourceAddress,
		"import_id":        artifact.ImportID,
		"summary":          artifact.Summary,
		"content":          artifact.Content,
		"notes":            append([]string(nil), artifact.Notes...),
		"iac_file":         artifact.IaCFile,
		"iac_module":       artifact.IaCModule,
		"iac_state_id":     artifact.IaCStateID,
	})
}

func bucketNameFromExecution(execution *Execution) string {
	if execution == nil {
		return ""
	}
	candidates := []string{
		strings.TrimSpace(remediationMapValueToString(execution.TriggerData, "resource_name")),
		strings.TrimSpace(remediationMapValueToString(execution.TriggerData, "bucket")),
		strings.TrimSpace(remediationMapValueToString(execution.TriggerData, "resource_external_id")),
		strings.TrimSpace(remediationMapValueToString(execution.TriggerData, "resource_id")),
		strings.TrimSpace(remediationMapValueToString(execution.TriggerData, "entity_id")),
	}
	for _, candidate := range candidates {
		if bucketName := normalizeBucketIdentifier(candidate); bucketName != "" {
			return bucketName
		}
	}
	return ""
}

func normalizeBucketIdentifier(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return ""
	}
	switch {
	case strings.HasPrefix(value, "arn:aws:s3:::"):
		return strings.TrimSpace(strings.TrimPrefix(value, "arn:aws:s3:::"))
	case strings.HasPrefix(value, "s3://"):
		return strings.TrimSpace(strings.TrimPrefix(value, "s3://"))
	case strings.HasPrefix(value, "bucket:"):
		return strings.TrimSpace(strings.TrimPrefix(value, "bucket:"))
	default:
		return strings.Trim(value, "/")
	}
}

func terraformArtifactPath(execution *Execution, fileName string) string {
	fileName = strings.TrimSpace(fileName)
	if fileName == "" {
		fileName = "cerebro_remediation.tf"
	}
	if execution != nil {
		if iacFile := strings.TrimSpace(remediationMapValueToString(execution.TriggerData, "iac_file")); iacFile != "" {
			dir := filepath.Dir(iacFile)
			if dir == "." || dir == "" {
				return filepath.ToSlash(fileName)
			}
			return filepath.ToSlash(filepath.Join(dir, fileName))
		}
		moduleSegments := terraformModulePathSegments(firstNonEmpty(
			strings.TrimSpace(remediationMapValueToString(execution.TriggerData, "iac_module")),
			terraformModuleAddressFromStateID(strings.TrimSpace(remediationMapValueToString(execution.TriggerData, "iac_state_id"))),
		))
		if len(moduleSegments) > 0 {
			pathParts := append([]string{"generated", "terraform"}, moduleSegments...)
			pathParts = append(pathParts, fileName)
			return filepath.ToSlash(filepath.Join(pathParts...))
		}
	}
	return filepath.ToSlash(filepath.Join("generated", "terraform", "aws", fileName))
}

func terraformModuleAddressFromStateID(stateID string) string {
	segments := terraformModulePathSegments(stateID)
	if len(segments) == 0 {
		return ""
	}
	parts := make([]string, 0, len(segments)*2)
	for _, segment := range segments {
		parts = append(parts, "module", segment)
	}
	return strings.Join(parts, ".")
}

func terraformModulePathSegments(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	if strings.Contains(raw, "module.") {
		parts := strings.Split(raw, ".")
		segments := make([]string, 0)
		for idx := 0; idx < len(parts)-1; idx++ {
			if parts[idx] != "module" {
				continue
			}
			name := terraformAddressSegment(parts[idx+1])
			if name == "" {
				continue
			}
			segments = append(segments, name)
			idx++
		}
		return segments
	}

	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == '/' || r == '\\'
	})
	segments := make([]string, 0, len(parts))
	for _, part := range parts {
		name := terraformAddressSegment(part)
		if name == "" {
			continue
		}
		segments = append(segments, name)
	}
	return segments
}

func terraformAddressSegment(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if idx := strings.IndexRune(raw, '['); idx >= 0 {
		raw = raw[:idx]
	}
	raw = strings.Trim(raw, `"'`)
	return terraformIdentifier(raw)
}

func terraformIdentifier(raw string) string {
	text := terraformIdentifierUnsafeChars.ReplaceAllString(strings.TrimSpace(raw), "_")
	text = strings.Trim(text, "_")
	if text == "" {
		return "generated"
	}
	if text[0] >= '0' && text[0] <= '9' {
		return "r_" + text
	}
	return text
}

func terraformString(value string) string {
	encoded, _ := json.Marshal(strings.TrimSpace(value))
	return string(encoded)
}

func renderTerraformTemplate(src string, data map[string]string) string {
	tmpl := template.Must(template.New("terraform").Parse(src))
	var builder strings.Builder
	if err := tmpl.Execute(&builder, data); err != nil {
		panic(err)
	}
	return strings.TrimLeft(builder.String(), "\n")
}

const terraformBucketDefaultEncryptionTemplate = `
# Generated by Cerebro. Review, import existing state, and run terraform plan before apply.
resource "aws_s3_bucket_server_side_encryption_configuration" "{{ .ResourceName }}" {
  bucket = {{ .BucketName }}

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = {{ .SSEAlgorithm }}
{{- if ne .KMSMasterKeyID "\"\"" }}
      kms_master_key_id = {{ .KMSMasterKeyID }}
{{- end }}
    }
{{- if eq .BucketKeyEnabled "true" }}
    bucket_key_enabled = true
{{- end }}
  }
}
`
