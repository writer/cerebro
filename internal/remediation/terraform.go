package remediation

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/evalops/cerebro/internal/iacrender"
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

type terraformArtifactRenderer func(Action, *Execution) (TerraformArtifact, error)

type terraformArtifactRendererKey struct {
	ActionType     ActionType
	Provider       string
	ResourceFamily string
}

var terraformArtifactRenderers = map[terraformArtifactRendererKey]terraformArtifactRenderer{
	{
		ActionType:     ActionRestrictPublicStorageAccess,
		Provider:       "aws",
		ResourceFamily: "bucket",
	}: renderTerraformRestrictPublicStorageAccessActionArtifact,
	{
		ActionType:     ActionEnableBucketDefaultEncryption,
		Provider:       "aws",
		ResourceFamily: "bucket",
	}: renderTerraformBucketDefaultEncryptionActionArtifact,
}

func actionDeliveryMode(action Action, execution *Execution, entry CatalogEntry) DeliveryMode {
	raw := strings.ToLower(strings.TrimSpace(action.Config["delivery_mode"]))
	switch DeliveryMode(raw) {
	case DeliveryModeRemoteApply, DeliveryModeTerraform:
		return DeliveryMode(raw)
	}
	provider := strings.ToLower(strings.TrimSpace(inferProvider(execution)))
	if provider != "" && len(entry.DefaultDeliveryModesByProvider) > 0 {
		if mode, ok := entry.DefaultDeliveryModesByProvider[provider]; ok {
			return mode
		}
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

func renderTerraformArtifact(action Action, execution *Execution) (TerraformArtifact, error) {
	key := terraformArtifactRendererLookupKey(action.Type, execution)
	renderer, ok := terraformArtifactRenderers[key]
	if !ok {
		return TerraformArtifact{}, terraformUnsupportedContextError(action.Type, key)
	}
	return renderer(action, execution)
}

func renderTerraformBucketDefaultEncryptionActionArtifact(action Action, execution *Execution) (TerraformArtifact, error) {
	sseAlgorithm := firstNonEmpty(strings.TrimSpace(action.Config["sse_algorithm"]), "AES256")
	kmsMasterKeyID := strings.TrimSpace(action.Config["kms_master_key_id"])
	bucketKeyEnabled := configBool(action.Config["bucket_key_enabled"])
	return renderTerraformBucketDefaultEncryptionArtifact(execution, sseAlgorithm, kmsMasterKeyID, bucketKeyEnabled)
}

func renderTerraformRestrictPublicStorageAccessActionArtifact(_ Action, execution *Execution) (TerraformArtifact, error) {
	return renderTerraformPublicStorageAccessArtifact(execution)
}

func renderTerraformPublicStorageAccessArtifact(execution *Execution) (TerraformArtifact, error) {
	if err := validateTerraformArtifactContext(ActionRestrictPublicStorageAccess, execution, "aws", "bucket"); err != nil {
		return TerraformArtifact{}, err
	}
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

	resourceName := terraformIdentifier(bucketName + "_public_access_block")
	address := "aws_s3_bucket_public_access_block." + resourceName
	path := terraformArtifactPath(execution, "cerebro_s3_bucket_public_access_block_"+terraformIdentifier(bucketName)+".tf")
	content := iacrender.RenderTemplate("terraform", terraformBucketPublicAccessBlockTemplate, map[string]string{
		"BucketReference":   terraformBucketArgument(execution, bucketName),
		"ResourceName":      resourceName,
		"ExistingIaCFile":   iacFile,
		"ExistingIaCModule": iacModule,
	})

	notes := []string{
		"Run terraform plan before apply.",
		fmt.Sprintf("Import the existing public access block before apply: terraform import %s %s", address, bucketName),
		"Review the existing bucket policy and ACL state to confirm this change matches intended public exposure handling.",
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
		Summary:         fmt.Sprintf("Terraform patch for blocking public access on S3 bucket %s", bucketName),
		Content:         content,
		Notes:           notes,
		IaCFile:         iacFile,
		IaCModule:       iacModule,
		IaCStateID:      iacStateID,
	}, nil
}

func renderTerraformBucketDefaultEncryptionArtifact(execution *Execution, sseAlgorithm, kmsMasterKeyID string, bucketKeyEnabled bool) (TerraformArtifact, error) {
	if err := validateTerraformArtifactContext(ActionEnableBucketDefaultEncryption, execution, "aws", "bucket"); err != nil {
		return TerraformArtifact{}, err
	}
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
	content := iacrender.RenderTemplate("terraform", terraformBucketDefaultEncryptionTemplate, map[string]string{
		"BucketReference":   terraformBucketArgument(execution, bucketName),
		"ResourceName":      resourceName,
		"SSEAlgorithm":      iacrender.HCLString(firstNonEmpty(strings.TrimSpace(sseAlgorithm), "AES256")),
		"KMSMasterKeyID":    iacrender.HCLString(strings.TrimSpace(kmsMasterKeyID)),
		"BucketKeyEnabled":  fmt.Sprintf("%t", bucketKeyEnabled),
		"ImportAddress":     address,
		"ImportIdentifier":  iacrender.HCLString(bucketName),
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

func terraformArtifactRendererLookupKey(actionType ActionType, execution *Execution) terraformArtifactRendererKey {
	return terraformArtifactRendererKey{
		ActionType:     actionType,
		Provider:       terraformActionProvider(actionType, execution),
		ResourceFamily: terraformActionResourceFamily(actionType, execution),
	}
}

func validateTerraformArtifactContext(actionType ActionType, execution *Execution, expectedProvider, expectedResourceFamily string) error {
	key := terraformArtifactRendererLookupKey(actionType, execution)
	if expectedProvider != "" && key.Provider != "" && key.Provider != expectedProvider {
		return fmt.Errorf("terraform delivery for %s is only implemented for %s %ss, got %s", actionType, expectedProvider, expectedResourceFamily, key.Provider)
	}
	if expectedResourceFamily != "" && key.ResourceFamily != "" && key.ResourceFamily != expectedResourceFamily {
		return fmt.Errorf("terraform delivery for %s is only implemented for %s %ss, got %s", actionType, expectedProvider, expectedResourceFamily, key.ResourceFamily)
	}
	return nil
}

func terraformUnsupportedContextError(actionType ActionType, key terraformArtifactRendererKey) error {
	providers := map[string]struct{}{}
	resourceFamilies := map[string]struct{}{}
	for candidate := range terraformArtifactRenderers {
		if candidate.ActionType != actionType {
			continue
		}
		if candidate.Provider != "" {
			providers[candidate.Provider] = struct{}{}
		}
		if candidate.ResourceFamily != "" {
			resourceFamilies[candidate.ResourceFamily] = struct{}{}
		}
	}
	if len(providers) == 1 && len(resourceFamilies) == 1 {
		return fmt.Errorf(
			"terraform delivery for %s is only implemented for %s %ss, got provider=%s resource_family=%s",
			actionType,
			firstMapKey(providers),
			firstMapKey(resourceFamilies),
			firstNonEmpty(key.Provider, "unknown"),
			firstNonEmpty(key.ResourceFamily, "unknown"),
		)
	}
	return fmt.Errorf(
		"terraform delivery is not implemented for %s (provider=%s resource_family=%s)",
		actionType,
		firstNonEmpty(key.Provider, "unknown"),
		firstNonEmpty(key.ResourceFamily, "unknown"),
	)
}

func firstMapKey(values map[string]struct{}) string {
	for value := range values {
		return value
	}
	return ""
}

func terraformActionProvider(actionType ActionType, execution *Execution) string {
	provider := strings.ToLower(strings.TrimSpace(inferProvider(execution)))
	if provider != "" {
		return provider
	}
	entry, ok := CatalogEntryByAction(actionType)
	if ok && len(entry.Providers) == 1 {
		return strings.ToLower(strings.TrimSpace(entry.Providers[0]))
	}
	return ""
}

func terraformActionResourceFamily(actionType ActionType, execution *Execution) string {
	raw := ""
	if execution != nil {
		raw = strings.ToLower(strings.TrimSpace(remediationMapValueToString(execution.TriggerData, "resource_type")))
	}
	entry, ok := CatalogEntryByAction(actionType)
	if raw != "" {
		canonical := canonicalTerraformResourceFamily(raw)
		if !ok {
			return canonical
		}
		for _, candidate := range entry.ResourceTypes {
			if raw == strings.ToLower(strings.TrimSpace(candidate)) || canonical == canonicalTerraformResourceFamily(candidate) {
				return canonicalTerraformResourceFamily(candidate)
			}
		}
		return canonical
	}
	if ok && len(entry.ResourceTypes) > 0 {
		return canonicalTerraformResourceFamily(entry.ResourceTypes[0])
	}
	return ""
}

func canonicalTerraformResourceFamily(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "bucket", "storage/bucket", "storage_bucket", "aws:s3:bucket", "blob_container", "storage/container":
		return "bucket"
	case "security_group", "security_group_rule", "aws:ec2:security_group":
		return "security_group"
	case "iam_user", "identity/user":
		return "identity_user"
	case "service_account", "identity/service_account":
		return "service_account"
	default:
		return strings.ToLower(strings.TrimSpace(raw))
	}
}

func terraformBucketArgument(execution *Execution, bucketName string) string {
	if reference := terraformBucketReferenceFromExecution(execution); reference != "" {
		return reference
	}
	return iacrender.HCLString(bucketName)
}

func terraformBucketReferenceFromExecution(execution *Execution) string {
	if execution == nil {
		return ""
	}
	stateID := strings.TrimSpace(remediationMapValueToString(execution.TriggerData, "iac_state_id"))
	resourceAddress, resourceType := terraformStateResourceAddress(stateID)
	if resourceType != "aws_s3_bucket" || resourceAddress == "" {
		return ""
	}
	return resourceAddress + ".id"
}

func terraformStateResourceAddress(stateID string) (string, string) {
	stateID = strings.TrimSpace(stateID)
	if stateID == "" {
		return "", ""
	}
	parts := terraformAddressParts(stateID)
	if len(parts) == 0 {
		return "", ""
	}
	prefix := make([]string, 0, len(parts))
	idx := 0
	for idx < len(parts) {
		part := strings.TrimSpace(parts[idx])
		if part == "" {
			return "", ""
		}
		if part != "module" {
			break
		}
		if idx+1 >= len(parts) {
			return "", ""
		}
		name := strings.TrimSpace(parts[idx+1])
		if name == "" {
			return "", ""
		}
		prefix = append(prefix, part, name)
		idx += 2
	}
	remaining := parts[idx:]
	if len(remaining) != 2 {
		return "", ""
	}
	resourceType := strings.TrimSpace(remaining[0])
	resourceName := strings.TrimSpace(remaining[1])
	if resourceType == "" || resourceName == "" || resourceType == "data" {
		return "", ""
	}
	addressParts := append(prefix, resourceType, resourceName)
	return strings.Join(addressParts, "."), resourceType
}

func terraformAddressParts(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := make([]string, 0, 8)
	var current strings.Builder
	bracketDepth := 0
	var quoted rune
	escaped := false
	flush := func() {
		parts = append(parts, current.String())
		current.Reset()
	}
	for _, r := range raw {
		switch {
		case escaped:
			current.WriteRune(r)
			escaped = false
		case quoted != 0:
			current.WriteRune(r)
			if r == '\\' {
				escaped = true
				continue
			}
			if r == quoted {
				quoted = 0
			}
		default:
			switch r {
			case '"', '\'':
				current.WriteRune(r)
				if bracketDepth > 0 {
					quoted = r
				}
			case '[':
				bracketDepth++
				current.WriteRune(r)
			case ']':
				if bracketDepth == 0 {
					return nil
				}
				bracketDepth--
				current.WriteRune(r)
			case '.':
				if bracketDepth == 0 {
					flush()
					continue
				}
				current.WriteRune(r)
			default:
				current.WriteRune(r)
			}
		}
	}
	if escaped || quoted != 0 || bracketDepth != 0 {
		return nil
	}
	flush()
	return parts
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
	stateID = strings.TrimSpace(stateID)
	if stateID == "" || !strings.Contains(stateID, "module.") {
		return ""
	}
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

const terraformBucketDefaultEncryptionTemplate = `
# Generated by Cerebro. Review, import existing state, and run terraform plan before apply.
resource "aws_s3_bucket_server_side_encryption_configuration" "{{ .ResourceName }}" {
  bucket = {{ .BucketReference }}

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

const terraformBucketPublicAccessBlockTemplate = `
# Generated by Cerebro. Review, import existing state, and run terraform plan before apply.
resource "aws_s3_bucket_public_access_block" "{{ .ResourceName }}" {
  bucket = {{ .BucketReference }}

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
`
