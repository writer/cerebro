package complianceexchange

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

const (
	layerParse     = "parse"
	layerSchema    = "schema"
	layerPaths     = "archive_safety"
	layerLimits    = "limits"
	layerRefs      = "referential_integrity"
	layerDigest    = "digest"
	layerTenant    = "authorization"
	layerSignature = "signature"
)

var validationLayerOrder = map[string]int{
	layerParse: 1, layerSchema: 2, layerPaths: 3, layerLimits: 4,
	layerRefs: 5, layerDigest: 6, layerTenant: 7, layerSignature: 8,
}

// Validate performs pure staged validation. It never persists bytes or
// canonical records, and emits a change plan only when every layer passes.
func Validate(ctx context.Context, request ValidationRequest) ValidationResult {
	result := ValidationResult{Status: ValidationInvalid, Issues: []ValidationIssue{}}
	limits, err := normalizeLimits(request.Limits)
	if err != nil {
		result.Issues = append(result.Issues, issue(layerLimits, "invalid_limits", "", "Validation limits are invalid.", "Use positive limits with the per-file limit no larger than the total limit."))
		return result
	}
	if len(request.ManifestBytes) == 0 {
		result.Issues = append(result.Issues, issue(layerParse, "manifest_required", "manifest.json", "The package manifest is missing.", "Include one manifest.json file."))
		return result
	}
	if len(request.ManifestBytes) > limits.MaxManifestBytes {
		result.Issues = append(result.Issues, issue(layerLimits, "manifest_size_limit", "manifest.json", "The package manifest exceeds the size limit.", "Reduce the manifest or split the package."))
		return result
	}
	if len(request.Signature) > limits.MaxSignatureBytes {
		result.Issues = append(result.Issues, issue(layerLimits, "signature_size_limit", "manifest.jws", "The detached signature exceeds the size limit.", "Use the bounded detached signature format."))
		return result
	}
	manifest, err := decodeManifest(request.ManifestBytes)
	if err != nil {
		result.Issues = append(result.Issues, issue(layerParse, "manifest_invalid_json", "manifest.json", "The package manifest is not valid JSON.", "Provide one JSON object matching the supported manifest schema."))
		return result
	}
	result.Manifest = &manifest
	result.ManifestDigest = sha256Hex(request.ManifestBytes)
	validateManifestShape(&result, manifest)
	validateTenant(&result, request.ExpectedTenantID, manifest.TenantID)
	actual := validateActualFiles(&result, request.Files, limits)
	validateManifestFiles(&result, manifest, actual, limits)

	if strings.TrimSpace(request.Signature) == "" {
		result.Issues = append(result.Issues, issue(layerSignature, "signature_required", "manifest.jws", "The detached manifest signature is missing.", "Sign the exact manifest bytes with an allowed trusted key."))
	} else if header, err := verifyDetached(ctx, request.ManifestBytes, request.Signature, request.Trust); err != nil {
		result.Issues = append(result.Issues, issue(layerSignature, "signature_invalid", "manifest.jws", "The manifest signature could not be verified.", "Use an allowed algorithm and a key trusted for this tenant."))
	} else {
		result.SignerKeyID = header.KeyID
		result.Algorithm = header.Algorithm
	}

	sortIssues(result.Issues)
	if len(result.Issues) > 0 {
		return result
	}
	result.Status = ValidationValid
	result.ChangePlan = changePlan(manifest, result.ManifestDigest)
	return result
}

func validateManifestShape(result *ValidationResult, manifest Manifest) {
	if manifest.SchemaVersion != ManifestSchemaVersion {
		result.Issues = append(result.Issues, issue(layerSchema, "unsupported_manifest_version", "schema_version", "The manifest schema version is not supported.", "Export the package using a supported manifest version."))
	}
	if strings.TrimSpace(manifest.PackageID) == "" {
		result.Issues = append(result.Issues, issue(layerSchema, "package_id_required", "package_id", "The package ID is missing.", "Set a stable package ID."))
	}
	if strings.TrimSpace(manifest.TenantID) == "" {
		result.Issues = append(result.Issues, issue(layerSchema, "tenant_id_required", "tenant_id", "The tenant ID is missing.", "Set the package tenant ID."))
	}
	if !validCreatedAt(manifest.CreatedAt) {
		result.Issues = append(result.Issues, issue(layerSchema, "created_at_required", "created_at", "The package creation time is missing.", "Set an RFC 3339 package creation time."))
	}
	if manifest.FileCount != len(manifest.Files) {
		result.Issues = append(result.Issues, issue(layerSchema, "file_count_mismatch", "file_count", "The declared file count does not match the manifest file list.", "Regenerate the manifest from the complete payload."))
	}
	if manifest.FileCount == 0 {
		result.Issues = append(result.Issues, issue(layerSchema, "payload_required", "files", "The package contains no payload files.", "Include at least one typed payload file."))
	}
	if manifest.PredecessorDigest != "" && !validDigest(manifest.PredecessorDigest) {
		result.Issues = append(result.Issues, issue(layerSchema, "predecessor_digest_invalid", "predecessor_digest", "The predecessor digest is not a lowercase SHA-256 value.", "Use the verified SHA-256 digest of the predecessor manifest."))
	}
}

func validateTenant(result *ValidationResult, expected string, actual string) {
	expected = strings.TrimSpace(expected)
	if expected == "" {
		result.Issues = append(result.Issues, issue(layerTenant, "expected_tenant_required", "tenant_id", "The validation tenant is missing.", "Resolve the authenticated tenant before validation."))
		return
	}
	if expected != strings.TrimSpace(actual) {
		result.Issues = append(result.Issues, issue(layerTenant, "tenant_mismatch", "tenant_id", "The package is not scoped to the importing tenant.", "Import a package issued for the authenticated tenant."))
	}
}

type actualFile struct {
	file File
	key  string
}

func validateActualFiles(result *ValidationResult, files []File, limits Limits) map[string]actualFile {
	actual := make(map[string]actualFile, len(files))
	if len(files) > limits.MaxFiles {
		result.Issues = append(result.Issues, issue(layerLimits, "file_count_limit", "files", "The package exceeds the file-count limit.", "Split the package into smaller bounded packages."))
	}
	var total int64
	for _, file := range files {
		if err := validatePackagePath(file.Path, limits.MaxPathBytes); err != nil {
			result.Issues = append(result.Issues, issue(layerPaths, "unsafe_path", safeIssuePath(file.Path), "A payload path is unsafe or not normalized.", "Use a unique normalized relative path without dot segments or backslashes."))
			continue
		}
		key := collisionKey(file.Path)
		if prior, ok := actual[key]; ok {
			result.Issues = append(result.Issues, issue(layerPaths, "duplicate_path", file.Path, fmt.Sprintf("The payload path collides with %q.", prior.file.Path), "Use unique paths that also differ when case-folded."))
			continue
		}
		actual[key] = actualFile{file: file, key: key}
		size := int64(len(file.Data))
		if size > limits.MaxFileBytes {
			result.Issues = append(result.Issues, issue(layerLimits, "file_size_limit", file.Path, "A payload file exceeds the per-file size limit.", "Split or omit the oversized payload."))
		}
		if total <= limits.MaxTotalBytes {
			if size > limits.MaxTotalBytes-total {
				total = limits.MaxTotalBytes + 1
			} else {
				total += size
			}
		}
	}
	if total > limits.MaxTotalBytes {
		result.Issues = append(result.Issues, issue(layerLimits, "total_size_limit", "files", "The package exceeds the total uncompressed size limit.", "Split the package into smaller bounded packages."))
	}
	return actual
}

func validateManifestFiles(result *ValidationResult, manifest Manifest, actual map[string]actualFile, limits Limits) {
	manifestPaths := make(map[string]string, len(manifest.Files))
	coveredActual := make(map[string]struct{}, len(manifest.Files))
	var declaredTotal int64
	priorPath := ""
	for index, declared := range manifest.Files {
		fieldPath := fmt.Sprintf("files[%d]", index)
		if err := validatePackagePath(declared.Path, limits.MaxPathBytes); err != nil {
			result.Issues = append(result.Issues, issue(layerPaths, "unsafe_manifest_path", fieldPath+".path", "A manifest path is unsafe or not normalized.", "Regenerate the manifest with normalized relative paths."))
			continue
		}
		if priorPath != "" && declared.Path <= priorPath {
			result.Issues = append(result.Issues, issue(layerSchema, "files_not_canonical", fieldPath+".path", "Manifest files are not in canonical path order.", "Sort manifest files by path and regenerate the signature."))
		}
		priorPath = declared.Path
		key := collisionKey(declared.Path)
		if prior, ok := manifestPaths[key]; ok {
			result.Issues = append(result.Issues, issue(layerPaths, "duplicate_manifest_path", fieldPath+".path", fmt.Sprintf("The manifest path collides with %q.", prior), "Use unique paths that also differ when case-folded."))
			continue
		}
		manifestPaths[key] = declared.Path
		if strings.TrimSpace(declared.MediaType) == "" || strings.TrimSpace(declared.LogicalType) == "" {
			result.Issues = append(result.Issues, issue(layerSchema, "file_type_required", fieldPath, "Every manifest file needs media and logical types.", "Set both media_type and logical_type."))
		}
		if declared.SizeBytes < 0 || declared.SizeBytes > limits.MaxFileBytes {
			result.Issues = append(result.Issues, issue(layerLimits, "declared_file_size_invalid", fieldPath+".size_bytes", "A declared file size is invalid or exceeds the limit.", "Regenerate the manifest from a bounded payload."))
		} else if declaredTotal <= limits.MaxTotalBytes {
			if declared.SizeBytes > limits.MaxTotalBytes-declaredTotal {
				declaredTotal = limits.MaxTotalBytes + 1
			} else {
				declaredTotal += declared.SizeBytes
			}
		}
		if !validDigest(declared.SHA256) {
			result.Issues = append(result.Issues, issue(layerSchema, "digest_invalid", fieldPath+".sha256", "A file digest is not a lowercase SHA-256 value.", "Regenerate the manifest from the exact payload bytes."))
		}
		found, ok := actual[key]
		if !ok {
			result.Issues = append(result.Issues, issue(layerRefs, "payload_file_missing", declared.Path, "A file declared by the manifest is missing.", "Include every declared payload file."))
			continue
		}
		if found.file.Path != declared.Path {
			result.Issues = append(result.Issues, issue(layerPaths, "path_case_mismatch", declared.Path, "A payload file path does not exactly match the signed manifest path.", "Use the exact path recorded in the signed manifest."))
			continue
		}
		coveredActual[key] = struct{}{}
		if int64(len(found.file.Data)) != declared.SizeBytes || sha256Hex(found.file.Data) != declared.SHA256 {
			result.Issues = append(result.Issues, issue(layerDigest, "file_digest_mismatch", declared.Path, "A payload file does not match its signed size or digest.", "Restore the exact signed file or regenerate and re-sign the package."))
		}
		if strings.TrimSpace(found.file.MediaType) != declared.MediaType || strings.TrimSpace(found.file.LogicalType) != declared.LogicalType {
			result.Issues = append(result.Issues, issue(layerSchema, "file_metadata_mismatch", declared.Path, "Payload file metadata does not match the signed manifest.", "Use the media and logical types recorded in the signed manifest."))
		}
	}
	if declaredTotal != manifest.TotalBytes {
		result.Issues = append(result.Issues, issue(layerSchema, "total_bytes_mismatch", "total_bytes", "The declared total does not match the manifest file sizes.", "Regenerate the manifest from the complete payload."))
	}
	for key, found := range actual {
		if _, ok := coveredActual[key]; !ok {
			result.Issues = append(result.Issues, issue(layerRefs, "unexpected_payload_file", found.file.Path, "A payload file is not covered by the signed manifest.", "Remove the file or include it in a newly signed manifest."))
		}
	}
}

func changePlan(manifest Manifest, digest string) *ChangePlan {
	operations := make([]ChangeOperation, 0, len(manifest.Files))
	for _, file := range manifest.Files {
		operations = append(operations, ChangeOperation{
			Action: "stage", Path: file.Path, LogicalType: file.LogicalType,
			SHA256: file.SHA256, SizeBytes: file.SizeBytes,
		})
	}
	return &ChangePlan{
		PackageID: manifest.PackageID, TenantID: manifest.TenantID,
		ManifestDigest: digest, FileCount: manifest.FileCount,
		TotalBytes: manifest.TotalBytes, Operations: operations,
	}
}

func issue(layer string, code string, path string, message string, remediation string) ValidationIssue {
	return ValidationIssue{Layer: layer, Code: code, Severity: SeverityError, Path: path, Message: message, Remediation: remediation}
}

func sortIssues(issues []ValidationIssue) {
	sort.SliceStable(issues, func(i, j int) bool {
		left, right := validationLayerOrder[issues[i].Layer], validationLayerOrder[issues[j].Layer]
		if left != right {
			return left < right
		}
		if issues[i].Path != issues[j].Path {
			return issues[i].Path < issues[j].Path
		}
		return issues[i].Code < issues[j].Code
	})
}
