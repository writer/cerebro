package compliance

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	findinganalysis "github.com/writer/cerebro/internal/findings"
	"gopkg.in/yaml.v3"
)

const DefaultFindingProfileExclusionsPath = "internal/compliance/finding_profile_exclusions.yaml"

// ErrInvalidFindingProfileExclusionLedger identifies malformed ledger YAML.
var ErrInvalidFindingProfileExclusionLedger = errors.New("invalid finding profile exclusion ledger")

const (
	findingProfileExclusionReviewStateReviewed = "reviewed"
	findingProfileExclusionReviewDateLayout    = "2006-01-02"
)

// FindingProfileExclusionLedger records reviewed decisions not to associate
// public findings with a named compliance profile.
type FindingProfileExclusionLedger struct {
	Version        string                    `json:"version" yaml:"version"`
	CatalogVersion string                    `json:"catalog_version" yaml:"catalog_version"`
	Exclusions     []FindingProfileExclusion `json:"exclusions" yaml:"exclusions"`
}

type FindingProfileExclusion struct {
	FindingID   string `json:"finding_id" yaml:"finding_id"`
	Reason      string `json:"reason" yaml:"reason"`
	Owner       string `json:"owner" yaml:"owner"`
	ReviewState string `json:"review_state" yaml:"review_state"`
	ReviewedAt  string `json:"reviewed_at" yaml:"reviewed_at"`
}

func LoadFindingProfileExclusionLedger(content []byte) (FindingProfileExclusionLedger, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(content))
	decoder.KnownFields(true)
	var ledger FindingProfileExclusionLedger
	if err := decoder.Decode(&ledger); err != nil {
		return FindingProfileExclusionLedger{}, fmt.Errorf("%w: %w", ErrInvalidFindingProfileExclusionLedger, err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err != nil {
			return FindingProfileExclusionLedger{}, fmt.Errorf("%w: %w", ErrInvalidFindingProfileExclusionLedger, err)
		}
		return FindingProfileExclusionLedger{}, fmt.Errorf("%w: multiple YAML documents are not allowed", ErrInvalidFindingProfileExclusionLedger)
	}
	return ledger, nil
}

// ValidateFindingProfileCoverage requires every public finding to resolve to a
// named compliance profile or have a complete reviewed exclusion.
func ValidateFindingProfileCoverage(index FindingProfileIndex, ledger FindingProfileExclusionLedger, catalog findinganalysis.PublicDetectionCatalog) []ValidationIssue {
	issues := []ValidationIssue{}
	if strings.TrimSpace(ledger.Version) == "" {
		issues = append(issues, ValidationIssue{Path: "version", Message: "is required"})
	}
	catalogVersion := strings.TrimSpace(catalog.Version)
	ledgerCatalogVersion := strings.TrimSpace(ledger.CatalogVersion)
	if catalogVersion == "" {
		issues = append(issues, ValidationIssue{Path: "public_catalog.version", Message: "is required"})
	}
	if ledgerCatalogVersion == "" {
		issues = append(issues, ValidationIssue{Path: "catalog_version", Message: "is required"})
	} else if catalogVersion != "" && ledgerCatalogVersion != catalogVersion {
		issues = append(issues, ValidationIssue{
			Path:    "catalog_version",
			Message: fmt.Sprintf("%q does not match public catalog version %q", ledgerCatalogVersion, catalogVersion),
		})
	}

	detectionsByID := make(map[string]findinganalysis.PublicDetection, len(catalog.Detections))
	linked := make(map[string]struct{}, len(catalog.Detections))
	for idx, detection := range catalog.Detections {
		path := fmt.Sprintf("public_catalog.detections[%d].id", idx)
		id := strings.TrimSpace(detection.ID)
		if id == "" {
			issues = append(issues, ValidationIssue{Path: path, Message: "is required"})
			continue
		}
		if _, duplicate := detectionsByID[id]; duplicate {
			issues = append(issues, ValidationIssue{Path: path, Message: fmt.Sprintf("public finding id %q is duplicated", id)})
			continue
		}
		detectionsByID[id] = detection
		refs := make([]ControlRef, 0, len(detection.ControlRefs))
		for _, ref := range detection.ControlRefs {
			refs = append(refs, ControlRef{FrameworkName: ref.FrameworkName, ControlID: ref.ControlID})
		}
		if len(ResolveFindingProfileMatches(index, id, refs)) != 0 {
			linked[id] = struct{}{}
		}
	}

	exclusionIDs := make(map[string]struct{}, len(ledger.Exclusions))
	reviewedExclusions := make(map[string]struct{}, len(ledger.Exclusions))
	for idx, exclusion := range ledger.Exclusions {
		path := fmt.Sprintf("exclusions[%d]", idx)
		id := strings.TrimSpace(exclusion.FindingID)
		valid := true
		if id == "" {
			issues = append(issues, ValidationIssue{Path: path + ".finding_id", Message: "is required"})
			continue
		}
		if _, duplicate := exclusionIDs[id]; duplicate {
			issues = append(issues, ValidationIssue{Path: path + ".finding_id", Message: fmt.Sprintf("exclusion for public finding %q is duplicated", id)})
			valid = false
		} else {
			exclusionIDs[id] = struct{}{}
		}
		if _, known := detectionsByID[id]; !known {
			issues = append(issues, ValidationIssue{Path: path + ".finding_id", Message: fmt.Sprintf("public finding %q is not in the catalog", id)})
			valid = false
		}
		if _, stale := linked[id]; stale {
			issues = append(issues, ValidationIssue{Path: path + ".finding_id", Message: fmt.Sprintf("public finding %q now resolves to a named profile", id)})
			valid = false
		}
		if !concreteFindingProfileReviewValue(exclusion.Reason) {
			issues = append(issues, ValidationIssue{Path: path + ".reason", Message: "a concrete reason is required"})
			valid = false
		}
		if !concreteFindingProfileReviewValue(exclusion.Owner) {
			issues = append(issues, ValidationIssue{Path: path + ".owner", Message: "a concrete owner is required"})
			valid = false
		}
		if strings.TrimSpace(exclusion.ReviewState) != findingProfileExclusionReviewStateReviewed {
			issues = append(issues, ValidationIssue{Path: path + ".review_state", Message: fmt.Sprintf("must be %q", findingProfileExclusionReviewStateReviewed)})
			valid = false
		}
		if _, err := time.Parse(findingProfileExclusionReviewDateLayout, strings.TrimSpace(exclusion.ReviewedAt)); err != nil {
			issues = append(issues, ValidationIssue{Path: path + ".reviewed_at", Message: "must be a valid YYYY-MM-DD date"})
			valid = false
		}
		if valid {
			reviewedExclusions[id] = struct{}{}
		}
	}

	for id := range detectionsByID {
		if _, ok := linked[id]; ok {
			continue
		}
		if _, ok := reviewedExclusions[id]; ok {
			continue
		}
		issues = append(issues, ValidationIssue{
			Path:    "public_catalog",
			Message: fmt.Sprintf("public finding %q has no named profile link or reviewed exclusion", id),
		})
	}
	sort.Slice(issues, func(i, j int) bool { return issues[i].Error() < issues[j].Error() })
	return issues
}

func ValidateBuiltinFindingProfileCoverage(catalog findinganalysis.PublicDetectionCatalog) error {
	ledger, err := LoadBuiltinFindingProfileExclusionLedger()
	if err != nil {
		return fmt.Errorf("load %s: %w", DefaultFindingProfileExclusionsPath, err)
	}
	index, err := LoadBuiltinFindingProfileIndex()
	if err != nil {
		return fmt.Errorf("load %s: %w", DefaultFindingProfileIndexPath, err)
	}
	issues := ValidateFindingProfileCoverage(index, ledger, catalog)
	if len(issues) == 0 {
		return nil
	}
	messages := make([]string, 0, len(issues))
	for _, issue := range issues {
		messages = append(messages, issue.Error())
	}
	return fmt.Errorf("validate %s: %s", DefaultFindingProfileExclusionsPath, strings.Join(messages, "; "))
}

func concreteFindingProfileReviewValue(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "-", "n/a", "na", "none", "placeholder", "tbd", "todo", "unknown", "unassigned":
		return false
	default:
		return true
	}
}
