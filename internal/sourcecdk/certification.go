package sourcecdk

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	CertificationEvidenceProviderSpec          = "provider_spec"
	CertificationEvidenceProviderDocumentation = "provider_documentation"
	CertificationEvidenceSandboxContract       = "sandbox_contract"
	CertificationEvidenceRecordedReplay        = "recorded_replay"
)

// CatalogCertification records review ownership and static proof only. Live
// runtime and outcome states are intentionally absent from this catalog type.
type CatalogCertification struct {
	Owner              string                         `yaml:"owner" json:"owner"`
	ReviewedAt         string                         `yaml:"reviewed_at" json:"reviewed_at"`
	ExpiresAt          string                         `yaml:"expires_at" json:"expires_at"`
	Evidence           []CatalogCertificationEvidence `yaml:"evidence" json:"evidence"`
	ProductionObserved any                            `yaml:"production_observed" json:"-"`
	OutcomeValidated   any                            `yaml:"outcome_validated" json:"-"`
}

// CatalogCertificationEvidence points at one immutable static proof artifact.
type CatalogCertificationEvidence struct {
	Kind      string   `yaml:"kind" json:"kind"`
	Reference string   `yaml:"reference" json:"reference,omitempty"`
	Receipt   string   `yaml:"receipt" json:"receipt,omitempty"`
	Digest    string   `yaml:"digest" json:"digest"`
	Families  []string `yaml:"families" json:"families,omitempty"`
}

func normalizeCatalogCertification(certification CatalogCertification) (*CatalogCertification, error) {
	if certification.ProductionObserved != nil || certification.OutcomeValidated != nil {
		return nil, fmt.Errorf("certification catalog cannot declare production_observed or outcome_validated; live owners supply those states")
	}
	certification.Owner = strings.TrimSpace(certification.Owner)
	certification.ReviewedAt = strings.TrimSpace(certification.ReviewedAt)
	certification.ExpiresAt = strings.TrimSpace(certification.ExpiresAt)
	if certification.Owner == "" && certification.ReviewedAt == "" && certification.ExpiresAt == "" && len(certification.Evidence) == 0 {
		return nil, nil
	}
	if certification.Owner == "" {
		return nil, fmt.Errorf("certification owner is required")
	}
	reviewedAt, err := parseCertificationTime("reviewed_at", certification.ReviewedAt)
	if err != nil {
		return nil, err
	}
	expiresAt, err := parseCertificationTime("expires_at", certification.ExpiresAt)
	if err != nil {
		return nil, err
	}
	if !expiresAt.After(reviewedAt) {
		return nil, fmt.Errorf("certification expires_at must be after reviewed_at")
	}
	if len(certification.Evidence) == 0 {
		return nil, fmt.Errorf("certification evidence is required")
	}
	normalized := make([]CatalogCertificationEvidence, 0, len(certification.Evidence))
	seen := map[string]struct{}{}
	for index, evidence := range certification.Evidence {
		evidence.Kind = strings.TrimSpace(evidence.Kind)
		evidence.Reference = strings.TrimSpace(evidence.Reference)
		evidence.Receipt = strings.TrimSpace(evidence.Receipt)
		evidence.Digest = strings.ToLower(strings.TrimSpace(evidence.Digest))
		evidence.Families = normalizeCatalogStringList(evidence.Families)
		switch evidence.Kind {
		case CertificationEvidenceProviderSpec, CertificationEvidenceProviderDocumentation:
			if evidence.Reference == "" || evidence.Receipt != "" {
				return nil, fmt.Errorf("certification evidence[%d] %s requires reference and forbids receipt", index, evidence.Kind)
			}
		case CertificationEvidenceSandboxContract, CertificationEvidenceRecordedReplay:
			if evidence.Receipt == "" || evidence.Reference != "" {
				return nil, fmt.Errorf("certification evidence[%d] %s requires receipt and forbids reference", index, evidence.Kind)
			}
		default:
			return nil, fmt.Errorf("certification evidence[%d] kind %q is not supported", index, evidence.Kind)
		}
		if !validCertificationDigest(evidence.Digest) {
			return nil, fmt.Errorf("certification evidence[%d] digest must be sha256 followed by 64 lowercase hexadecimal characters", index)
		}
		key := evidence.Kind + "\x00" + evidence.Reference + "\x00" + evidence.Receipt + "\x00" + evidence.Digest
		if _, ok := seen[key]; ok {
			return nil, fmt.Errorf("duplicate certification evidence[%d]", index)
		}
		seen[key] = struct{}{}
		normalized = append(normalized, evidence)
	}
	sort.SliceStable(normalized, func(i, j int) bool {
		if normalized[i].Kind != normalized[j].Kind {
			return normalized[i].Kind < normalized[j].Kind
		}
		if normalized[i].Reference != normalized[j].Reference {
			return normalized[i].Reference < normalized[j].Reference
		}
		return normalized[i].Receipt < normalized[j].Receipt
	})
	certification.ReviewedAt = reviewedAt.UTC().Format(time.RFC3339)
	certification.ExpiresAt = expiresAt.UTC().Format(time.RFC3339)
	certification.Evidence = normalized
	return &certification, nil
}

func parseCertificationTime(field, value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, fmt.Errorf("certification %s is required", field)
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("certification %s must be RFC3339: %w", field, err)
	}
	return parsed.UTC(), nil
}

func validCertificationDigest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 {
		return false
	}
	for _, char := range strings.TrimPrefix(value, "sha256:") {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

func registerCatalogCertification(sourceID string, certification *CatalogCertification) {
	sourceID = strings.TrimSpace(sourceID)
	if sourceID == "" {
		return
	}
	if certification == nil {
		catalogCertifications.Delete(sourceID)
		return
	}
	catalogCertifications.Store(sourceID, cloneCatalogCertification(*certification))
}

// CatalogCertificationForSource returns normalized static proof metadata for a
// loaded source catalog.
func CatalogCertificationForSource(sourceID string) (CatalogCertification, bool) {
	value, ok := catalogCertifications.Load(strings.TrimSpace(sourceID))
	if !ok {
		return CatalogCertification{}, false
	}
	certification, ok := value.(CatalogCertification)
	if !ok {
		return CatalogCertification{}, false
	}
	return cloneCatalogCertification(certification), true
}

func cloneCatalogCertification(certification CatalogCertification) CatalogCertification {
	cloned := certification
	cloned.Evidence = make([]CatalogCertificationEvidence, len(certification.Evidence))
	for index, evidence := range certification.Evidence {
		cloned.Evidence[index] = evidence
		cloned.Evidence[index].Families = append([]string(nil), evidence.Families...)
	}
	return cloned
}

func cloneCatalogCertificationPtr(certification *CatalogCertification) *CatalogCertification {
	if certification == nil {
		return nil
	}
	cloned := cloneCatalogCertification(*certification)
	return &cloned
}
