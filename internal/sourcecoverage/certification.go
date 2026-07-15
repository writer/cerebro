package sourcecoverage

import "strings"

// RuntimeCertificationConfigKey is the runtime-only configuration key used by
// deployment adapters. Certification facts do not belong in public catalogs.
const RuntimeCertificationConfigKey = "__cerebro_runtime_certification_tier"

// CertificationTier is a bounded statement of how a source implementation was validated.
type CertificationTier string

const (
	CertificationUnknown          CertificationTier = "unknown"
	CertificationCatalogDeclared  CertificationTier = "catalog_declared"
	CertificationFixtureValidated CertificationTier = "fixture_validated"
	CertificationLiveValidated    CertificationTier = "live_validated"
)

// ParseCertificationTier normalizes a bounded tier. Missing values are unknown;
// unrecognized values fail closed and are not promoted to a known tier.
func ParseCertificationTier(value string) (CertificationTier, bool) {
	tier := CertificationTier(strings.ToLower(strings.TrimSpace(value)))
	if tier == "" {
		return CertificationUnknown, true
	}
	switch tier {
	case CertificationUnknown, CertificationCatalogDeclared, CertificationFixtureValidated, CertificationLiveValidated:
		return tier, true
	default:
		return CertificationUnknown, false
	}
}

// BoundedCertificationTier returns unknown for an unrecognized declaration.
func BoundedCertificationTier(value CertificationTier) CertificationTier {
	tier, ok := ParseCertificationTier(string(value))
	if !ok {
		return CertificationUnknown
	}
	return tier
}

// CertificationMeetsMinimum reports whether an actual tier satisfies a required tier.
// Unknown actual trust never satisfies a known minimum.
func CertificationMeetsMinimum(actual, minimum CertificationTier) bool {
	actual, actualOK := ParseCertificationTier(string(actual))
	minimum, minimumOK := ParseCertificationTier(string(minimum))
	if !actualOK || !minimumOK {
		return false
	}
	if minimum == CertificationUnknown {
		return true
	}
	if actual == CertificationUnknown {
		return false
	}
	return certificationRank(actual) >= certificationRank(minimum)
}

func certificationRank(value CertificationTier) int {
	switch value {
	case CertificationCatalogDeclared:
		return 1
	case CertificationFixtureValidated:
		return 2
	case CertificationLiveValidated:
		return 3
	default:
		return 0
	}
}
