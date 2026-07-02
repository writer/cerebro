package kolide

import "github.com/writer/cerebro/sources/internal/jsonapi"

type Source struct {
	*jsonapi.Source
}

func New() (*Source, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, err
	}
	inner, err := jsonapi.New(spec, jsonapi.Options{
		SourceID:        sourceID,
		DefaultBaseURL:  defaultBaseURL,
		DefaultFamily:   defaultFamily,
		RequireTenantID: true,
		TokenScheme:     "Bearer",
		StaticHeaders:   map[string]string{"X-Kolide-Api-Version": defaultAPIVersion},
		RecordFilters: map[string]jsonapi.RecordFilter{
			familyVulnerability: jsonapi.RecordFilterAnyPrefixOrNonEmpty(
				[]string{"cve_id", "value.cve_id", "value.cve", "issue_value", "ghsa_id", "value.ghsa_id"},
				[]string{"advisory_id", "value.advisory_id"},
				"CVE-", "GHSA-",
			),
		},
		Families: families(),
	})
	if err != nil {
		return nil, err
	}
	return &Source{Source: inner}, nil
}

func (s *Source) allowLoopbackForTest() {
	if s != nil && s.Source != nil {
		s.AllowLoopbackBaseURL = true
	}
}
