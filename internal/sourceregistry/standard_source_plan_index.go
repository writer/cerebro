package sourceregistry

import (
	"context"
	_ "embed"
	"fmt"
	"strings"

	"github.com/writer/cerebro/internal/sourcecdk"
	sourcecatalogs "github.com/writer/cerebro/sources"
)

var errAuthoritativeRuntimeRequired = fmt.Errorf("source execution requires the authoritative runtime")

//go:embed standard_source_plan_index.txt
var standardSourcePlanIndex string

func loadStandardSourcePlans() (map[string][]string, error) {
	lines := strings.Split(strings.TrimSuffix(standardSourcePlanIndex, "\n"), "\n")
	if len(lines) < 2 || lines[0] != "standard-source-plan-index/v1" {
		return nil, fmt.Errorf("unsupported standard source plan index")
	}
	plans := make(map[string][]string, len(lines)-1)
	for _, line := range lines[1:] {
		columns := strings.Split(line, "\t")
		if len(columns) != 2 || columns[0] == "" || columns[1] == "" {
			return nil, fmt.Errorf("invalid standard source plan")
		}
		if _, duplicate := plans[columns[0]]; duplicate {
			return nil, fmt.Errorf("duplicate standard source plan")
		}
		plans[columns[0]] = strings.Split(columns[1], ",")
	}
	return plans, nil
}

func newMetadataOnlyCatalogSource(sourceID string, payload []byte) (sourcecdk.Source, error) {
	if len(payload) == 0 {
		var err error
		payload, err = sourcecatalogs.BuiltinCatalog(sourceID)
		if err != nil {
			return nil, err
		}
	}
	catalog, err := sourcecdk.LoadSourceCatalog(payload)
	if err != nil {
		return nil, err
	}
	if catalog.Spec == nil || catalog.Spec.GetId() != sourceID {
		return nil, fmt.Errorf("metadata-only source catalog id differs from %q", sourceID)
	}
	return sourcecdk.NewFixtureSource(sourcecdk.FixtureSourceOptions{
		Spec:      catalog.Spec,
		Contracts: catalog.EventContracts,
		Check: func(_ context.Context, cfg sourcecdk.Config) error {
			return sourcecdk.WrapSourceError(sourcecdk.ErrorKindProvider, sourceID, sourcecdk.ConfigValue(cfg, "family"), errAuthoritativeRuntimeRequired)
		},
	})
}
