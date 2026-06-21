package sourcecdk

import (
	"context"
	"fmt"
	"sort"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

// FixtureSuiteT is the subset of testing.TB used by RunFixtureSuite.
type FixtureSuiteT interface {
	Helper()
	Fatalf(string, ...any)
}

// FixtureSuiteOptions configures a reusable source contract test.
type FixtureSuiteOptions struct {
	Source          Source
	Config          Config
	FamilyConfigs   map[string]Config
	MaxPages        int
	RequireDiscover bool
}

// RunFixtureSuite exercises Check, Discover, Read pagination, and event
// contracts for deterministic source fixtures.
func RunFixtureSuite(t FixtureSuiteT, ctx context.Context, options FixtureSuiteOptions) {
	t.Helper()
	if err := ValidateFixtureSuite(ctx, options); err != nil {
		t.Fatalf("source fixture suite failed: %v", err)
	}
}

// ValidateFixtureSuite is the non-testing implementation behind RunFixtureSuite.
func ValidateFixtureSuite(ctx context.Context, options FixtureSuiteOptions) error {
	if sourceIsNil(options.Source) {
		return fmt.Errorf("source is required")
	}
	configs := []Config{options.Config}
	if len(options.FamilyConfigs) > 0 {
		configs = configs[:0]
		families := make([]string, 0, len(options.FamilyConfigs))
		for family := range options.FamilyConfigs {
			families = append(families, family)
		}
		sort.Strings(families)
		for _, family := range families {
			configs = append(configs, options.FamilyConfigs[family])
		}
	}
	maxPages := options.MaxPages
	if maxPages <= 0 {
		maxPages = 100
	}
	for _, cfg := range configs {
		if err := options.Source.Check(ctx, cfg); err != nil {
			return fmt.Errorf("check: %w", err)
		}
		if options.RequireDiscover {
			urns, err := options.Source.Discover(ctx, cfg)
			if err != nil {
				return fmt.Errorf("discover: %w", err)
			}
			for _, urn := range urns {
				if _, err := ParseURN(urn.String()); err != nil {
					return fmt.Errorf("discover urn %q: %w", urn, err)
				}
			}
		}
		var cursor *cerebrov1.SourceCursor
		for page := 0; page < maxPages; page++ {
			pull, err := options.Source.Read(ctx, cfg, cursor)
			if err != nil {
				return fmt.Errorf("read page %d: %w", page+1, err)
			}
			for _, event := range pull.Events {
				if err := ValidateEventEnvelopeWithContracts(event, fixtureSuiteContracts(options.Source)); err != nil {
					return fmt.Errorf("validate event %q: %w", event.GetId(), err)
				}
			}
			if pull.NextCursor == nil {
				break
			}
			if cursor != nil && cursor.GetOpaque() == pull.NextCursor.GetOpaque() {
				return fmt.Errorf("read page %d returned same next cursor %q", page+1, pull.NextCursor.GetOpaque())
			}
			cursor = pull.NextCursor
			if page == maxPages-1 {
				return fmt.Errorf("read exceeded max pages %d", maxPages)
			}
		}
	}
	return nil
}

func fixtureSuiteContracts(source Source) []EventContract {
	provider, ok := source.(EventContractProvider)
	if !ok {
		return nil
	}
	return provider.EventContracts()
}
