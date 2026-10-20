package compliance

import (
	"errors"
	"fmt"
	"strings"
)

// ErrUnknownFramework reports a framework selection that does not name an
// active built-in framework.
var ErrUnknownFramework = errors.New("unknown compliance framework")

// DefaultEnabledFrameworkNames is the selection a tenant measures against until
// it saves its own: the broad SaaS audit baseline, the ISO management standard,
// and the AWS configuration benchmark most CSPM rules map to.
var DefaultEnabledFrameworkNames = []string{
	"SOC 2",
	"ISO 27001:2022",
	"CIS AWS Foundations Benchmark v2.0",
}

// ResolveEnabledFrameworks canonicalizes a requested framework selection to
// catalog names, in catalog order and without duplicates. Each entry may be a
// framework name or id, matched case-insensitively. Upcoming frameworks are
// rejected because no rules map to them yet.
func ResolveEnabledFrameworks(catalog ControlCatalog, requested []string) ([]string, error) {
	byKey := make(map[string]int, len(catalog.Frameworks)*2)
	for index, framework := range catalog.Frameworks {
		for _, key := range []string{framework.Name, framework.ID} {
			if normalized := strings.ToLower(strings.TrimSpace(key)); normalized != "" {
				byKey[normalized] = index
			}
		}
	}
	selected := make(map[int]struct{}, len(requested))
	for _, value := range requested {
		key := strings.ToLower(strings.TrimSpace(value))
		if key == "" {
			continue
		}
		index, ok := byKey[key]
		if !ok {
			return nil, fmt.Errorf("%w: %q", ErrUnknownFramework, strings.TrimSpace(value))
		}
		framework := catalog.Frameworks[index]
		if normalizeFrameworkLifecycle(framework.Lifecycle) == FrameworkLifecycleUpcoming {
			return nil, fmt.Errorf("%w: %q is not available yet", ErrUnknownFramework, strings.TrimSpace(framework.Name))
		}
		selected[index] = struct{}{}
	}
	names := make([]string, 0, len(selected))
	for index, framework := range catalog.Frameworks {
		if _, ok := selected[index]; ok {
			names = append(names, strings.TrimSpace(framework.Name))
		}
	}
	return names, nil
}
