package sync

import (
	"sort"
	"strings"
)

func normalizeTableFilter(tables []string) map[string]struct{} {
	if len(tables) == 0 {
		return nil
	}

	filter := make(map[string]struct{})
	for _, table := range tables {
		trimmed := strings.TrimSpace(strings.ToLower(table))
		if trimmed == "" {
			continue
		}
		filter[trimmed] = struct{}{}
	}
	if len(filter) == 0 {
		return nil
	}
	return filter
}

func filterNames(filter map[string]struct{}) []string {
	if len(filter) == 0 {
		return nil
	}

	names := make([]string, 0, len(filter))
	for name := range filter {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func matchesFilter(filter map[string]struct{}, names ...string) bool {
	if len(filter) == 0 {
		return true
	}
	for _, name := range names {
		if name == "" {
			continue
		}
		if _, ok := filter[strings.ToLower(name)]; ok {
			return true
		}
	}
	return false
}

func filterTableSpecs(tables []TableSpec, filter map[string]struct{}) []TableSpec {
	if len(filter) == 0 {
		return tables
	}
	filtered := make([]TableSpec, 0, len(tables))
	for _, table := range tables {
		if matchesFilter(filter, table.Name) {
			filtered = append(filtered, table)
		}
	}
	return filtered
}

func filterGCPTables(tables []GCPTableSpec, filter map[string]struct{}) []GCPTableSpec {
	if len(filter) == 0 {
		return tables
	}
	filtered := make([]GCPTableSpec, 0, len(tables))
	for _, table := range tables {
		if matchesFilter(filter, table.Name) {
			filtered = append(filtered, table)
		}
	}
	return filtered
}

func filterAzureTables(tables []AzureTableSpec, filter map[string]struct{}) []AzureTableSpec {
	if len(filter) == 0 {
		return tables
	}
	filtered := make([]AzureTableSpec, 0, len(tables))
	for _, table := range tables {
		if matchesFilter(filter, table.Name) {
			filtered = append(filtered, table)
		}
	}
	return filtered
}

func filterK8sTables(tables []K8sTableSpec, filter map[string]struct{}) []K8sTableSpec {
	if len(filter) == 0 {
		return tables
	}
	filtered := make([]K8sTableSpec, 0, len(tables))
	for _, table := range tables {
		if matchesFilter(filter, table.Name) {
			filtered = append(filtered, table)
		}
	}
	return filtered
}
