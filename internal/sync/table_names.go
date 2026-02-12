package sync

import "sort"

// SupportedTableNames returns all table names supported by native sync engines.
func SupportedTableNames() []string {
	nameSet := make(map[string]struct{})
	add := func(name string) {
		if name == "" {
			return
		}
		nameSet[name] = struct{}{}
	}

	addTables := func(tables []TableSpec) {
		for _, table := range tables {
			add(table.Name)
		}
	}

	addGCPTables := func(tables []GCPTableSpec) {
		for _, table := range tables {
			add(table.Name)
		}
	}

	addAzureTables := func(tables []AzureTableSpec) {
		for _, table := range tables {
			add(table.Name)
		}
	}

	addK8sTables := func(tables []K8sTableSpec) {
		for _, table := range tables {
			add(table.Name)
		}
	}

	addTables((&SyncEngine{}).getAWSTables())
	addGCPTables((&GCPSyncEngine{}).getGCPTables())
	addAzureTables((&AzureSyncEngine{}).getAzureTables())
	addK8sTables((&K8sSyncEngine{}).getK8sTables())

	for _, tableName := range GCPAssetTypes {
		add(tableName)
	}

	names := make([]string, 0, len(nameSet))
	for name := range nameSet {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
