package sync

// SupportedTableNames returns all table names supported by native sync engines.
func SupportedTableNames() []string {
	RegisterAllTables()
	return GlobalTableRegistry().Names()
}
