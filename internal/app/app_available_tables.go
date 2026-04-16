package app

func (a *App) SetAvailableTables(tables []string) {
	if a == nil {
		return
	}
	cloned := append([]string(nil), tables...)
	a.availableTablesMu.Lock()
	a.AvailableTables = cloned
	a.availableTablesMu.Unlock()
}

func (a *App) AvailableTablesSnapshot() []string {
	if a == nil {
		return nil
	}
	a.availableTablesMu.RLock()
	defer a.availableTablesMu.RUnlock()
	return append([]string(nil), a.AvailableTables...)
}
