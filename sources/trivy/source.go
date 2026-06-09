package trivy

import (
	internal "github.com/writer/cerebro/sources/internal/trivy"
)

// Source reads offline Trivy JSON reports.
type Source = internal.Source

// New constructs the Trivy report source.
func New() (*Source, error) { return internal.New() }
