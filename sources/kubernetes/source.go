package kubernetes

import (
	internal "github.com/writer/cerebro/sources/internal/kubernetes"
)

// Source is the Kubernetes inventory source.
type Source = internal.Source

// New constructs the Kubernetes source.
func New() (*Source, error) { return internal.New() }
