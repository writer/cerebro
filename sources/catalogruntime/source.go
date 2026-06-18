package catalogruntime

import (
	"github.com/writer/cerebro/internal/connectorcatalog"
	"github.com/writer/cerebro/internal/connectordefinitions"
	internal "github.com/writer/cerebro/sources/internal/catalogruntime"
)

// Source adapts a normalized connector catalog definition into a runnable JSON API source.
type Source = internal.Source

// New creates a runnable source from a connector catalog entry.
func New(entry connectorcatalog.Entry) (*Source, error) {
	return internal.New(entry)
}

// NewDefinition creates a runnable source from a connector definition.
func NewDefinition(definition connectordefinitions.Definition) (*Source, error) {
	return internal.NewDefinition(definition)
}
