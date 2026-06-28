package catalogruntime

import (
	"context"

	"github.com/writer/cerebro/internal/connectorcatalog"
	"github.com/writer/cerebro/internal/connectordefinitions"
	internal "github.com/writer/cerebro/sources/internal/catalogruntime"
)

// Source adapts a normalized connector catalog definition into a runnable JSON API source.
type Source = internal.Source

type ValidationOptions = internal.ValidationOptions

type FixtureReadResult = internal.FixtureReadResult

// New creates a runnable source from a connector catalog entry.
func New(entry connectorcatalog.Entry) (*Source, error) {
	return internal.New(entry)
}

// NewDefinition creates a runnable source from a connector definition.
func NewDefinition(definition connectordefinitions.Definition) (*Source, error) {
	return internal.NewDefinition(definition)
}

func NewDefinitionWithValidationOptions(definition connectordefinitions.Definition, options ValidationOptions) (*Source, error) {
	return internal.NewDefinitionWithValidationOptions(definition, options)
}

func ReadDefinitionFixture(ctx context.Context, definition connectordefinitions.Definition, familyID string, body []byte) (FixtureReadResult, error) {
	return internal.ReadDefinitionFixture(ctx, definition, familyID, body)
}
