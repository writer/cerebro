package sourcecdk

import (
	"context"
	"fmt"
	"sort"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

// Family groups source behavior for one configured event family.
type Family[S any] struct {
	Name     string
	Check    func(context.Context, S) error
	Discover func(context.Context, S) ([]URN, error)
	Read     func(context.Context, S, *cerebrov1.SourceCursor) (Pull, error)
}

// FamilyEngine dispatches source operations to table-driven families.
type FamilyEngine[S any] struct {
	parse    func(Config) (S, error)
	family   func(S) string
	families map[string]Family[S]
}

// NewFamilyEngine constructs a source family dispatcher.
func NewFamilyEngine[S any](parse func(Config) (S, error), family func(S) string, families ...Family[S]) (*FamilyEngine[S], error) {
	if parse == nil {
		return nil, fmt.Errorf("family settings parser is required")
	}
	if family == nil {
		return nil, fmt.Errorf("family name resolver is required")
	}
	engine := &FamilyEngine[S]{
		parse:    parse,
		family:   family,
		families: make(map[string]Family[S], len(families)),
	}
	for _, candidate := range families {
		name := strings.TrimSpace(candidate.Name)
		if name == "" {
			return nil, fmt.Errorf("family name is required")
		}
		if _, ok := engine.families[name]; ok {
			return nil, fmt.Errorf("duplicate family %q", name)
		}
		engine.families[name] = candidate
	}
	return engine, nil
}

// Names returns sorted family names.
func (e *FamilyEngine[S]) Names() []string {
	if e == nil {
		return nil
	}
	names := make([]string, 0, len(e.families))
	for name := range e.families {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Check validates the configured family.
func (e *FamilyEngine[S]) Check(ctx context.Context, cfg Config) error {
	family, settings, err := e.resolve(cfg)
	if err != nil {
		return err
	}
	if family.Check == nil {
		return nil
	}
	return family.Check(ctx, settings)
}

// Discover returns URNs for the configured family.
func (e *FamilyEngine[S]) Discover(ctx context.Context, cfg Config) ([]URN, error) {
	family, settings, err := e.resolve(cfg)
	if err != nil {
		return nil, err
	}
	if family.Discover == nil {
		return nil, nil
	}
	return family.Discover(ctx, settings)
}

// Read reads one page for the configured family.
func (e *FamilyEngine[S]) Read(ctx context.Context, cfg Config, cursor *cerebrov1.SourceCursor) (Pull, error) {
	family, settings, err := e.resolve(cfg)
	if err != nil {
		return Pull{}, err
	}
	if family.Read == nil {
		return Pull{}, nil
	}
	return family.Read(ctx, settings, cursor)
}

func (e *FamilyEngine[S]) resolve(cfg Config) (Family[S], S, error) {
	var zero S
	if e == nil {
		return Family[S]{}, zero, fmt.Errorf("family engine is required")
	}
	settings, err := e.parse(cfg)
	if err != nil {
		return Family[S]{}, zero, err
	}
	name := strings.TrimSpace(e.family(settings))
	family, ok := e.families[name]
	if !ok {
		return Family[S]{}, zero, fmt.Errorf("unsupported family %q", name)
	}
	return family, settings, nil
}
