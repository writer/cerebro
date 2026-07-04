package sourcecdk

import (
	"context"
	"fmt"
	"sort"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/resourcescope"
)

// Family groups source behavior for one configured event family.
type Family[S any] struct {
	Name                 string
	IncrementalWatermark bool
	Check                func(context.Context, S) error
	Discover             func(context.Context, S) ([]URN, error)
	Probe                func(context.Context, S, *cerebrov1.SourceCheckpoint) (ChangeProbe, error)
	ProbeOptions         FamilyFreshnessReadOptions
	ReadWithChange       func(context.Context, S, *cerebrov1.SourceCursor, *cerebrov1.SourceCheckpoint, ChangeProbe) (Pull, error)
	Read                 func(context.Context, S, *cerebrov1.SourceCursor) (Pull, error)
	ReadWithCheckpoint   func(context.Context, S, *cerebrov1.SourceCursor, *cerebrov1.SourceCheckpoint) (Pull, error)
}

// ChangeProbe is an optional cheap pre-read result for families that can test
// whether provider data changed before fetching and projecting the full page.
type ChangeProbe struct {
	Unchanged          bool
	Checkpoint         *cerebrov1.SourceCheckpoint
	ShortCircuitReason PullShortCircuitReason
	ChangedResourceIDs []string
	ChangedURNs        []URN
}

// FamilyEngine dispatches source operations to table-driven families.
type FamilyEngine[S any] struct {
	sourceID string
	parse    func(Config) (S, error)
	family   func(S) string
	families map[string]Family[S]
}

// NewFamilyEngine constructs a source family dispatcher.
func NewFamilyEngine[S any](parse func(Config) (S, error), family func(S) string, families ...Family[S]) (*FamilyEngine[S], error) {
	return NewFamilyEngineWithSourceID("", parse, family, families...)
}

// NewFamilyEngineWithSourceID constructs a source family dispatcher with a source id for scope policy matching.
func NewFamilyEngineWithSourceID[S any](sourceID string, parse func(Config) (S, error), family func(S) string, families ...Family[S]) (*FamilyEngine[S], error) {
	if parse == nil {
		return nil, fmt.Errorf("family settings parser is required")
	}
	if family == nil {
		return nil, fmt.Errorf("family name resolver is required")
	}
	engine := &FamilyEngine[S]{
		sourceID: strings.TrimSpace(sourceID),
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
	family, settings, policy, err := e.resolve(cfg)
	if err != nil {
		return err
	}
	if policy.ExcludesFamily(e.sourceID, family.Name) {
		return nil
	}
	if family.Check == nil {
		return nil
	}
	return family.Check(ctx, settings)
}

// Discover returns URNs for the configured family.
func (e *FamilyEngine[S]) Discover(ctx context.Context, cfg Config) ([]URN, error) {
	family, settings, policy, err := e.resolve(cfg)
	if err != nil {
		return nil, err
	}
	if policy.ExcludesFamily(e.sourceID, family.Name) {
		return nil, nil
	}
	if family.Discover == nil {
		return nil, nil
	}
	return family.Discover(ctx, settings)
}

// Read reads one page for the configured family.
func (e *FamilyEngine[S]) Read(ctx context.Context, cfg Config, cursor *cerebrov1.SourceCursor) (Pull, error) {
	return e.ReadWithCheckpoint(ctx, cfg, cursor, nil)
}

// ReadWithCheckpoint reads one page and lets families short-circuit with a
// cheap provider change probe when they support one.
func (e *FamilyEngine[S]) ReadWithCheckpoint(ctx context.Context, cfg Config, cursor *cerebrov1.SourceCursor, checkpoint *cerebrov1.SourceCheckpoint) (Pull, error) {
	family, settings, policy, err := e.resolve(cfg)
	if err != nil {
		return Pull{}, err
	}
	if policy.ExcludesFamily(e.sourceID, family.Name) {
		return Pull{ShortCircuitReason: PullShortCircuitReasonScopeExcluded}, nil
	}
	readCheckpoint := checkpoint
	activeCursor := strings.TrimSpace(CursorToken(cursor)) != ""
	if family.Probe != nil && e.sourceID != "" {
		readCheckpoint = FamilyFreshnessCheckpointFromCursor(e.sourceID, family.Name, cursor, readCheckpoint)
	}
	if family.Probe != nil && !activeCursor {
		probe, err := family.Probe(ctx, settings, readCheckpoint)
		if err != nil {
			if normalizeFamilyFreshnessProbeErrorMode(family.ProbeOptions.ProbeErrorMode) == FamilyFreshnessProbeErrorFailOpen {
				probe = ChangeProbe{}
			} else {
				return Pull{}, err
			}
		} else {
			probe = applyFamilyFreshnessReadOptions(e.sourceID, family.Name, checkpoint, probe, family.ProbeOptions)
		}
		if probe.Unchanged {
			reason := probe.ShortCircuitReason
			if reason == "" {
				reason = PullShortCircuitReasonNotModified
			}
			return Pull{Checkpoint: probe.Checkpoint, ShortCircuitReason: reason}, nil
		}
		if probe.Checkpoint != nil {
			readCheckpoint = probe.Checkpoint
		}
		if family.ReadWithChange != nil {
			pull, err := family.ReadWithChange(ctx, settings, cursor, readCheckpoint, probe)
			if err != nil {
				return Pull{}, err
			}
			pull = e.applyIncrementalWatermark(family, cursor, readCheckpoint, pull)
			return applyResourceScopePolicy(pull, policy), nil
		}
	}
	if family.ReadWithCheckpoint != nil {
		pull, err := family.ReadWithCheckpoint(ctx, settings, cursor, readCheckpoint)
		if err != nil {
			return Pull{}, err
		}
		return applyResourceScopePolicy(pull, policy), nil
	}
	if family.Read == nil {
		return Pull{}, nil
	}
	pull, err := family.Read(ctx, settings, cursor)
	if err != nil {
		return Pull{}, err
	}
	if family.IncrementalWatermark && e.sourceID != "" {
		pull = e.applyIncrementalWatermark(family, cursor, readCheckpoint, pull)
	}
	return applyResourceScopePolicy(pull, policy), nil
}

func (e *FamilyEngine[S]) applyIncrementalWatermark(family Family[S], cursor *cerebrov1.SourceCursor, checkpoint *cerebrov1.SourceCheckpoint, pull Pull) Pull {
	if !family.IncrementalWatermark || e.sourceID == "" {
		return pull
	}
	readCheckpoint := IncrementalCheckpointForCursor(e.sourceID, family.Name, cursor, checkpoint)
	next := ""
	if pull.NextCursor != nil {
		next = CursorToken(pull.NextCursor)
	}
	pull = IncrementalPullFromEvents(e.sourceID, family.Name, pull.Events, next, readCheckpoint)
	if family.Probe != nil {
		pull = attachFamilyFreshnessToPull(e.sourceID, family.Name, readCheckpoint, pull)
	}
	return pull
}

func attachFamilyFreshnessToPull(source string, family string, checkpoint *cerebrov1.SourceCheckpoint, pull Pull) Pull {
	if checkpoint == nil {
		return pull
	}
	pull.Checkpoint = FamilyFreshnessCheckpointFromCheckpoint(source, family, checkpoint, pull.Checkpoint)
	if pull.NextCursor != nil {
		nextCheckpoint := FamilyFreshnessCheckpointFromCheckpoint(source, family, checkpoint, &cerebrov1.SourceCheckpoint{CursorOpaque: pull.NextCursor.GetOpaque()})
		if nextCheckpoint != nil {
			pull.NextCursor.Opaque = nextCheckpoint.GetCursorOpaque()
		}
	}
	return pull
}

func (e *FamilyEngine[S]) resolve(cfg Config) (Family[S], S, resourcescope.Policy, error) {
	var zero S
	if e == nil {
		return Family[S]{}, zero, resourcescope.Policy{}, fmt.Errorf("family engine is required")
	}
	settings, err := e.parse(cfg)
	if err != nil {
		return Family[S]{}, zero, resourcescope.Policy{}, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	name := strings.TrimSpace(e.family(settings))
	family, ok := e.families[name]
	if !ok {
		return Family[S]{}, zero, resourcescope.Policy{}, fmt.Errorf("%w: unsupported family %q", ErrInvalidConfig, name)
	}
	policy, err := resourcescope.FromConfig(cfg.Values())
	if err != nil {
		return Family[S]{}, zero, resourcescope.Policy{}, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	return family, settings, policy, nil
}
