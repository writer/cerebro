package boot

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"

	"golang.org/x/sync/errgroup"
)

type NamedSubsystem interface {
	Name() string
}

type InitSubsystem interface {
	NamedSubsystem
	Init(context.Context) error
}

type StartSubsystem interface {
	NamedSubsystem
	Start(context.Context) error
}

type CloseSubsystem interface {
	NamedSubsystem
	Close(context.Context) error
}

type InitStartSubsystem interface {
	InitSubsystem
	StartSubsystem
}

type LifecycleSubsystem struct {
	SubsystemName string
	Dependencies  []string
	InitFunc      func(context.Context) error
	StartFunc     func(context.Context) error
	CloseFunc     func(context.Context) error
}

type LifecycleAction string

const (
	LifecycleActionInit  LifecycleAction = "init"
	LifecycleActionStart LifecycleAction = "start"
)

type LifecycleStage struct {
	Phase        string
	Action       LifecycleAction
	Subsystems   []LifecycleSubsystem
	PreSatisfied []string
}

type LifecycleStageReport struct {
	Phase     string
	Action    string
	Waves     [][]string
	Succeeded []string
}

type LifecycleExecutionReport struct {
	Stages []LifecycleStageReport
	Closed []string
}

func (s LifecycleSubsystem) Name() string {
	name := strings.TrimSpace(s.SubsystemName)
	if name == "" {
		return "subsystem"
	}
	return name
}

func (s LifecycleSubsystem) Requires() []string {
	if len(s.Dependencies) == 0 {
		return nil
	}
	return append([]string(nil), s.Dependencies...)
}

func (s LifecycleSubsystem) Init(ctx context.Context) error {
	if s.InitFunc == nil {
		return nil
	}
	return s.InitFunc(ctx)
}

func (s LifecycleSubsystem) Start(ctx context.Context) error {
	if s.StartFunc == nil {
		return nil
	}
	return s.StartFunc(ctx)
}

func (s LifecycleSubsystem) Close(ctx context.Context) error {
	if s.CloseFunc == nil {
		return nil
	}
	return s.CloseFunc(ctx)
}

func (a LifecycleAction) String() string {
	action := strings.TrimSpace(string(a))
	if action == "" {
		return "lifecycle"
	}
	return action
}

func (a LifecycleAction) run(ctx context.Context, subsystem LifecycleSubsystem) error {
	switch a {
	case LifecycleActionInit:
		return subsystem.Init(ctx)
	case LifecycleActionStart:
		return subsystem.Start(ctx)
	default:
		return nil
	}
}

func runLifecycleErrorStep(phase, name string, fn func() error) (err error) {
	phase = strings.TrimSpace(phase)
	if phase == "" {
		phase = "lifecycle"
	}
	name = strings.TrimSpace(name)
	if name == "" {
		name = "subsystem"
	}
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%s %s panic: %v", name, phase, r)
		}
	}()
	if fn == nil {
		return nil
	}
	return fn()
}

func BuildSubsystemWaves(subsystems []LifecycleSubsystem, preSatisfied ...string) ([][]LifecycleSubsystem, error) {
	if len(subsystems) == 0 {
		return nil, nil
	}

	specs := make(map[string]LifecycleSubsystem, len(subsystems))
	order := make(map[string]int, len(subsystems))
	dependents := make(map[string][]string, len(subsystems))
	indegree := make(map[string]int, len(subsystems))
	satisfied := make(map[string]struct{}, len(preSatisfied))

	for _, name := range preSatisfied {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		satisfied[name] = struct{}{}
	}

	for idx, subsystem := range subsystems {
		name := subsystem.Name()
		if _, exists := specs[name]; exists {
			return nil, fmt.Errorf("duplicate subsystem %q", name)
		}
		specs[name] = subsystem
		order[name] = idx
		indegree[name] = 0
	}

	for _, subsystem := range subsystems {
		name := subsystem.Name()
		for _, dep := range normalizeLifecycleDependencies(subsystem.Requires()) {
			if dep == name {
				return nil, fmt.Errorf("subsystem %q cannot require itself", name)
			}
			if _, ok := specs[dep]; ok {
				dependents[dep] = append(dependents[dep], name)
				indegree[name]++
				continue
			}
			if _, ok := satisfied[dep]; ok {
				continue
			}
			return nil, fmt.Errorf("subsystem %q requires unknown dependency %q", name, dep)
		}
	}

	remaining := make(map[string]struct{}, len(subsystems))
	for name := range specs {
		remaining[name] = struct{}{}
	}

	ready := orderedReadySubsystems(remaining, indegree, order)
	waves := make([][]LifecycleSubsystem, 0, len(subsystems))
	for len(ready) > 0 {
		wave := make([]LifecycleSubsystem, 0, len(ready))
		nextCandidates := make(map[string]struct{})
		for _, name := range ready {
			delete(remaining, name)
			wave = append(wave, specs[name])
			for _, dependent := range dependents[name] {
				indegree[dependent]--
				if indegree[dependent] == 0 {
					if _, ok := remaining[dependent]; ok {
						nextCandidates[dependent] = struct{}{}
					}
				}
			}
		}
		waves = append(waves, wave)
		ready = orderedReadyCandidateNames(nextCandidates, order)
	}

	if len(remaining) > 0 {
		names := orderedReadyCandidateNames(remaining, order)
		return nil, fmt.Errorf("subsystem dependency cycle: %s", strings.Join(names, ", "))
	}

	return waves, nil
}

func ExecuteLifecycleStages(ctx context.Context, logger *slog.Logger, stages ...LifecycleStage) (LifecycleExecutionReport, error) {
	report := LifecycleExecutionReport{}
	seenClosers := make(map[string]struct{})
	successfulClosers := make([]LifecycleSubsystem, 0)

	for _, stage := range stages {
		stageReport, closers, err := runLifecycleStage(ctx, logger, stage)
		report.Stages = append(report.Stages, stageReport)
		for _, subsystem := range closers {
			if subsystem.CloseFunc == nil {
				continue
			}
			name := subsystem.Name()
			if _, ok := seenClosers[name]; ok {
				continue
			}
			seenClosers[name] = struct{}{}
			successfulClosers = append(successfulClosers, subsystem)
		}
		if err != nil {
			closed, closeErrs := closeLifecycleSubsystems(ctx, successfulClosers)
			report.Closed = closed
			if len(closeErrs) > 0 {
				return report, errors.Join(append([]error{err}, closeErrs...)...)
			}
			return report, err
		}
	}

	return report, nil
}

func runLifecycleStage(ctx context.Context, logger *slog.Logger, stage LifecycleStage) (LifecycleStageReport, []LifecycleSubsystem, error) {
	report := LifecycleStageReport{
		Phase:  strings.TrimSpace(stage.Phase),
		Action: stage.Action.String(),
	}

	waves, err := BuildSubsystemWaves(stage.Subsystems, stage.PreSatisfied...)
	if err != nil {
		return report, nil, err
	}
	report.Waves = subsystemWaveNames(waves)
	logLifecycleStagePlan(logger, stage, report.Waves)

	successful := make([]LifecycleSubsystem, 0, len(stage.Subsystems))
	for _, wave := range waves {
		names, subsystems, err := runLifecycleWave(ctx, stage.Action, wave)
		report.Succeeded = append(report.Succeeded, names...)
		successful = append(successful, subsystems...)
		if err != nil {
			return report, successful, err
		}
	}

	return report, successful, nil
}

func runLifecycleWave(ctx context.Context, action LifecycleAction, wave []LifecycleSubsystem) ([]string, []LifecycleSubsystem, error) {
	if len(wave) == 0 {
		return nil, nil, nil
	}

	type success struct {
		index     int
		subsystem LifecycleSubsystem
	}

	var (
		mu        sync.Mutex
		successes []success
	)

	g, gctx := errgroup.WithContext(ctx)
	for idx, subsystem := range wave {
		idx := idx
		subsystem := subsystem
		g.Go(func() error {
			err := runLifecycleErrorStep(action.String(), subsystem.Name(), func() error {
				return action.run(gctx, subsystem)
			})
			if err == nil {
				mu.Lock()
				successes = append(successes, success{index: idx, subsystem: subsystem})
				mu.Unlock()
			}
			return err
		})
	}

	err := g.Wait()
	sort.Slice(successes, func(i, j int) bool {
		return successes[i].index < successes[j].index
	})

	names := make([]string, 0, len(successes))
	subsystems := make([]LifecycleSubsystem, 0, len(successes))
	for _, success := range successes {
		names = append(names, success.subsystem.Name())
		subsystems = append(subsystems, success.subsystem)
	}
	return names, subsystems, err
}

func closeLifecycleSubsystems(ctx context.Context, subsystems []LifecycleSubsystem) ([]string, []error) {
	if len(subsystems) == 0 {
		return nil, nil
	}

	ordered := make([]CloseSubsystem, 0, len(subsystems))
	closed := make([]string, 0, len(subsystems))
	for i := len(subsystems) - 1; i >= 0; i-- {
		subsystem := subsystems[i]
		if subsystem.CloseFunc == nil {
			continue
		}
		ordered = append(ordered, subsystem)
		closed = append(closed, subsystem.Name())
	}
	if len(ordered) == 0 {
		return nil, nil
	}
	return closed, RunSubsystemCloseSequentially(ctx, ordered...)
}

func logLifecycleStagePlan(logger *slog.Logger, stage LifecycleStage, waves [][]string) {
	if logger == nil || !logger.Enabled(context.Background(), slog.LevelDebug) {
		return
	}
	logger.Debug("computed subsystem lifecycle plan",
		"phase", strings.TrimSpace(stage.Phase),
		"action", stage.Action.String(),
		"pre_satisfied", normalizeLifecycleDependencies(stage.PreSatisfied),
		"waves", waves,
	)
}

func subsystemWaveNames(waves [][]LifecycleSubsystem) [][]string {
	if len(waves) == 0 {
		return nil
	}
	result := make([][]string, 0, len(waves))
	for _, wave := range waves {
		names := make([]string, 0, len(wave))
		for _, subsystem := range wave {
			names = append(names, subsystem.Name())
		}
		result = append(result, names)
	}
	return result
}

func orderedReadySubsystems(remaining map[string]struct{}, indegree map[string]int, order map[string]int) []string {
	candidates := make(map[string]struct{})
	for name := range remaining {
		if indegree[name] == 0 {
			candidates[name] = struct{}{}
		}
	}
	return orderedReadyCandidateNames(candidates, order)
}

func orderedReadyCandidateNames(candidates map[string]struct{}, order map[string]int) []string {
	names := make([]string, 0, len(candidates))
	for name := range candidates {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool {
		return order[names[i]] < order[names[j]]
	})
	return names
}

func normalizeLifecycleDependencies(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}
	return normalized
}

func RunSubsystemInitConcurrently(ctx context.Context, subsystems ...InitSubsystem) error {
	if len(subsystems) == 0 {
		return nil
	}

	g, gctx := errgroup.WithContext(ctx)
	for _, subsystem := range subsystems {
		subsystem := subsystem
		if subsystem == nil {
			continue
		}
		g.Go(func() error {
			return runLifecycleErrorStep("init", subsystem.Name(), func() error {
				return subsystem.Init(gctx)
			})
		})
	}
	return g.Wait()
}

func RunSubsystemStartSequentially(ctx context.Context, subsystems ...StartSubsystem) error {
	for _, subsystem := range subsystems {
		if subsystem == nil {
			continue
		}
		if err := runLifecycleErrorStep("start", subsystem.Name(), func() error {
			return subsystem.Start(ctx)
		}); err != nil {
			return err
		}
	}
	return nil
}

func RunSubsystemCloseSequentially(ctx context.Context, subsystems ...CloseSubsystem) []error {
	if len(subsystems) == 0 {
		return nil
	}

	var errs []error
	for _, subsystem := range subsystems {
		if subsystem == nil {
			continue
		}
		if err := runLifecycleErrorStep("close", subsystem.Name(), func() error {
			return subsystem.Close(ctx)
		}); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}
