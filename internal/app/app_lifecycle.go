package app

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

type namedSubsystem interface {
	Name() string
}

type initSubsystem interface {
	namedSubsystem
	Init(context.Context) error
}

type startSubsystem interface {
	namedSubsystem
	Start(context.Context) error
}

type closeSubsystem interface {
	namedSubsystem
	Close(context.Context) error
}

type lifecycleSubsystem struct {
	name     string
	requires []string
	init     func(context.Context) error
	start    func(context.Context) error
	close    func(context.Context) error
}

type lifecycleAction string

const (
	lifecycleActionInit  lifecycleAction = "init"
	lifecycleActionStart lifecycleAction = "start"
)

type lifecycleStage struct {
	phase        string
	action       lifecycleAction
	subsystems   []lifecycleSubsystem
	preSatisfied []string
}

type lifecycleStageReport struct {
	Phase     string
	Action    string
	Waves     [][]string
	Succeeded []string
}

type lifecycleExecutionReport struct {
	Stages []lifecycleStageReport
	Closed []string
}

func (s lifecycleSubsystem) Name() string {
	name := strings.TrimSpace(s.name)
	if name == "" {
		return "subsystem"
	}
	return name
}

func (s lifecycleSubsystem) Requires() []string {
	if len(s.requires) == 0 {
		return nil
	}
	return append([]string(nil), s.requires...)
}

func (s lifecycleSubsystem) Init(ctx context.Context) error {
	if s.init == nil {
		return nil
	}
	return s.init(ctx)
}

func (s lifecycleSubsystem) Start(ctx context.Context) error {
	if s.start == nil {
		return nil
	}
	return s.start(ctx)
}

func (s lifecycleSubsystem) Close(ctx context.Context) error {
	if s.close == nil {
		return nil
	}
	return s.close(ctx)
}

func (a lifecycleAction) String() string {
	action := strings.TrimSpace(string(a))
	if action == "" {
		return "lifecycle"
	}
	return action
}

func (a lifecycleAction) run(ctx context.Context, subsystem lifecycleSubsystem) error {
	switch a {
	case lifecycleActionInit:
		return subsystem.Init(ctx)
	case lifecycleActionStart:
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
	return fn()
}

func buildSubsystemWaves(subsystems []lifecycleSubsystem, preSatisfied ...string) ([][]lifecycleSubsystem, error) {
	if len(subsystems) == 0 {
		return nil, nil
	}

	specs := make(map[string]lifecycleSubsystem, len(subsystems))
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
	waves := make([][]lifecycleSubsystem, 0, len(subsystems))
	for len(ready) > 0 {
		wave := make([]lifecycleSubsystem, 0, len(ready))
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

func executeLifecycleStages(ctx context.Context, logger *slog.Logger, stages ...lifecycleStage) (lifecycleExecutionReport, error) {
	report := lifecycleExecutionReport{}
	seenClosers := make(map[string]struct{})
	successfulClosers := make([]lifecycleSubsystem, 0)

	for _, stage := range stages {
		stageReport, closers, err := runLifecycleStage(ctx, logger, stage)
		report.Stages = append(report.Stages, stageReport)
		for _, subsystem := range closers {
			if subsystem.close == nil {
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

func runLifecycleStage(ctx context.Context, logger *slog.Logger, stage lifecycleStage) (lifecycleStageReport, []lifecycleSubsystem, error) {
	report := lifecycleStageReport{
		Phase:  strings.TrimSpace(stage.phase),
		Action: stage.action.String(),
	}

	waves, err := buildSubsystemWaves(stage.subsystems, stage.preSatisfied...)
	if err != nil {
		return report, nil, err
	}
	report.Waves = subsystemWaveNames(waves)
	logLifecycleStagePlan(logger, stage, report.Waves)

	successful := make([]lifecycleSubsystem, 0, len(stage.subsystems))
	for _, wave := range waves {
		names, subsystems, err := runLifecycleWave(ctx, stage.action, wave)
		report.Succeeded = append(report.Succeeded, names...)
		successful = append(successful, subsystems...)
		if err != nil {
			return report, successful, err
		}
	}

	return report, successful, nil
}

func runLifecycleWave(ctx context.Context, action lifecycleAction, wave []lifecycleSubsystem) ([]string, []lifecycleSubsystem, error) {
	if len(wave) == 0 {
		return nil, nil, nil
	}

	type success struct {
		index     int
		subsystem lifecycleSubsystem
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
	subsystems := make([]lifecycleSubsystem, 0, len(successes))
	for _, success := range successes {
		names = append(names, success.subsystem.Name())
		subsystems = append(subsystems, success.subsystem)
	}
	return names, subsystems, err
}

func closeLifecycleSubsystems(ctx context.Context, subsystems []lifecycleSubsystem) ([]string, []error) {
	if len(subsystems) == 0 {
		return nil, nil
	}

	ordered := make([]closeSubsystem, 0, len(subsystems))
	closed := make([]string, 0, len(subsystems))
	for i := len(subsystems) - 1; i >= 0; i-- {
		subsystem := subsystems[i]
		if subsystem.close == nil {
			continue
		}
		ordered = append(ordered, subsystem)
		closed = append(closed, subsystem.Name())
	}
	if len(ordered) == 0 {
		return nil, nil
	}
	return closed, runSubsystemCloseSequentially(ctx, ordered...)
}

func logLifecycleStagePlan(logger *slog.Logger, stage lifecycleStage, waves [][]string) {
	if logger == nil || !logger.Enabled(context.Background(), slog.LevelDebug) {
		return
	}
	logger.Debug("computed subsystem lifecycle plan",
		"phase", strings.TrimSpace(stage.phase),
		"action", stage.action.String(),
		"pre_satisfied", normalizeLifecycleDependencies(stage.preSatisfied),
		"waves", waves,
	)
}

func subsystemWaveNames(waves [][]lifecycleSubsystem) [][]string {
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

func runSubsystemInitConcurrently(ctx context.Context, subsystems ...initSubsystem) error {
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

func runSubsystemInitSequentially(ctx context.Context, subsystems ...initSubsystem) error {
	for _, subsystem := range subsystems {
		if subsystem == nil {
			continue
		}
		if err := runLifecycleErrorStep("init", subsystem.Name(), func() error {
			return subsystem.Init(ctx)
		}); err != nil {
			return err
		}
	}
	return nil
}

func runSubsystemStartSequentially(ctx context.Context, subsystems ...startSubsystem) error {
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

func runSubsystemCloseSequentially(ctx context.Context, subsystems ...closeSubsystem) []error {
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

func initOnlySubsystem(name string, init func(context.Context)) lifecycleSubsystem {
	return lifecycleSubsystem{
		name: name,
		init: func(ctx context.Context) error {
			if init != nil {
				init(ctx)
			}
			return nil
		},
	}
}

func initOnlySubsystemWithDeps(name string, requires []string, init func(context.Context)) lifecycleSubsystem {
	subsystem := initOnlySubsystem(name, init)
	subsystem.requires = normalizeLifecycleDependencies(requires)
	return subsystem
}

func wrapInitSubsystem(subsystem initSubsystem, requires ...string) lifecycleSubsystem {
	if subsystem == nil {
		return lifecycleSubsystem{}
	}
	return lifecycleSubsystem{
		name:     subsystem.Name(),
		requires: normalizeLifecycleDependencies(requires),
		init:     subsystem.Init,
	}
}

func wrapStartSubsystem(subsystem startSubsystem, requires ...string) lifecycleSubsystem {
	if subsystem == nil {
		return lifecycleSubsystem{}
	}
	return lifecycleSubsystem{
		name:     subsystem.Name(),
		requires: normalizeLifecycleDependencies(requires),
		start:    subsystem.Start,
	}
}
