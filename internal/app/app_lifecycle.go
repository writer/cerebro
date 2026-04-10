package app

import (
	"context"
	"fmt"
	"strings"

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
	name  string
	init  func(context.Context) error
	start func(context.Context) error
	close func(context.Context) error
}

func (s lifecycleSubsystem) Name() string {
	name := strings.TrimSpace(s.name)
	if name == "" {
		return "subsystem"
	}
	return name
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
