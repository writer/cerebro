package pipeline

import (
	"context"
	"hash/fnv"
	"sync"
)

type TransformFunc[I, O any] func(context.Context, I) (O, bool)
type KeyFunc[T any] func(T) string

type StageConfig[I, O any] struct {
	Workers   int
	Buffer    int
	Key       KeyFunc[I]
	Transform TransformFunc[I, O]
}

type Stage[O any] struct {
	out          chan O
	done         chan struct{}
	backpressure *BackpressureSignal
}

func StartStage[I, O any](ctx context.Context, in <-chan I, cfg StageConfig[I, O]) *Stage[O] {
	workers := cfg.Workers
	if workers <= 0 {
		workers = 1
	}
	buffer := cfg.Buffer
	if buffer <= 0 {
		buffer = 1
	}

	stage := &Stage[O]{
		out:          make(chan O, buffer),
		done:         make(chan struct{}),
		backpressure: &BackpressureSignal{},
	}
	workerInputs := make([]chan I, workers)
	var workerWG sync.WaitGroup
	for worker := range workerInputs {
		workerInputs[worker] = make(chan I, buffer)
		workerWG.Add(1)
		go func(ch <-chan I) {
			defer workerWG.Done()
			draining := false
			for {
				var (
					item I
					ok   bool
				)
				if draining {
					item, ok = <-ch
				} else {
					select {
					case <-ctx.Done():
						draining = true
						continue
					case item, ok = <-ch:
					}
				}
				if !ok {
					return
				}
				out, emit := cfg.Transform(ctx, item)
				if !emit {
					continue
				}
				stage.out <- out
			}
		}(workerInputs[worker])
	}

	go func() {
		defer close(stage.done)
		defer close(stage.out)
		defer func() {
			for _, ch := range workerInputs {
				close(ch)
			}
			workerWG.Wait()
		}()

		nextWorker := 0
		draining := false
		for {
			var (
				item I
				ok   bool
			)
			if draining {
				item, ok = <-in
			} else {
				select {
				case <-ctx.Done():
					draining = true
					continue
				case item, ok = <-in:
				}
			}
			if !ok {
				return
			}

			target := 0
			if len(workerInputs) > 1 {
				if cfg.Key != nil {
					target = stageShardIndex(cfg.Key(item), len(workerInputs))
				} else {
					target = nextWorker % len(workerInputs)
					nextWorker++
				}
			}
			if len(workerInputs[target]) == cap(workerInputs[target]) && stageAllChannelsFull(workerInputs) {
				stage.backpressure.Mark()
			}
			if draining {
				workerInputs[target] <- item
				continue
			}
			if !sendStageItem(ctx, workerInputs[target], item) {
				draining = true
			}
		}
	}()

	return stage
}

func (s *Stage[O]) Output() <-chan O {
	if s == nil {
		return nil
	}
	return s.out
}

func (s *Stage[O]) Wait() {
	if s == nil {
		return
	}
	<-s.done
}

func (s *Stage[O]) Backpressured() bool {
	return s != nil && s.backpressure.Active()
}

func sendStageItem[T any](ctx context.Context, ch chan<- T, item T) bool {
	if ctx == nil {
		ch <- item
		return true
	}
	select {
	case ch <- item:
		return true
	case <-ctx.Done():
		ch <- item
		return false
	}
}

func stageAllChannelsFull[T any](channels []chan T) bool {
	if len(channels) == 0 {
		return false
	}
	for _, ch := range channels {
		if len(ch) < cap(ch) {
			return false
		}
	}
	return true
}

func stageShardIndex(key string, workers int) int {
	if workers <= 1 || key == "" {
		return 0
	}
	hasher := fnv.New32a()
	_, _ = hasher.Write([]byte(key))
	return int(hasher.Sum32() % uint32(workers)) // #nosec G115 -- workers is guaranteed positive by guard above
}
