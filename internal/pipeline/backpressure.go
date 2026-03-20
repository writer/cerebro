package pipeline

import "sync/atomic"

type BackpressureSignal struct {
	triggered atomic.Bool
}

func (s *BackpressureSignal) Mark() {
	if s == nil {
		return
	}
	s.triggered.Store(true)
}

func (s *BackpressureSignal) Active() bool {
	return s != nil && s.triggered.Load()
}
