package a

import "sync"

// OneMutex is fine.
type OneMutex struct {
	mu sync.Mutex
	n  int
}

// OneRW is fine.
type OneRW struct {
	mu sync.RWMutex
	m  map[string]int
}

// TwoMutexes should trigger a diagnostic.
type TwoMutexes struct { // want `struct TwoMutexes declares 2 mutex fields`
	a sync.Mutex
	b sync.Mutex
}

// MutexAndRW should trigger.
type MutexAndRW struct { // want `struct MutexAndRW declares 2 mutex fields`
	a sync.Mutex
	b sync.RWMutex
}

// PointerMutexes also count.
type PointerMutexes struct { // want `struct PointerMutexes declares 2 mutex fields`
	a *sync.Mutex
	b *sync.RWMutex
}

// MultiNameField: `a, b sync.Mutex` counts as 2.
type MultiName struct { // want `struct MultiName declares 2 mutex fields`
	a, b sync.Mutex
}

// Allowed struct should not trigger.
//
//cerebro:lint:allow maxmutex legacy god-struct https://example.com/issue/123
type Allowed struct {
	a sync.Mutex
	b sync.Mutex
}

// NonMutexNamedMutex: a type called Mutex from a different package should not trigger.
type fakePkgMutex struct{}

type NotRealMutex struct {
	a fakePkgMutex
	b fakePkgMutex
}
