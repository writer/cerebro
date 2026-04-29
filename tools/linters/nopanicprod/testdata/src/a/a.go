package a

import "log"

func Bad() {
	panic("boom") // want `panic is forbidden outside tests, init, and panicsafe`
}

func BadLogPanic() {
	log.Panic("boom") // want `panic is forbidden outside tests, init, and panicsafe`
}

func BadLogPanicf() {
	log.Panicf("boom: %s", "x") // want `panic is forbidden outside tests, init, and panicsafe`
}

func BadLogPanicln() {
	log.Panicln("boom") // want `panic is forbidden outside tests, init, and panicsafe`
}

var _ = func() int {
	panic("boom") // want `panic is forbidden outside tests, init, and panicsafe`
	return 0
}()

func init() {
	panic("allowed during init")
	_ = func() int {
		panic("closure panic is not package init") // want `panic is forbidden outside tests, init, and panicsafe`
	}
}

type T struct{}

func (T) init() {
	panic("method init is not package init") // want `panic is forbidden outside tests, init, and panicsafe`
}
