package a

func Bad() {
	panic("boom") // want `panic is forbidden outside tests, init, and panicsafe`
}

var _ = func() int {
	panic("boom") // want `panic is forbidden outside tests, init, and panicsafe`
	return 0
}()

func init() {
	panic("allowed during init")
}

type T struct{}

func (T) init() {
	panic("method init is not package init") // want `panic is forbidden outside tests, init, and panicsafe`
}
