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
