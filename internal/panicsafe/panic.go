package panicsafe

// Payload names a recovered panic value crossing into the panicsafe package.
type Payload struct {
	Value any
}

// Repanic rethrows a recovered panic value at explicit process-edge boundaries
// where Go runtime or standard-library sentinels must preserve panic semantics.
func Repanic(payload Payload) {
	panic(payload.Value)
}
