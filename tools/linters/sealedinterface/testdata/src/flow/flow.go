package flow

import (
	"externalbad"
	"sealedpkg"
)

func ReturnBad() sealedpkg.Runner {
	return externalbad.Bad{} // want `externalbad.Bad crosses sealed interface sealedpkg.Runner`
}

func makeBad() (externalbad.Bad, error) {
	return externalbad.Bad{}, nil
}

func ReturnTupleBad() (sealedpkg.Runner, error) {
	return makeBad() // want `externalbad.Bad crosses sealed interface sealedpkg.Runner`
}

func AssignTupleBad() {
	var runner sealedpkg.Runner
	var err error
	runner, err = makeBad() // want `externalbad.Bad crosses sealed interface sealedpkg.Runner`
	_, _ = runner, err
}

func acceptTuple(sealedpkg.Runner, error) {}

func PassTupleCallBad() {
	acceptTuple(makeBad()) // want `externalbad.Bad crosses sealed interface sealedpkg.Runner`
}

func AppendBad() {
	var runners []sealedpkg.Runner
	runners = append(runners, externalbad.Bad{}) // want `externalbad.Bad crosses sealed interface sealedpkg.Runner`
	_ = runners
}

type runners []sealedpkg.Runner

func AppendNamedSliceBad() {
	var rs runners
	rs = append(rs, externalbad.Bad{}) // want `externalbad.Bad crosses sealed interface sealedpkg.Runner`
	_ = rs
}

func SendChannelBad(ch chan sealedpkg.Runner) {
	ch <- externalbad.Bad{} // want `externalbad.Bad crosses sealed interface sealedpkg.Runner`
}

func acceptVariadic(...sealedpkg.Runner) {}

func PassVariadicBad() {
	acceptVariadic(externalbad.Bad{}) // want `externalbad.Bad crosses sealed interface sealedpkg.Runner`
}

func CompositeLiteralBad() []sealedpkg.Runner {
	return []sealedpkg.Runner{
		externalbad.Bad{}, // want `externalbad.Bad crosses sealed interface sealedpkg.Runner`
	}
}

func NamedCompositeLiteralBad() runners {
	return runners{
		externalbad.Bad{}, // want `externalbad.Bad crosses sealed interface sealedpkg.Runner`
	}
}

type holder struct {
	Runner sealedpkg.Runner
}

var structLiteralBad = holder{
	Runner: externalbad.Bad{}, // want `externalbad.Bad crosses sealed interface sealedpkg.Runner`
}

var mapKeyLiteralBad = map[sealedpkg.Runner]string{
	externalbad.Bad{}: "bad", // want `externalbad.Bad crosses sealed interface sealedpkg.Runner`
}

func PassBad(fn func(sealedpkg.Runner)) {
	fn(externalbad.Bad{}) // want `externalbad.Bad crosses sealed interface sealedpkg.Runner`
}

var closureRunner = func() sealedpkg.Runner {
	return externalbad.Bad{} // want `externalbad.Bad crosses sealed interface sealedpkg.Runner`
}()

var closurePass = func(fn func(sealedpkg.Runner)) {
	fn(externalbad.Bad{}) // want `externalbad.Bad crosses sealed interface sealedpkg.Runner`
}

var converted = sealedpkg.Runner(externalbad.Bad{}) // want `externalbad.Bad crosses sealed interface sealedpkg.Runner`
