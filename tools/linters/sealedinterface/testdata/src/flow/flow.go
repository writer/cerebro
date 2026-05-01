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

func AppendBad() {
	var runners []sealedpkg.Runner
	runners = append(runners, externalbad.Bad{}) // want `externalbad.Bad crosses sealed interface sealedpkg.Runner`
	_ = runners
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
