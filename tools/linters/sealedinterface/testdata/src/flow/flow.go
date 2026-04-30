package flow

import (
	"externalbad"
	"sealedpkg"
)

func ReturnBad() sealedpkg.Runner {
	return externalbad.Bad{} // want `externalbad.Bad crosses sealed interface sealedpkg.Runner`
}

func PassBad(fn func(sealedpkg.Runner)) {
	fn(externalbad.Bad{}) // want `externalbad.Bad crosses sealed interface sealedpkg.Runner`
}

var converted = sealedpkg.Runner(externalbad.Bad{}) // want `externalbad.Bad crosses sealed interface sealedpkg.Runner`
