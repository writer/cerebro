package useexternal

import (
	"externalbad"
	"sealedpkg"
)

var _ sealedpkg.Runner = externalbad.Bad{} // want `type externalbad.Bad implements sealed interface sealedpkg.Runner`
