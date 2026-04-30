package bad

import "sealedpkg"

type Bad struct { // want `implements sealed interface sealedpkg.Runner`
	Name string
}

func (Bad) Run() {}

var _ sealedpkg.Runner = Bad{}
