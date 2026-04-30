package sealedpkg

//cerebro:sealed
type Runner interface {
	Run()
}

type local struct{}

func (local) Run() {}
