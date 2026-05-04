package flow

import (
	"externalbad"
	"sealedpkg"
)

func ReturnBad() sealedpkg.Runner {
	return externalbad.Bad{} // want `externalbad.Bad crosses sealed interface sealedpkg.Runner`
}

type RunnerAlias = sealedpkg.Runner

func ReturnAliasBad() RunnerAlias {
	return externalbad.Bad{} // want `externalbad.Bad crosses sealed interface sealedpkg.Runner`
}

func makeBad() (externalbad.Bad, error) {
	return externalbad.Bad{}, nil
}

func makeTwoBad() (externalbad.Bad, externalbad.Bad) {
	return externalbad.Bad{}, externalbad.Bad{}
}

func ReturnTupleBad() (sealedpkg.Runner, error) {
	return makeBad() // want `externalbad.Bad crosses sealed interface sealedpkg.Runner`
}

func ReturnTypeAssertBad() sealedpkg.Runner {
	var value any = externalbad.Bad{}
	return value.(sealedpkg.Runner) // want `externalbad.Bad crosses sealed interface sealedpkg.Runner`
}

func ReturnDirectTypeAssertBad() sealedpkg.Runner {
	return any(externalbad.Bad{}).(sealedpkg.Runner) // want `externalbad.Bad crosses sealed interface sealedpkg.Runner`
}

func ReturnPlainInterfaceFactBad() sealedpkg.Runner {
	var value interface{ Run() } = externalbad.Bad{}
	return value // want `externalbad.Bad crosses sealed interface sealedpkg.Runner`
}

func ClosureCaptureTypeAssertBad() sealedpkg.Runner {
	value := any(externalbad.Bad{})
	return func() sealedpkg.Runner {
		return value.(sealedpkg.Runner) // want `externalbad.Bad crosses sealed interface sealedpkg.Runner`
	}()
}

func BranchTypeAssertBad(flag bool) sealedpkg.Runner {
	var value any
	if flag {
		value = externalbad.Bad{}
	} else {
		value = nil
	}
	return value.(sealedpkg.Runner) // want `externalbad.Bad crosses sealed interface sealedpkg.Runner`
}

func SwitchTypeAssertBad(index int) sealedpkg.Runner {
	var value any
	switch index {
	case 1:
		value = externalbad.Bad{}
	default:
		value = nil
	}
	return value.(sealedpkg.Runner) // want `externalbad.Bad crosses sealed interface sealedpkg.Runner`
}

func FallthroughSwitchTypeAssertBad(flag bool) sealedpkg.Runner {
	var value any
	switch {
	case flag:
		value = externalbad.Bad{}
		fallthrough
	default:
		return value.(sealedpkg.Runner) // want `externalbad.Bad crosses sealed interface sealedpkg.Runner`
	}
}

func TypeSwitchCaseVariableBad() sealedpkg.Runner {
	switch value := any(externalbad.Bad{}).(type) {
	case sealedpkg.Runner:
		return value // want `externalbad.Bad crosses sealed interface sealedpkg.Runner`
	default:
		return nil
	}
}

func TypeSwitchShadowedCaseVariableSafe() sealedpkg.Runner {
	switch value := any(externalbad.Bad{}).(type) {
	case sealedpkg.Runner:
		_ = value
		{
			var value sealedpkg.Runner
			return value
		}
	default:
		return nil
	}
}

func TypeSwitchDefaultVariableBad() sealedpkg.Runner {
	switch value := any(externalbad.Bad{}).(type) {
	case string:
		return nil
	default:
		return value.(sealedpkg.Runner) // want `externalbad.Bad crosses sealed interface sealedpkg.Runner`
	}
}

type typeAssertBox struct {
	value any
}

func SelectorTypeAssertBad() sealedpkg.Runner {
	var box typeAssertBox
	box.value = externalbad.Bad{}
	return box.value.(sealedpkg.Runner) // want `externalbad.Bad crosses sealed interface sealedpkg.Runner`
}

func CompositeIndexTypeAssertBad() sealedpkg.Runner {
	values := []any{externalbad.Bad{}}
	return values[0].(sealedpkg.Runner) // want `externalbad.Bad crosses sealed interface sealedpkg.Runner`
}

func AssignmentIndexTypeAssertBad() sealedpkg.Runner {
	values := []any{nil}
	values[0] = externalbad.Bad{}
	return values[0].(sealedpkg.Runner) // want `externalbad.Bad crosses sealed interface sealedpkg.Runner`
}

func MapIndexTypeAssertBad() sealedpkg.Runner {
	values := map[string]any{"runner": externalbad.Bad{}}
	return values["runner"].(sealedpkg.Runner) // want `externalbad.Bad crosses sealed interface sealedpkg.Runner`
}

func CopySliceTypeAssertBad() sealedpkg.Runner {
	src := []any{externalbad.Bad{}}
	dst := make([]any, 1)
	copy(dst, src)
	return dst[0].(sealedpkg.Runner) // want `externalbad.Bad crosses sealed interface sealedpkg.Runner`
}

func CopySliceCompositeLiteralBad() sealedpkg.Runner {
	dst := make([]any, 1)
	copy(dst, []any{externalbad.Bad{}})
	return dst[0].(sealedpkg.Runner) // want `externalbad.Bad crosses sealed interface sealedpkg.Runner`
}

func CopySliceClearsDestinationSafe() sealedpkg.Runner {
	dst := []any{externalbad.Bad{}}
	copy(dst, []any{nil})
	return dst[0].(sealedpkg.Runner)
}

func CopySlicePreservesUntouchedDestinationBad() sealedpkg.Runner {
	dst := []any{nil, externalbad.Bad{}}
	copy(dst, []any{nil})
	return dst[1].(sealedpkg.Runner) // want `externalbad.Bad crosses sealed interface sealedpkg.Runner`
}

func RangeSliceTypeAssertBad() sealedpkg.Runner {
	values := []any{externalbad.Bad{}}
	for _, value := range values {
		return value.(sealedpkg.Runner) // want `externalbad.Bad crosses sealed interface sealedpkg.Runner`
	}
	return nil
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

func ReceiveChannelTypeAssertBad() sealedpkg.Runner {
	ch := make(chan any, 1)
	ch <- externalbad.Bad{}
	value := <-ch
	return value.(sealedpkg.Runner) // want `externalbad.Bad crosses sealed interface sealedpkg.Runner`
}

func LocalVarBad() {
	var runner sealedpkg.Runner = externalbad.Bad{} // want `externalbad.Bad crosses sealed interface sealedpkg.Runner`
	_ = runner
}

func acceptVariadic(...sealedpkg.Runner) {}

func PassVariadicBad() {
	acceptVariadic(externalbad.Bad{}) // want `externalbad.Bad crosses sealed interface sealedpkg.Runner`
}

func PassVariadicTupleBad() {
	acceptVariadic(makeTwoBad()) // want `externalbad.Bad crosses sealed interface sealedpkg.Runner`
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

func MapAssignmentKeyBad() {
	values := map[sealedpkg.Runner]string{}
	values[externalbad.Bad{}] = "bad" // want `externalbad.Bad crosses sealed interface sealedpkg.Runner`
}

func RangeAssignBad(values []externalbad.Bad) {
	var runner sealedpkg.Runner
	for _, runner = range values { // want `externalbad.Bad crosses sealed interface sealedpkg.Runner`
	}
	_ = runner
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
