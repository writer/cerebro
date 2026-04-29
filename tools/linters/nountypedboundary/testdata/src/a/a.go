package a

// Good: typed struct.
type Request struct {
	ID   string
	Kind string
}

type Response struct {
	OK bool
}

func Good(req Request) Response { return Response{OK: true} }

// Bad: any parameter.
func Bad1(x any) error { return nil } // want `has parameter of forbidden untyped shape`

// Bad: interface{} parameter.
func Bad2(x interface{}) error { return nil } // want `has parameter of forbidden untyped shape`

// Bad: map[string]any return.
func Bad3() map[string]any { return nil } // want `has return value of forbidden untyped shape`

// Bad: map[string]interface{} return.
func Bad4() map[string]interface{} { return nil } // want `has return value of forbidden untyped shape`

// Bad: []any parameter.
func Bad5(xs []any) {} // want `has parameter of forbidden untyped shape`

// Bad: []interface{} parameter.
func Bad6(xs []interface{}) {} // want `has parameter of forbidden untyped shape`

// Good: named interface is allowed.
type Runner interface{ Run() error }

func RunIt(r Runner) error { return r.Run() }

// Unexported function: not checked.
func secret(x any) {}

// Methods on unexported types: not checked.
type hidden struct{}

func (h *hidden) Do(x any) {}

// Methods on exported types: checked.
type Svc struct{}

func (s *Svc) Handle(x any) {} // want `has parameter of forbidden untyped shape`

// Explicit allow marker.
//
//cerebro:lint:allow nountypedboundary legacy boundary https://example.com/issue/7
func Legacy(x any) {}
