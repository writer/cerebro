package a

import "time"

// OK: a real function.
func realFunc() {}

// OK: a var with a non-function value.
var count = 3

// BAD: test-seam hook via func literal.
var doThing = func() error { return nil } // want `package-level var 'doThing' is bound to a function literal`

// BAD: declared func-typed var, to be overwritten at init() time.
var now func() time.Time // want `package-level var 'now' is bound to a function literal`

// BAD: multi-name declaration still counts each name individually.
var (
	before = func() {} // want `package-level var 'before' is bound to a function literal`
	after  = func() {} // want `package-level var 'after' is bound to a function literal`
)

// Allowed via marker.
//
//cerebro:lint:allow novarfunc legacy platform shim https://example.com/issue/111
var legacyHook = func() {}
