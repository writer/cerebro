// Separate module for Cerebro's custom linters.
// Kept out of the main module so that golang.org/x/tools never leaks into the
// runtime vendor tree.
module github.com/writer/cerebro/tools/linters

go 1.26

require golang.org/x/tools v0.47.0

require (
	golang.org/x/mod v0.37.0 // indirect
	golang.org/x/sync v0.21.0 // indirect
)
