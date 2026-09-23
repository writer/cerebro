// Separate module for Cerebro's custom linters.
// Kept out of the main module so that golang.org/x/tools never leaks into the
// runtime vendor tree.
module github.com/writer/cerebro/tools/linters

go 1.26.0

require golang.org/x/tools v0.50.0

require (
	golang.org/x/mod v0.41.0 // indirect
	golang.org/x/sync v0.23.0 // indirect
)
