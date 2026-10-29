package cloudidentitysource

import (
	ci "github.com/writer/cerebro/internal/cloudidentity"
)

// CollectionCoverage records missing evidence without asserting a control
// result. It is an alias for the core cloudidentity.CollectionCoverage
// model so internal/sourceprojection, which cannot import this adapter
// package, can decode the exact wire shape this source emits.
type CollectionCoverage = ci.CollectionCoverage
