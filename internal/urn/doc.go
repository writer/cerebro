// Package urn parses and mints tenant-scoped Cerebro resource names.
//
// Cerebro URNs use the form urn:cerebro:<tenant>:<kind>:<parts...>. Provider
// identifiers must be passed through EncodeSegment before they become parts;
// Mint validates structure but cannot infer which inputs are provider
// controlled. StableExternalID is available when the source identifier should
// not be disclosed or cannot safely serve as a path segment.
package urn
