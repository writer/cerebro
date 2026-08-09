// Package graphfacts exposes the claim store as a read-only fact model.
//
// A fact is a normalized claim about a subject. It may point to another URN,
// carry a scalar value, or both. The service deliberately keeps fact lookup
// separate from graph traversal: List selects stored claims, Explain derives a
// human-readable edge and freshness view for one claim, and Trace groups claims
// that share the anchor subject. None of these operations mutate graph state.
//
// TenantID and RuntimeID are authority boundaries, not optional search hints.
// Every list operation requires at least one of them. Pagination uses the
// store's stable observed-at, updated-at, and claim-ID ordering so callers can
// continue a scan without relying on offsets in a changing dataset.
package graphfacts
