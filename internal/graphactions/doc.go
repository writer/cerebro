// Package graphactions turns an authorized finding into a bounded provider
// action and links the provider receipt back to that finding.
//
// The registry is the policy boundary. Each ActionSpec fixes the provider,
// provider operation, target kind, eligibility check, target resolver, and
// optional reversal. A caller-supplied target is only a selector: the resolver
// must prove that the normalized target is present in the finding's verified
// identifiers before execution can proceed.
//
// Execute always plans before it mutates. Dry runs return the exact normalized
// target and provider request metadata without calling a provider. Live runs
// require explicit approval, normalize the provider response, and persist an
// external reference on the finding. Reconcile only follows an external ID
// already linked to that finding, preventing arbitrary provider records from
// being attached after the fact.
package graphactions
