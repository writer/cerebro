// Package risk implements the Phase-3 anomaly-detection layer that runs on
// every authenticated SeCheck request.
//
// The pipeline is:
//
//  1. The HTTP handler calls [Scorer.Score] with a [Signal] capturing the
//     remote IP, the device's previous-known location, and the time since
//     the last refresh.
//  2. [Scorer] runs each registered [Detector] -- velocity (impossible
//     travel), geo/ASN drift, request-rate anomaly -- and aggregates the
//     numeric signals into a single 0..100 score.
//  3. The handler decides what to do:
//       - score < LowThreshold:    allow as-is
//       - LowThreshold..HighThr:   allow but emit an audit signal
//       - score >= HighThreshold:  drop sensitive scopes (telemetry write,
//                                  bootstrap-token issuance, revocation)
//                                  and emit a high-priority audit + WAF
//                                  rule update.
//
// Geo/ASN lookup is pluggable via [GeoLookup]. The default
// [InMemoryGeoLookup] holds a static IP -> (country, asn, lat, lon) table
// suitable for tests and offline development; production wires a MaxMind-
// or AWS-managed-service-backed lookup.
//
// WAF rule updates are pluggable via [WAFEmitter]. The default
// [JSONLogEmitter] just writes a JSON line; production wires an emitter
// that talks to AWS WAFv2's UpdateIPSet API or pushes to an EventBridge
// rule that drives a Lambda.
package risk
