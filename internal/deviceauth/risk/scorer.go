package risk

import (
	"context"
	"net"
	"sort"
	"strings"
	"time"
)

// Signal is the per-request input to the risk pipeline.
type Signal struct {
	DeviceID  string
	TenantID  string
	RemoteIP  net.IP
	UserAgent string
	Method    string
	Path      string
	Now       time.Time
	// PriorObservation is the most recently recorded observation for this
	// device, if any. The scorer uses it to derive velocity and geo drift.
	PriorObservation *Observation
}

// Observation records what we know about a device's last successful
// authentication. The Tracker layer persists these between calls; the
// scorer reads them.
type Observation struct {
	IP        string
	Country   string
	ASN       string
	Latitude  float64
	Longitude float64
	At        time.Time
}

// Detector is one signal in the composite scorer. Its job is to return a
// numeric score in [0, 100] plus a human-readable label that explains why.
type Detector interface {
	Name() string
	// Evaluate returns a score (0..100) and a non-empty signal label when
	// the detector wants the audit log to record what fired. A 0-score
	// detector returns an empty label.
	Evaluate(ctx context.Context, sig Signal, geo *GeoFact) (int, string)
}

// GeoFact is what GeoLookup hands back for a given IP.
type GeoFact struct {
	Country   string
	ASN       string
	Latitude  float64
	Longitude float64
}

// Decision is the scorer's per-request output.
type Decision struct {
	// Score is the composite 0..100 score.
	Score int
	// Level is "low", "elevated", or "high".
	Level string
	// Signals lists the (detector, label) pairs that contributed.
	Signals []SignalEntry
	// Geo is the geo-fact looked up for the request IP, or nil.
	Geo *GeoFact
	// AllowSensitiveScopes is false when Level == "high"; the auth pipeline
	// uses this to drop sensitive scopes from a device JWT before forwarding
	// to handlers.
	AllowSensitiveScopes bool
}

// SignalEntry is one (detector, label, score) triple in [Decision.Signals].
type SignalEntry struct {
	Detector string
	Label    string
	Score    int
}

// Thresholds maps numeric scores to levels. Defaults are 30 / 70.
type Thresholds struct {
	Elevated int
	High     int
}

// Scorer composes detectors. Detectors and configuration are immutable after
// construction; the scorer is goroutine-safe purely because every dependency
// it touches (Detector implementations, GeoLookup, WAFEmitter) is
// goroutine-safe on its own.
type Scorer struct {
	detectors  []Detector
	geo        GeoLookup
	thresholds Thresholds
	emitter    WAFEmitter
}

// NewScorer returns a Scorer.
func NewScorer(thresholds Thresholds, geo GeoLookup, emitter WAFEmitter, detectors ...Detector) *Scorer {
	if thresholds.Elevated <= 0 {
		thresholds.Elevated = 30
	}
	if thresholds.High <= 0 {
		thresholds.High = 70
	}
	if geo == nil {
		geo = NoOpLookup{}
	}
	if emitter == nil {
		emitter = NoOpEmitter{}
	}
	clean := make([]Detector, 0, len(detectors))
	for _, d := range detectors {
		if d == nil {
			continue
		}
		clean = append(clean, d)
	}
	return &Scorer{detectors: clean, geo: geo, thresholds: thresholds, emitter: emitter}
}

// Score computes a Decision for the given Signal.
func (s *Scorer) Score(ctx context.Context, sig Signal) Decision {
	var geo *GeoFact
	if sig.RemoteIP != nil {
		fact, ok := s.geo.Lookup(ctx, sig.RemoteIP)
		if ok {
			geo = &fact
		}
	}
	dec := Decision{Geo: geo}
	dec.Signals = make([]SignalEntry, 0, len(s.detectors))
	composite := 0
	for _, d := range s.detectors {
		sub, label := d.Evaluate(ctx, sig, geo)
		if sub <= 0 {
			continue
		}
		dec.Signals = append(dec.Signals, SignalEntry{Detector: d.Name(), Label: label, Score: sub})
		composite = max(composite, sub)
	}
	if composite > 100 {
		composite = 100
	}
	dec.Score = composite
	switch {
	case composite >= s.thresholds.High:
		dec.Level = "high"
		dec.AllowSensitiveScopes = false
	case composite >= s.thresholds.Elevated:
		dec.Level = "elevated"
		dec.AllowSensitiveScopes = true
	default:
		dec.Level = "low"
		dec.AllowSensitiveScopes = true
	}
	sort.SliceStable(dec.Signals, func(i, j int) bool {
		if dec.Signals[i].Score != dec.Signals[j].Score {
			return dec.Signals[i].Score > dec.Signals[j].Score
		}
		return dec.Signals[i].Detector < dec.Signals[j].Detector
	})
	if dec.Level == "high" {
		_ = s.emitter.Emit(ctx, WAFRuleUpdate{
			DeviceID: sig.DeviceID,
			TenantID: sig.TenantID,
			IP:       ipString(sig.RemoteIP),
			Reason:   strings.Join(labelsOf(dec.Signals), ","),
			At:       sig.Now,
		})
	}
	return dec
}

// SensitiveScopes is the scope subset the scorer downgrades on a "high"
// risk decision.
var SensitiveScopes = map[string]struct{}{
	"platform.devices.bootstrap_tokens.write": {},
	"platform.devices.revoke":                 {},
	"platform.telemetry.ingest":               {},
}

// FilterScopes returns a copy of in with sensitive scopes removed iff the
// decision level is "high".
func (d Decision) FilterScopes(in []string) []string {
	if d.AllowSensitiveScopes {
		return in
	}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, sensitive := SensitiveScopes[s]; sensitive {
			continue
		}
		out = append(out, s)
	}
	return out
}

func ipString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}

func labelsOf(entries []SignalEntry) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.Label != "" {
			out = append(out, e.Detector+":"+e.Label)
		}
	}
	return out
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
