package risk

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"
)

func TestVelocityDetectorImpossibleTravel(t *testing.T) {
	d := NewVelocityDetector()
	now := time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC)
	score, label := d.Evaluate(context.Background(), Signal{
		PriorObservation: &Observation{Latitude: 40.7128, Longitude: -74.0060, Country: "US", At: now.Add(-30 * time.Minute)},
		Now:              now,
	}, &GeoFact{Latitude: 51.5074, Longitude: -0.1278, Country: "GB"})
	if score < 50 {
		t.Errorf("velocity score=%d want >=50; label=%s", score, label)
	}
	if !strings.Contains(label, "from=US") {
		t.Errorf("label missing prior country: %s", label)
	}
}

func TestVelocityDetectorBenignSpeed(t *testing.T) {
	d := NewVelocityDetector()
	now := time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC)
	score, _ := d.Evaluate(context.Background(), Signal{
		PriorObservation: &Observation{Latitude: 40.0, Longitude: -74.0, Country: "US", At: now.Add(-10 * time.Hour)},
		Now:              now,
	}, &GeoFact{Latitude: 41.0, Longitude: -75.0, Country: "US"})
	if score != 0 {
		t.Errorf("benign speed score=%d want 0", score)
	}
}

func TestVelocityDetectorNoPriorOrGeo(t *testing.T) {
	d := NewVelocityDetector()
	if score, _ := d.Evaluate(context.Background(), Signal{}, nil); score != 0 {
		t.Errorf("no prior score=%d", score)
	}
}

func TestCountryDriftDetector(t *testing.T) {
	d := NewCountryDriftDetector()
	score, _ := d.Evaluate(context.Background(), Signal{
		PriorObservation: &Observation{Country: "US"},
	}, &GeoFact{Country: "RU"})
	if score == 0 {
		t.Error("expected non-zero score on country drift")
	}
}

func TestASNDriftDetector(t *testing.T) {
	d := NewASNDriftDetector()
	score, _ := d.Evaluate(context.Background(), Signal{
		PriorObservation: &Observation{ASN: "AS7922"},
	}, &GeoFact{ASN: "AS3320"})
	if score == 0 {
		t.Error("expected non-zero score on ASN drift")
	}
}

func TestScorerThresholds(t *testing.T) {
	geo := NewInMemoryLookup()
	geo.Set("198.51.100.10", GeoFact{Country: "RU", ASN: "AS3320", Latitude: 55.7558, Longitude: 37.6176})
	scorer := NewScorer(Thresholds{Elevated: 30, High: 70}, geo, NoOpEmitter{},
		NewVelocityDetector(), NewCountryDriftDetector(), NewASNDriftDetector(),
	)
	now := time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC)
	dec := scorer.Score(context.Background(), Signal{
		DeviceID: "d1", TenantID: "writer", RemoteIP: net.ParseIP("198.51.100.10"), Now: now,
		PriorObservation: &Observation{Country: "US", ASN: "AS7922", Latitude: 40.7128, Longitude: -74.0060, At: now.Add(-30 * time.Minute)},
	})
	if dec.Level != "high" {
		t.Errorf("level=%s want high; signals=%+v score=%d", dec.Level, dec.Signals, dec.Score)
	}
	if dec.AllowSensitiveScopes {
		t.Error("high risk should drop sensitive scopes")
	}
	filtered := dec.FilterScopes([]string{"platform.devices.read", "platform.telemetry.ingest"})
	for _, s := range filtered {
		if _, sensitive := SensitiveScopes[s]; sensitive {
			t.Errorf("filtered list still contains sensitive scope %q", s)
		}
	}
}

func TestScorerLowAllowsAllScopes(t *testing.T) {
	scorer := NewScorer(Thresholds{}, NoOpLookup{}, NoOpEmitter{}, NewVelocityDetector())
	dec := scorer.Score(context.Background(), Signal{Now: time.Now()})
	if dec.Level != "low" {
		t.Errorf("level=%s", dec.Level)
	}
	in := []string{"platform.devices.read", "platform.telemetry.ingest"}
	out := dec.FilterScopes(in)
	if len(out) != len(in) {
		t.Errorf("low risk should not filter; got %v from %v", out, in)
	}
}

func TestJSONLogEmitter(t *testing.T) {
	var buf bytes.Buffer
	e := NewJSONLogEmitter(&buf)
	if err := e.Emit(context.Background(), WAFRuleUpdate{DeviceID: "d1", IP: "1.2.3.4", At: time.Unix(0, 0)}); err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["name"] != "cerebro.deviceauth.waf_emit" {
		t.Errorf("emitted name=%v", got["name"])
	}
	if got["device_id"] != "d1" {
		t.Errorf("emitted device_id=%v", got["device_id"])
	}
}

func TestObservationStoreRoundTrip(t *testing.T) {
	s := NewInMemoryObservationStore()
	if _, ok := s.Get(context.Background(), "d1"); ok {
		t.Fatal("unexpected hit on empty store")
	}
	if err := s.Put(context.Background(), "d1", Observation{Country: "US", At: time.Now()}); err != nil {
		t.Fatal(err)
	}
	got, ok := s.Get(context.Background(), "d1")
	if !ok || got.Country != "US" {
		t.Fatalf("got=%+v ok=%v", got, ok)
	}
}
