package risk

import (
	"context"
	"fmt"
	"math"
	"time"
)

// VelocityDetector flags impossible-travel: a device whose previous geo
// observation places it more kilometers away than could be reached at
// MaxKMPerHour given the elapsed time. Scores scale linearly between
// FloorScore (just over the threshold) and 100 (3x the threshold).
type VelocityDetector struct {
	MaxKMPerHour float64
	FloorScore   int
	MinElapsed   time.Duration
}

// NewVelocityDetector builds a VelocityDetector with sensible defaults
// (1000 km/h roughly approximating commercial-flight speed, 50 baseline
// score, 60s minimum elapsed time before the detector engages).
func NewVelocityDetector() *VelocityDetector {
	return &VelocityDetector{
		MaxKMPerHour: 1000,
		FloorScore:   50,
		MinElapsed:   60 * time.Second,
	}
}

// Name implements [Detector].
func (v *VelocityDetector) Name() string { return "velocity" }

// Evaluate implements [Detector].
func (v *VelocityDetector) Evaluate(_ context.Context, sig Signal, geo *GeoFact) (int, string) {
	if sig.PriorObservation == nil || geo == nil {
		return 0, ""
	}
	prior := sig.PriorObservation
	elapsed := sig.Now.Sub(prior.At)
	if elapsed <= v.MinElapsed {
		return 0, ""
	}
	dist := haversineKM(prior.Latitude, prior.Longitude, geo.Latitude, geo.Longitude)
	hours := elapsed.Hours()
	if hours <= 0 {
		return 0, ""
	}
	speed := dist / hours
	if speed <= v.MaxKMPerHour {
		return 0, ""
	}
	ratio := speed / v.MaxKMPerHour
	score := v.FloorScore + int((ratio-1)*25)
	if score > 100 {
		score = 100
	}
	if score < v.FloorScore {
		score = v.FloorScore
	}
	return score, fmt.Sprintf("speed_kmh=%.0f from=%s to=%s", speed, prior.Country, geo.Country)
}

// haversineKM returns the great-circle distance in kilometers.
func haversineKM(lat1, lon1, lat2, lon2 float64) float64 {
	const r = 6371.0
	dLat := degToRad(lat2 - lat1)
	dLon := degToRad(lon2 - lon1)
	a := math.Sin(dLat/2)*math.Sin(dLat/2) +
		math.Cos(degToRad(lat1))*math.Cos(degToRad(lat2))*
			math.Sin(dLon/2)*math.Sin(dLon/2)
	c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))
	return r * c
}

func degToRad(deg float64) float64 { return deg * math.Pi / 180 }

// CountryDriftDetector fires when the geo country changes between the
// prior observation and this one. Lower-severity than velocity because it
// fires on legitimate VPN flips, hence the modest score.
type CountryDriftDetector struct {
	Score int
}

// NewCountryDriftDetector builds a detector with a 35 default score.
func NewCountryDriftDetector() *CountryDriftDetector {
	return &CountryDriftDetector{Score: 35}
}

// Name implements [Detector].
func (c *CountryDriftDetector) Name() string { return "country_drift" }

// Evaluate implements [Detector].
func (c *CountryDriftDetector) Evaluate(_ context.Context, sig Signal, geo *GeoFact) (int, string) {
	if sig.PriorObservation == nil || geo == nil {
		return 0, ""
	}
	if sig.PriorObservation.Country == "" || geo.Country == "" {
		return 0, ""
	}
	if sig.PriorObservation.Country == geo.Country {
		return 0, ""
	}
	return c.Score, fmt.Sprintf("from=%s to=%s", sig.PriorObservation.Country, geo.Country)
}

// ASNDriftDetector fires when the AS number changes between observations.
// Scored just under country drift because a legitimate ISP change is more
// common than a country change.
type ASNDriftDetector struct {
	Score int
}

// NewASNDriftDetector builds a detector with a 25 default score.
func NewASNDriftDetector() *ASNDriftDetector { return &ASNDriftDetector{Score: 25} }

// Name implements [Detector].
func (d *ASNDriftDetector) Name() string { return "asn_drift" }

// Evaluate implements [Detector].
func (d *ASNDriftDetector) Evaluate(_ context.Context, sig Signal, geo *GeoFact) (int, string) {
	if sig.PriorObservation == nil || geo == nil {
		return 0, ""
	}
	if sig.PriorObservation.ASN == "" || geo.ASN == "" {
		return 0, ""
	}
	if sig.PriorObservation.ASN == geo.ASN {
		return 0, ""
	}
	return d.Score, fmt.Sprintf("from=%s to=%s", sig.PriorObservation.ASN, geo.ASN)
}
