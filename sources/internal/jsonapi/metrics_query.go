package jsonapi

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// MetricsQueryLimits bounds provider metrics queries before they reach the
// transport. Adapters supply their documented views and stable ID dimension.
type MetricsQueryLimits struct {
	AllowedViews      map[string]bool
	RequiredDimension string
	MaxBytes          int
	MaxMetrics        int
	MaxInterval       time.Duration
}

type metricsQuery struct {
	View       string `json:"view"`
	Dimensions []struct {
		Field string `json:"field"`
	} `json:"dimensions"`
	Metrics []struct {
		Measure     string `json:"measure"`
		Aggregation string `json:"aggregation"`
	} `json:"metrics"`
	FromTimestamp string `json:"fromTimestamp"`
	ToTimestamp   string `json:"toTimestamp"`
}

// ValidateMetricsQuery validates a bounded query against the provider contract
// selected by limits.
func ValidateMetricsQuery(raw string, limits MetricsQueryLimits) error {
	raw = strings.TrimSpace(raw)
	if raw == "" || limits.MaxBytes <= 0 || len(raw) > limits.MaxBytes {
		return fmt.Errorf("metrics query must be bounded JSON")
	}
	var query metricsQuery
	if err := json.Unmarshal([]byte(raw), &query); err != nil {
		return fmt.Errorf("metrics query must match the documented query schema: %w", err)
	}
	if !limits.AllowedViews[query.View] || len(query.Metrics) < 1 || len(query.Metrics) > limits.MaxMetrics {
		return fmt.Errorf("metrics query requires one supported view and 1 to %d metrics", limits.MaxMetrics)
	}
	stableDimension := false
	for _, dimension := range query.Dimensions {
		if dimension.Field == limits.RequiredDimension {
			stableDimension = true
		}
	}
	if !stableDimension {
		return fmt.Errorf("metrics query requires the %s dimension for stable IDs", limits.RequiredDimension)
	}
	from, err := time.Parse(time.RFC3339, query.FromTimestamp)
	if err != nil {
		return fmt.Errorf("metrics query fromTimestamp must be RFC3339")
	}
	to, err := time.Parse(time.RFC3339, query.ToTimestamp)
	if err != nil {
		return fmt.Errorf("metrics query toTimestamp must be RFC3339")
	}
	if !to.After(from) || limits.MaxInterval <= 0 || to.Sub(from) > limits.MaxInterval {
		return fmt.Errorf("metrics query interval must be positive and bounded")
	}
	for _, metric := range query.Metrics {
		if strings.TrimSpace(metric.Measure) == "" || strings.TrimSpace(metric.Aggregation) == "" {
			return fmt.Errorf("metrics query metrics require measure and aggregation")
		}
	}
	return nil
}
