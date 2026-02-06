// Package threatintel provides EPSS (Exploit Prediction Scoring System) integration
// for probability-based vulnerability prioritization.
package threatintel

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// EPSSScore represents an EPSS score for a CVE
type EPSSScore struct {
	CVE        string    `json:"cve"`
	EPSS       float64   `json:"epss"`       // Probability of exploitation (0-1)
	Percentile float64   `json:"percentile"` // Relative ranking (0-1)
	Date       string    `json:"date"`       // Score date
	FetchedAt  time.Time `json:"fetched_at"`
}

// EPSSClient fetches EPSS scores from the FIRST.org API
type EPSSClient struct {
	client    *http.Client
	baseURL   string
	cache     map[string]*EPSSScore
	cacheTTL  time.Duration
	cacheHits int64
	cacheMiss int64
	mu        sync.RWMutex
}

// EPSSResponse represents the API response from FIRST.org
type EPSSResponse struct {
	Status     string `json:"status"`
	StatusCode int    `json:"status-code"`
	Version    string `json:"version"`
	Total      int    `json:"total"`
	Offset     int    `json:"offset"`
	Limit      int    `json:"limit"`
	Data       []struct {
		CVE        string `json:"cve"`
		EPSS       string `json:"epss"`
		Percentile string `json:"percentile"`
		Date       string `json:"date"`
	} `json:"data"`
}

// NewEPSSClient creates a new EPSS client with default settings
func NewEPSSClient() *EPSSClient {
	return &EPSSClient{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		baseURL:  "https://api.first.org/data/v1/epss",
		cache:    make(map[string]*EPSSScore),
		cacheTTL: 24 * time.Hour, // EPSS scores update daily
	}
}

// GetScore fetches the EPSS score for a single CVE
func (c *EPSSClient) GetScore(ctx context.Context, cve string) (*EPSSScore, error) {
	// Check cache first
	c.mu.RLock()
	if cached, ok := c.cache[cve]; ok {
		if time.Since(cached.FetchedAt) < c.cacheTTL {
			c.mu.RUnlock()
			c.mu.Lock()
			c.cacheHits++
			c.mu.Unlock()
			return cached, nil
		}
	}
	c.mu.RUnlock()

	c.mu.Lock()
	c.cacheMiss++
	c.mu.Unlock()

	// Fetch from API
	url := fmt.Sprintf("%s?cve=%s", c.baseURL, cve)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch EPSS score: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("EPSS API returned status %d", resp.StatusCode)
	}

	var epssResp EPSSResponse
	if err := json.NewDecoder(resp.Body).Decode(&epssResp); err != nil {
		return nil, fmt.Errorf("decode EPSS response: %w", err)
	}

	if len(epssResp.Data) == 0 {
		return nil, nil // CVE not found in EPSS database
	}

	score := c.parseScore(epssResp.Data[0])

	// Cache the result
	c.mu.Lock()
	c.cache[cve] = score
	c.mu.Unlock()

	return score, nil
}

// GetScoresBatch fetches EPSS scores for multiple CVEs efficiently
func (c *EPSSClient) GetScoresBatch(ctx context.Context, cves []string) (map[string]*EPSSScore, error) {
	results := make(map[string]*EPSSScore)
	var toFetch []string

	// Check cache first
	c.mu.RLock()
	for _, cve := range cves {
		if cached, ok := c.cache[cve]; ok && time.Since(cached.FetchedAt) < c.cacheTTL {
			results[cve] = cached
		} else {
			toFetch = append(toFetch, cve)
		}
	}
	c.mu.RUnlock()

	if len(toFetch) == 0 {
		return results, nil
	}

	// Batch fetch in chunks of 100 (API limit)
	const batchSize = 100
	for i := 0; i < len(toFetch); i += batchSize {
		end := i + batchSize
		if end > len(toFetch) {
			end = len(toFetch)
		}
		batch := toFetch[i:end]

		scores, err := c.fetchBatch(ctx, batch)
		if err != nil {
			return results, fmt.Errorf("fetch batch: %w", err)
		}

		c.mu.Lock()
		for cve, score := range scores {
			c.cache[cve] = score
			results[cve] = score
		}
		c.mu.Unlock()
	}

	return results, nil
}

func (c *EPSSClient) fetchBatch(ctx context.Context, cves []string) (map[string]*EPSSScore, error) {
	if len(cves) == 0 {
		return make(map[string]*EPSSScore), nil
	}

	// Build comma-separated CVE list efficiently
	cveList := strings.Join(cves, ",")

	url := fmt.Sprintf("%s?cve=%s", c.baseURL, cveList)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("EPSS API returned status %d", resp.StatusCode)
	}

	var epssResp EPSSResponse
	if err := json.NewDecoder(resp.Body).Decode(&epssResp); err != nil {
		return nil, err
	}

	results := make(map[string]*EPSSScore)
	for _, data := range epssResp.Data {
		score := c.parseScore(data)
		results[score.CVE] = score
	}

	return results, nil
}

func (c *EPSSClient) parseScore(data struct {
	CVE        string `json:"cve"`
	EPSS       string `json:"epss"`
	Percentile string `json:"percentile"`
	Date       string `json:"date"`
}) *EPSSScore {
	epss, err := strconv.ParseFloat(data.EPSS, 64)
	if err != nil {
		slog.Warn("failed to parse EPSS score",
			"cve", data.CVE,
			"value", data.EPSS,
			"error", err,
		)
		epss = 0
	}

	percentile, err := strconv.ParseFloat(data.Percentile, 64)
	if err != nil {
		slog.Warn("failed to parse EPSS percentile",
			"cve", data.CVE,
			"value", data.Percentile,
			"error", err,
		)
		percentile = 0
	}

	return &EPSSScore{
		CVE:        data.CVE,
		EPSS:       epss,
		Percentile: percentile,
		Date:       data.Date,
		FetchedAt:  time.Now(),
	}
}

// CacheStats returns cache size and hit rate (0.0-1.0)
func (c *EPSSClient) CacheStats() (size int, hitRate float64) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	total := c.cacheHits + c.cacheMiss
	if total > 0 {
		hitRate = float64(c.cacheHits) / float64(total)
	}
	return len(c.cache), hitRate
}

// ClearCache removes all cached scores and resets hit rate counters
func (c *EPSSClient) ClearCache() {
	c.mu.Lock()
	c.cache = make(map[string]*EPSSScore)
	c.cacheHits = 0
	c.cacheMiss = 0
	c.mu.Unlock()
}

// VulnerabilityRiskScore calculates a composite risk score combining CVSS and EPSS
type VulnerabilityRiskScore struct {
	CVE              string  `json:"cve"`
	CVSSScore        float64 `json:"cvss_score"`
	EPSSScore        float64 `json:"epss_score"`
	EPSSPercentile   float64 `json:"epss_percentile"`
	IsKEV            bool    `json:"is_kev"`             // In CISA KEV list
	HasPublicExploit bool    `json:"has_public_exploit"` // Exploit-DB, Metasploit, etc.
	CompositeScore   float64 `json:"composite_score"`    // 0-100 normalized score
	Priority         string  `json:"priority"`           // critical, high, medium, low
	Reasoning        string  `json:"reasoning"`
}

// CalculateVulnerabilityRisk computes a composite risk score
func CalculateVulnerabilityRisk(cvss float64, epss *EPSSScore, isKEV, hasExploit bool) *VulnerabilityRiskScore {
	score := &VulnerabilityRiskScore{
		CVSSScore:        cvss,
		IsKEV:            isKEV,
		HasPublicExploit: hasExploit,
	}

	if epss != nil {
		score.CVE = epss.CVE
		score.EPSSScore = epss.EPSS
		score.EPSSPercentile = epss.Percentile
	}

	// Calculate composite score using weighted factors
	// Base: CVSS contributes 40%, EPSS contributes 40%, Context 20%
	cvssContrib := (cvss / 10.0) * 40.0

	epssContrib := 0.0
	if epss != nil {
		// Use percentile for more even distribution
		epssContrib = epss.Percentile * 40.0
	}

	contextContrib := 0.0
	var reasons []string

	// KEV is a strong signal - actively exploited
	if isKEV {
		contextContrib += 15.0
		reasons = append(reasons, "In CISA KEV (actively exploited)")
	}

	// Public exploit availability
	if hasExploit {
		contextContrib += 5.0
		reasons = append(reasons, "Public exploit available")
	}

	score.CompositeScore = cvssContrib + epssContrib + contextContrib
	if score.CompositeScore > 100 {
		score.CompositeScore = 100
	}

	// Determine priority
	switch {
	case isKEV || score.CompositeScore >= 80:
		score.Priority = "critical"
		if isKEV {
			reasons = append(reasons, "Requires immediate patching per CISA directive")
		}
	case score.CompositeScore >= 60:
		score.Priority = "high"
	case score.CompositeScore >= 40:
		score.Priority = "medium"
	default:
		score.Priority = "low"
	}

	// Build reasoning
	if epss != nil && epss.EPSS > 0.1 {
		reasons = append(reasons, fmt.Sprintf("High exploitation probability (%.1f%%)", epss.EPSS*100))
	}
	if cvss >= 9.0 {
		reasons = append(reasons, "Critical CVSS severity")
	}

	if len(reasons) > 0 {
		score.Reasoning = reasons[0]
		for i := 1; i < len(reasons); i++ {
			score.Reasoning += "; " + reasons[i]
		}
	}

	return score
}
