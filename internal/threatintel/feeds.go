package threatintel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ThreatIntelService manages threat intelligence feeds
type ThreatIntelService struct {
	feeds       map[string]Feed
	indicators  *IndicatorStore
	client      *http.Client
	lastUpdated time.Time
	mu          sync.RWMutex
}

// Feed represents a threat intelligence feed
type Feed struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Type        FeedType  `json:"type"`
	URL         string    `json:"url"`
	Format      string    `json:"format"` // json, csv, stix
	Enabled     bool      `json:"enabled"`
	LastSync    time.Time `json:"last_sync"`
	Indicators  int       `json:"indicator_count"`
}

type FeedType string

const (
	FeedTypeVulnerability FeedType = "vulnerability"
	FeedTypeMalwareIP     FeedType = "malware_ip"
	FeedTypeMalwareDomain FeedType = "malware_domain"
	FeedTypeExploit       FeedType = "exploit"
	FeedTypeIndicator     FeedType = "indicator"
)

// Indicator represents a threat indicator
type Indicator struct {
	ID          string            `json:"id"`
	Type        IndicatorType     `json:"type"`
	Value       string            `json:"value"`
	Source      string            `json:"source"`
	Severity    string            `json:"severity"`
	Confidence  int               `json:"confidence"` // 0-100
	FirstSeen   time.Time         `json:"first_seen"`
	LastSeen    time.Time         `json:"last_seen"`
	Description string            `json:"description,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

type IndicatorType string

const (
	IndicatorTypeIP     IndicatorType = "ip"
	IndicatorTypeDomain IndicatorType = "domain"
	IndicatorTypeHash   IndicatorType = "hash"
	IndicatorTypeCVE    IndicatorType = "cve"
	IndicatorTypeURL    IndicatorType = "url"
)

// IndicatorStore stores indicators in memory with fast lookup
type IndicatorStore struct {
	byType map[IndicatorType]map[string]*Indicator
	all    []*Indicator
	mu     sync.RWMutex
}

func NewIndicatorStore() *IndicatorStore {
	return &IndicatorStore{
		byType: make(map[IndicatorType]map[string]*Indicator),
		all:    make([]*Indicator, 0),
	}
}

func (s *IndicatorStore) Add(ind *Indicator) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.byType[ind.Type] == nil {
		s.byType[ind.Type] = make(map[string]*Indicator)
	}
	s.byType[ind.Type][ind.Value] = ind
	s.all = append(s.all, ind)
}

func (s *IndicatorStore) Lookup(indType IndicatorType, value string) (*Indicator, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if m, ok := s.byType[indType]; ok {
		if ind, found := m[value]; found {
			return ind, true
		}
	}
	return nil, false
}

func (s *IndicatorStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.all)
}

func (s *IndicatorStore) CountByType() map[IndicatorType]int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	counts := make(map[IndicatorType]int)
	for t, m := range s.byType {
		counts[t] = len(m)
	}
	return counts
}

func NewThreatIntelService() *ThreatIntelService {
	svc := &ThreatIntelService{
		feeds:      make(map[string]Feed),
		indicators: NewIndicatorStore(),
		client: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
	svc.loadDefaultFeeds()
	return svc
}

func (s *ThreatIntelService) loadDefaultFeeds() {
	s.feeds = map[string]Feed{
		"cisa-kev": {
			ID:          "cisa-kev",
			Name:        "CISA Known Exploited Vulnerabilities",
			Description: "CISA catalog of actively exploited vulnerabilities",
			Type:        FeedTypeVulnerability,
			URL:         "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
			Format:      "json",
			Enabled:     true,
		},
		"nvd-cve": {
			ID:          "nvd-cve",
			Name:        "NVD CVE Feed",
			Description: "NIST National Vulnerability Database",
			Type:        FeedTypeVulnerability,
			URL:         "https://services.nvd.nist.gov/rest/json/cves/2.0",
			Format:      "json",
			Enabled:     true,
		},
		"abuse-ch-ip": {
			ID:          "abuse-ch-ip",
			Name:        "Abuse.ch Feodo Tracker",
			Description: "Botnet C&C server IP addresses",
			Type:        FeedTypeMalwareIP,
			URL:         "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
			Format:      "json",
			Enabled:     true,
		},
		"abuse-ch-domains": {
			ID:          "abuse-ch-domains",
			Name:        "Abuse.ch URLhaus",
			Description: "Malware distribution URLs",
			Type:        FeedTypeMalwareDomain,
			URL:         "https://urlhaus.abuse.ch/downloads/json/",
			Format:      "json",
			Enabled:     true,
		},
	}
}

// ListFeeds returns all configured feeds
func (s *ThreatIntelService) ListFeeds() []Feed {
	s.mu.RLock()
	defer s.mu.RUnlock()

	feeds := make([]Feed, 0, len(s.feeds))
	for _, f := range s.feeds {
		feeds = append(feeds, f)
	}
	return feeds
}

// SyncFeed fetches and parses a specific feed
func (s *ThreatIntelService) SyncFeed(ctx context.Context, feedID string) error {
	s.mu.RLock()
	feed, ok := s.feeds[feedID]
	s.mu.RUnlock()

	if !ok {
		return fmt.Errorf("feed not found: %s", feedID)
	}

	if !feed.Enabled {
		return fmt.Errorf("feed is disabled: %s", feedID)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", feed.URL, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch feed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("feed returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}

	count := s.parseFeed(feed, body)

	s.mu.Lock()
	feed.LastSync = time.Now().UTC()
	feed.Indicators = count
	s.feeds[feedID] = feed
	s.lastUpdated = time.Now().UTC()
	s.mu.Unlock()

	return nil
}

func (s *ThreatIntelService) parseFeed(feed Feed, data []byte) int {
	switch feed.ID {
	case "cisa-kev":
		return s.parseCISAKEV(data)
	case "abuse-ch-ip":
		return s.parseAbuseChIP(data)
	default:
		// Generic JSON parsing
		return s.parseGenericJSON(data)
	}
}

func (s *ThreatIntelService) parseCISAKEV(data []byte) int {
	var kev struct {
		Vulnerabilities []struct {
			CveID              string `json:"cveID"`
			VendorProject      string `json:"vendorProject"`
			Product            string `json:"product"`
			VulnerabilityName  string `json:"vulnerabilityName"`
			DateAdded          string `json:"dateAdded"`
			ShortDescription   string `json:"shortDescription"`
			RequiredAction     string `json:"requiredAction"`
			DueDate            string `json:"dueDate"`
			KnownRansomware    string `json:"knownRansomwareCampaignUse"`
		} `json:"vulnerabilities"`
	}

	if err := json.Unmarshal(data, &kev); err != nil {
		return 0
	}

	for _, v := range kev.Vulnerabilities {
		ind := &Indicator{
			ID:          v.CveID,
			Type:        IndicatorTypeCVE,
			Value:       v.CveID,
			Source:      "cisa-kev",
			Severity:    "critical", // KEV = actively exploited
			Confidence:  100,
			Description: v.ShortDescription,
			Tags:        []string{"kev", "actively-exploited"},
			Metadata: map[string]string{
				"vendor":           v.VendorProject,
				"product":          v.Product,
				"due_date":         v.DueDate,
				"ransomware":       v.KnownRansomware,
				"required_action":  v.RequiredAction,
			},
		}
		if v.DateAdded != "" {
			ind.FirstSeen, _ = time.Parse("2006-01-02", v.DateAdded)
		}
		s.indicators.Add(ind)
	}

	return len(kev.Vulnerabilities)
}

func (s *ThreatIntelService) parseAbuseChIP(data []byte) int {
	var feodo struct {
		IPAddresses []struct {
			IP          string `json:"ip_address"`
			Port        int    `json:"port"`
			Status      string `json:"status"`
			Hostname    string `json:"hostname"`
			ASNumber    int    `json:"as_number"`
			ASName      string `json:"as_name"`
			Country     string `json:"country"`
			FirstSeen   string `json:"first_seen"`
			LastOnline  string `json:"last_online"`
			Malware     string `json:"malware"`
		} `json:"ip_addresses"`
	}

	if err := json.Unmarshal(data, &feodo); err != nil {
		// Try alternate format
		return s.parseAbuseChIPAlt(data)
	}

	for _, ip := range feodo.IPAddresses {
		ind := &Indicator{
			ID:         fmt.Sprintf("feodo-%s", ip.IP),
			Type:       IndicatorTypeIP,
			Value:      ip.IP,
			Source:     "abuse-ch-feodo",
			Severity:   "high",
			Confidence: 90,
			Tags:       []string{"botnet", "c2", ip.Malware},
			Metadata: map[string]string{
				"malware": ip.Malware,
				"country": ip.Country,
				"as_name": ip.ASName,
			},
		}
		if ip.FirstSeen != "" {
			ind.FirstSeen, _ = time.Parse("2006-01-02 15:04:05", ip.FirstSeen)
		}
		s.indicators.Add(ind)
	}

	return len(feodo.IPAddresses)
}

func (s *ThreatIntelService) parseAbuseChIPAlt(data []byte) int {
	// Simple line-based IP list
	lines := strings.Split(string(data), "\n")
	count := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		s.indicators.Add(&Indicator{
			ID:         fmt.Sprintf("ip-%s", line),
			Type:       IndicatorTypeIP,
			Value:      line,
			Source:     "abuse-ch",
			Severity:   "high",
			Confidence: 85,
			Tags:       []string{"malware", "c2"},
		})
		count++
	}
	return count
}

func (s *ThreatIntelService) parseGenericJSON(data []byte) int {
	// Try to parse as array of objects
	var items []map[string]interface{}
	if err := json.Unmarshal(data, &items); err != nil {
		return 0
	}
	return len(items)
}

// LookupIP checks if an IP is in threat intel
func (s *ThreatIntelService) LookupIP(ip string) (*Indicator, bool) {
	return s.indicators.Lookup(IndicatorTypeIP, ip)
}

// LookupDomain checks if a domain is in threat intel
func (s *ThreatIntelService) LookupDomain(domain string) (*Indicator, bool) {
	return s.indicators.Lookup(IndicatorTypeDomain, domain)
}

// LookupCVE checks if a CVE is in threat intel (KEV)
func (s *ThreatIntelService) LookupCVE(cve string) (*Indicator, bool) {
	return s.indicators.Lookup(IndicatorTypeCVE, cve)
}

// IsKEV checks if a CVE is in CISA Known Exploited Vulnerabilities
func (s *ThreatIntelService) IsKEV(cve string) bool {
	ind, found := s.LookupCVE(cve)
	return found && ind.Source == "cisa-kev"
}

// Stats returns threat intel statistics
func (s *ThreatIntelService) Stats() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return map[string]interface{}{
		"total_indicators": s.indicators.Count(),
		"by_type":          s.indicators.CountByType(),
		"feeds_count":      len(s.feeds),
		"last_updated":     s.lastUpdated,
	}
}

// SyncAll syncs all enabled feeds
func (s *ThreatIntelService) SyncAll(ctx context.Context) error {
	s.mu.RLock()
	feeds := make([]string, 0)
	for id, f := range s.feeds {
		if f.Enabled {
			feeds = append(feeds, id)
		}
	}
	s.mu.RUnlock()

	var lastErr error
	for _, id := range feeds {
		if err := s.SyncFeed(ctx, id); err != nil {
			lastErr = err
		}
	}
	return lastErr
}
