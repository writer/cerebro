package threatintel

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

type CustomFeedManager struct {
	feeds      map[string]*CustomFeed
	indicators *IndicatorStore
	mu         sync.RWMutex
}

type CustomFeed struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Type        IndicatorType `json:"type"`
	Format      string        `json:"format"`
	Source      FeedSource    `json:"source"`
	Enabled     bool          `json:"enabled"`
	LastSync    time.Time     `json:"last_sync"`
	Indicators  int           `json:"indicator_count"`
	Tags        []string      `json:"tags"`
	CreatedBy   string        `json:"created_by"`
	CreatedAt   time.Time     `json:"created_at"`
}

type FeedSource struct {
	Type    string            `json:"type"`
	URL     string            `json:"url,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
}

type IOCEntry struct {
	Value       string   `json:"value"`
	Severity    string   `json:"severity,omitempty"`
	Description string   `json:"description,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

type FeedParseResult struct {
	TotalLines     int          `json:"total_lines"`
	ValidEntries   int          `json:"valid_entries"`
	InvalidEntries int          `json:"invalid_entries"`
	Errors         []string     `json:"errors,omitempty"`
	Indicators     []*Indicator `json:"-"`
}

func NewCustomFeedManager(store *IndicatorStore) *CustomFeedManager {
	return &CustomFeedManager{feeds: make(map[string]*CustomFeed), indicators: store}
}

func (m *CustomFeedManager) CreateFeed(feed *CustomFeed) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if feed.ID == "" {
		return fmt.Errorf("feed ID required")
	}
	feed.CreatedAt = time.Now()
	feed.Enabled = true
	m.feeds[feed.ID] = feed
	return nil
}

func (m *CustomFeedManager) UploadFeed(ctx context.Context, feedID string, data []byte) (*FeedParseResult, error) {
	m.mu.RLock()
	feed, exists := m.feeds[feedID]
	m.mu.RUnlock()
	if !exists {
		return nil, fmt.Errorf("feed not found")
	}
	result := m.parseData(feed, data)
	for _, ind := range result.Indicators {
		ind.Source = feedID
		m.indicators.Add(ind)
	}
	m.mu.Lock()
	feed.Indicators = result.ValidEntries
	feed.LastSync = time.Now()
	m.mu.Unlock()
	return result, nil
}

func (m *CustomFeedManager) SyncFeed(ctx context.Context, feedID string) (*FeedParseResult, error) {
	m.mu.RLock()
	feed, exists := m.feeds[feedID]
	m.mu.RUnlock()
	if !exists {
		return nil, fmt.Errorf("feed not found")
	}
	if feed.Source.Type != "url" {
		return nil, fmt.Errorf("feed source is not URL")
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", feed.Source.URL, nil)
	for k, v := range feed.Source.Headers {
		req.Header.Set(k, v)
	}
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	return m.UploadFeed(ctx, feedID, data)
}

func (m *CustomFeedManager) parseData(feed *CustomFeed, data []byte) *FeedParseResult {
	switch feed.Format {
	case "csv":
		return m.parseCSV(feed, data)
	case "json":
		return m.parseJSON(feed, data)
	default:
		return m.parseTXT(feed, data)
	}
}

func (m *CustomFeedManager) parseCSV(feed *CustomFeed, data []byte) *FeedParseResult {
	result := &FeedParseResult{}
	reader := csv.NewReader(strings.NewReader(string(data)))
	header, _ := reader.Read()
	colMap := make(map[string]int)
	for i, col := range header {
		colMap[strings.ToLower(col)] = i
	}
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			result.InvalidEntries++
			continue
		}
		result.TotalLines++
		ind := m.recordToIndicator(feed, record, colMap)
		if ind != nil {
			result.ValidEntries++
			result.Indicators = append(result.Indicators, ind)
		}
	}
	return result
}

func (m *CustomFeedManager) recordToIndicator(feed *CustomFeed, record []string, colMap map[string]int) *Indicator {
	var value string
	for _, col := range []string{"value", "indicator", "ip", "domain", "hash"} {
		if idx, ok := colMap[col]; ok && idx < len(record) {
			value = strings.TrimSpace(record[idx])
			break
		}
	}
	if value == "" && len(record) > 0 {
		value = strings.TrimSpace(record[0])
	}
	if value == "" {
		return nil
	}
	return &Indicator{ID: fmt.Sprintf("%s-%s", feed.ID, value), Type: feed.Type, Value: value, Source: feed.ID, Tags: feed.Tags}
}

func (m *CustomFeedManager) parseJSON(feed *CustomFeed, data []byte) *FeedParseResult {
	result := &FeedParseResult{}
	var entries []IOCEntry
	if err := json.Unmarshal(data, &entries); err == nil {
		result.TotalLines = len(entries)
		for _, e := range entries {
			if e.Value != "" {
				result.ValidEntries++
				result.Indicators = append(result.Indicators, &Indicator{ID: fmt.Sprintf("%s-%s", feed.ID, e.Value), Type: feed.Type, Value: e.Value, Source: feed.ID, Severity: e.Severity, Description: e.Description, Tags: append(feed.Tags, e.Tags...)})
			}
		}
	}
	return result
}

func (m *CustomFeedManager) parseTXT(feed *CustomFeed, data []byte) *FeedParseResult {
	result := &FeedParseResult{}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		result.TotalLines++
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		result.ValidEntries++
		result.Indicators = append(result.Indicators, &Indicator{ID: fmt.Sprintf("%s-%s", feed.ID, line), Type: feed.Type, Value: line, Source: feed.ID, Tags: feed.Tags})
	}
	return result
}

func (m *CustomFeedManager) ListFeeds() []*CustomFeed {
	m.mu.RLock()
	defer m.mu.RUnlock()
	feeds := make([]*CustomFeed, 0, len(m.feeds))
	for _, f := range m.feeds {
		feeds = append(feeds, f)
	}
	return feeds
}

func (m *CustomFeedManager) GetFeed(id string) (*CustomFeed, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	f, ok := m.feeds[id]
	return f, ok
}

func (m *CustomFeedManager) DeleteFeed(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.feeds, id)
	return nil
}
