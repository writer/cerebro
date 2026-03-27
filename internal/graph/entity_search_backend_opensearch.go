package graph

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

const defaultOpenSearchEntitySearchMaxCandidates = 100

type openSearchHTTPSigner interface {
	SignHTTP(ctx context.Context, credentials aws.Credentials, r *http.Request, payloadHash string, service string, region string, signingTime time.Time, optFns ...func(*v4.SignerOptions)) error
}

type OpenSearchEntitySearchBackendOptions struct {
	Endpoint      string
	Region        string
	Index         string
	HTTPClient    *http.Client
	Credentials   aws.CredentialsProvider
	Signer        openSearchHTTPSigner
	HydrateEntity func(context.Context, string, string) (EntityRecord, bool, error)
	Now           func() time.Time
	MaxCandidates int
}

type OpenSearchEntitySearchBackend struct {
	endpoint      *url.URL
	region        string
	index         string
	httpClient    *http.Client
	credentials   aws.CredentialsProvider
	signer        openSearchHTTPSigner
	hydrateEntity func(context.Context, string, string) (EntityRecord, bool, error)
	now           func() time.Time
	maxCandidates int
}

type openSearchEntitySearchResponse struct {
	Hits struct {
		Hits []openSearchEntitySearchHitResponse `json:"hits"`
	} `json:"hits"`
}

type openSearchEntitySearchHitResponse struct {
	ID     string                   `json:"_id"`
	Score  float64                  `json:"_score"`
	Source openSearchEntityDocument `json:"_source"`
}

type openSearchEntityDocument struct {
	GraphID  string   `json:"graphId"`
	Kind     NodeKind `json:"kind"`
	Name     string   `json:"name"`
	Provider string   `json:"provider"`
	Account  string   `json:"account"`
	Region   string   `json:"region"`
}

func NewOpenSearchEntitySearchBackend(opts OpenSearchEntitySearchBackendOptions) (*OpenSearchEntitySearchBackend, error) {
	endpoint := strings.TrimSpace(opts.Endpoint)
	if endpoint == "" {
		return nil, fmt.Errorf("opensearch endpoint is required")
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("parse opensearch endpoint: %w", err)
	}
	if strings.TrimSpace(parsed.Scheme) == "" || strings.TrimSpace(parsed.Host) == "" {
		return nil, fmt.Errorf("opensearch endpoint must include scheme and host")
	}
	region := strings.TrimSpace(opts.Region)
	if region == "" {
		return nil, fmt.Errorf("opensearch region is required")
	}
	index := strings.TrimSpace(opts.Index)
	if index == "" {
		return nil, fmt.Errorf("opensearch index is required")
	}
	if opts.HTTPClient == nil {
		opts.HTTPClient = &http.Client{Timeout: 5 * time.Second}
	}
	if opts.Credentials == nil {
		return nil, fmt.Errorf("opensearch credentials provider is required")
	}
	if opts.Signer == nil {
		opts.Signer = v4.NewSigner()
	}
	if opts.HydrateEntity == nil {
		return nil, fmt.Errorf("opensearch entity hydrator is required")
	}
	if opts.Now == nil {
		opts.Now = temporalNowUTC
	}
	if opts.MaxCandidates <= 0 {
		opts.MaxCandidates = defaultOpenSearchEntitySearchMaxCandidates
	}
	return &OpenSearchEntitySearchBackend{
		endpoint:      parsed,
		region:        region,
		index:         index,
		httpClient:    opts.HTTPClient,
		credentials:   opts.Credentials,
		signer:        opts.Signer,
		hydrateEntity: opts.HydrateEntity,
		now:           opts.Now,
		maxCandidates: opts.MaxCandidates,
	}, nil
}

func (b *OpenSearchEntitySearchBackend) Backend() EntitySearchBackendType {
	return EntitySearchBackendOpenSearch
}

func (b *OpenSearchEntitySearchBackend) Search(ctx context.Context, tenantID string, opts EntitySearchOptions) (EntitySearchCollection, error) {
	query := normalizeEntitySearchOptions(opts)
	result := EntitySearchCollection{
		GeneratedAt: temporalNowUTC(),
		Query:       query.Query,
		Fuzzy:       query.Fuzzy,
	}
	if query.Query == "" {
		return result, nil
	}
	allowedKinds, ok := openSearchAllowedEntityKinds(query.Kinds)
	if !ok {
		return result, nil
	}
	allowedKindSet := openSearchEntityKindSet(allowedKinds)

	hits, err := b.searchHits(ctx, tenantID, query, allowedKinds, allowedKindSet)
	if err != nil {
		return result, err
	}
	if len(hits) == 0 {
		return result, nil
	}

	results := make([]EntitySearchResult, 0, min(query.Limit, len(hits)))
	seen := make(map[string]struct{}, len(hits))
	for _, hit := range hits {
		if _, ok := seen[hit.EntityID]; ok {
			continue
		}
		seen[hit.EntityID] = struct{}{}

		record, ok, err := b.hydrateEntity(ctx, strings.TrimSpace(tenantID), hit.EntityID)
		if err != nil {
			return result, err
		}
		if !ok {
			continue
		}
		results = append(results, EntitySearchResult{
			Entity:        record,
			Score:         hit.Score,
			MatchedFields: hit.MatchedFields,
		})
		if len(results) >= query.Limit {
			break
		}
	}

	sort.Slice(results, func(i, j int) bool {
		if results[i].Score != results[j].Score {
			return results[i].Score > results[j].Score
		}
		if results[i].Entity.Risk != results[j].Entity.Risk {
			return entityRiskOrder(results[i].Entity.Risk) < entityRiskOrder(results[j].Entity.Risk)
		}
		if results[i].Entity.Name != results[j].Entity.Name {
			return results[i].Entity.Name < results[j].Entity.Name
		}
		return results[i].Entity.ID < results[j].Entity.ID
	})

	result.Results = results
	result.Count = len(results)
	return result, nil
}

func (b *OpenSearchEntitySearchBackend) Suggest(ctx context.Context, tenantID string, opts EntitySuggestOptions) (EntitySuggestCollection, error) {
	query := normalizeEntitySuggestOptions(opts)
	result := EntitySuggestCollection{
		GeneratedAt: temporalNowUTC(),
		Prefix:      query.Prefix,
	}
	if query.Prefix == "" {
		return result, nil
	}
	allowedKinds, ok := openSearchAllowedEntityKinds(query.Kinds)
	if !ok {
		return result, nil
	}
	allowedKindSet := openSearchEntityKindSet(allowedKinds)

	var response openSearchEntitySearchResponse
	if err := b.executeSearch(ctx, b.buildSuggestRequest(strings.TrimSpace(tenantID), query, allowedKinds), &response); err != nil {
		return result, err
	}

	normalizedPrefix := entitySearchNormalize(query.Prefix)
	suggestions := make([]EntitySuggestion, 0, len(response.Hits.Hits)*2)
	seen := make(map[string]struct{}, len(response.Hits.Hits)*2)
	for _, hit := range response.Hits.Hits {
		if !openSearchEntityKindAllowed(hit.Source.Kind, allowedKindSet) {
			continue
		}
		entityID := strings.TrimSpace(firstNonEmpty(hit.Source.GraphID, hit.ID))
		if entityID == "" {
			continue
		}
		candidates := []EntitySuggestion{
			{
				EntityID: entityID,
				Kind:     hit.Source.Kind,
				Name:     strings.TrimSpace(hit.Source.Name),
				Value:    strings.TrimSpace(hit.Source.Name),
			},
			{
				EntityID: entityID,
				Kind:     hit.Source.Kind,
				Name:     strings.TrimSpace(hit.Source.Name),
				Value:    entityID,
			},
		}
		for _, suggestion := range candidates {
			if strings.TrimSpace(suggestion.Value) == "" || !strings.HasPrefix(entitySearchNormalize(suggestion.Value), normalizedPrefix) {
				continue
			}
			key := suggestion.EntityID + "\x00" + entitySearchNormalize(suggestion.Value)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			suggestions = append(suggestions, suggestion)
		}
	}

	sort.Slice(suggestions, func(i, j int) bool {
		left := entitySearchNormalize(suggestions[i].Value)
		right := entitySearchNormalize(suggestions[j].Value)
		if len(left) != len(right) {
			return len(left) < len(right)
		}
		if suggestions[i].Kind != suggestions[j].Kind {
			return suggestions[i].Kind < suggestions[j].Kind
		}
		if suggestions[i].Value != suggestions[j].Value {
			return suggestions[i].Value < suggestions[j].Value
		}
		return suggestions[i].EntityID < suggestions[j].EntityID
	})

	if len(suggestions) > query.Limit {
		suggestions = suggestions[:query.Limit]
	}
	result.Suggestions = suggestions
	result.Count = len(suggestions)
	return result, nil
}

type openSearchEntitySearchHit struct {
	EntityID      string
	Score         float64
	MatchedFields []string
}

func (b *OpenSearchEntitySearchBackend) searchHits(ctx context.Context, tenantID string, query EntitySearchOptions, allowedKinds []NodeKind, allowedKindSet map[NodeKind]struct{}) ([]openSearchEntitySearchHit, error) {
	var response openSearchEntitySearchResponse
	if err := b.executeSearch(ctx, b.buildSearchRequest(strings.TrimSpace(tenantID), query, allowedKinds), &response); err != nil {
		return nil, err
	}

	hits := make([]openSearchEntitySearchHit, 0, len(response.Hits.Hits))
	for _, hit := range response.Hits.Hits {
		if !openSearchEntityKindAllowed(hit.Source.Kind, allowedKindSet) {
			continue
		}
		entityID := strings.TrimSpace(firstNonEmpty(hit.Source.GraphID, hit.ID))
		if entityID == "" {
			continue
		}
		hits = append(hits, openSearchEntitySearchHit{
			EntityID:      entityID,
			Score:         hit.Score,
			MatchedFields: openSearchMatchedFields(query.Query, hit.Source),
		})
	}
	return hits, nil
}

func (b *OpenSearchEntitySearchBackend) executeSearch(ctx context.Context, payload any, out any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal opensearch request: %w", err)
	}

	requestURL := *b.endpoint
	requestURL.Path = path.Join("/", b.endpoint.Path, b.index, "_search")
	requestURL.RawQuery = ""
	requestURL.Fragment = ""

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL.String(), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build opensearch request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	sum := sha256.Sum256(body)
	payloadHash := hex.EncodeToString(sum[:])
	creds, err := b.credentials.Retrieve(ctx)
	if err != nil {
		return fmt.Errorf("retrieve opensearch credentials: %w", err)
	}
	if err := b.signer.SignHTTP(ctx, creds, req, payloadHash, "es", b.region, b.now().UTC()); err != nil {
		return fmt.Errorf("sign opensearch request: %w", err)
	}

	resp, err := b.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("execute opensearch request: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		return fmt.Errorf("opensearch request failed: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decode opensearch response: %w", err)
	}
	return nil
}

func (b *OpenSearchEntitySearchBackend) Check(ctx context.Context) error {
	allowedKinds, ok := openSearchAllowedEntityKinds(nil)
	if !ok {
		return fmt.Errorf("no searchable entity kinds configured")
	}
	var response openSearchEntitySearchResponse
	return b.executeSearch(ctx, map[string]any{
		"size":             0,
		"track_total_hits": false,
		"query": map[string]any{
			"bool": map[string]any{
				"filter": openSearchEntitySearchFilters("", allowedKinds),
			},
		},
	}, &response)
}

func (b *OpenSearchEntitySearchBackend) buildSearchRequest(tenantID string, query EntitySearchOptions, allowedKinds []NodeKind) map[string]any {
	should := []any{
		map[string]any{
			"multi_match": map[string]any{
				"query":    query.Query,
				"fields":   []string{"name^5", "fullText^2"},
				"type":     "best_fields",
				"operator": "and",
				"boost":    3,
			},
		},
		map[string]any{
			"match_phrase_prefix": map[string]any{
				"name": map[string]any{
					"query": query.Query,
					"boost": 4,
				},
			},
		},
	}
	if query.Fuzzy {
		should = append(should, map[string]any{
			"multi_match": map[string]any{
				"query":         query.Query,
				"fields":        []string{"name^4", "fullText"},
				"type":          "best_fields",
				"fuzziness":     "AUTO",
				"prefix_length": 1,
				"boost":         1.5,
			},
		})
	}
	if clause := openSearchGraphIDWildcardClause(query.Query, true, true, 6); clause != nil {
		should = append(should, clause)
	}

	return map[string]any{
		"size":             b.candidateLimit(query.Limit, 4),
		"track_total_hits": false,
		"_source":          []string{"graphId", "kind", "name", "provider", "account", "region"},
		"query": map[string]any{
			"bool": map[string]any{
				"filter":               openSearchEntitySearchFilters(tenantID, allowedKinds),
				"should":               should,
				"minimum_should_match": 1,
			},
		},
	}
}

func (b *OpenSearchEntitySearchBackend) buildSuggestRequest(tenantID string, query EntitySuggestOptions, allowedKinds []NodeKind) map[string]any {
	should := []any{
		map[string]any{
			"wildcard": map[string]any{
				"name.keyword": map[string]any{
					"value":            openSearchPrefixPattern(query.Prefix),
					"case_insensitive": true,
					"boost":            5,
				},
			},
		},
		map[string]any{
			"match_phrase_prefix": map[string]any{
				"name": map[string]any{
					"query": query.Prefix,
					"boost": 4,
				},
			},
		},
	}
	if clause := openSearchGraphIDWildcardClause(query.Prefix, false, true, 4); clause != nil {
		should = append(should, clause)
	}

	return map[string]any{
		"size":             b.candidateLimit(query.Limit, 6),
		"track_total_hits": false,
		"_source":          []string{"graphId", "kind", "name"},
		"query": map[string]any{
			"bool": map[string]any{
				"filter":               openSearchEntitySearchFilters(tenantID, allowedKinds),
				"should":               should,
				"minimum_should_match": 1,
			},
		},
	}
}

func openSearchEntitySearchFilters(tenantID string, kinds []NodeKind) []any {
	filters := []any{
		map[string]any{
			"term": map[string]any{
				"entityKind": "node",
			},
		},
	}
	values := make([]string, 0, len(kinds))
	for _, kind := range kinds {
		values = append(values, string(kind))
	}
	if len(values) > 0 {
		filters = append(filters, map[string]any{
			"terms": map[string]any{
				"kind": values,
			},
		})
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return filters
	}
	filters = append(filters, map[string]any{
		"bool": map[string]any{
			"should": []any{
				map[string]any{
					"term": map[string]any{
						"tenantId": tenantID,
					},
				},
				map[string]any{
					"term": map[string]any{
						"tenantId": "",
					},
				},
				map[string]any{
					"bool": map[string]any{
						"must_not": []any{
							map[string]any{
								"exists": map[string]any{
									"field": "tenantId",
								},
							},
						},
					},
				},
			},
			"minimum_should_match": 1,
		},
	})
	return filters
}

func (b *OpenSearchEntitySearchBackend) candidateLimit(limit, multiplier int) int {
	if limit <= 0 {
		limit = defaultEntitySearchLimit
	}
	if multiplier <= 0 {
		multiplier = 1
	}
	size := limit * multiplier
	if size < limit {
		size = limit
	}
	if b.maxCandidates > 0 && size > b.maxCandidates {
		size = b.maxCandidates
	}
	return size
}

func openSearchMatchedFields(query string, source openSearchEntityDocument) []string {
	normalizedQuery := entitySearchNormalize(query)
	if normalizedQuery == "" {
		return nil
	}
	fields := make([]string, 0, 5)
	appendField := func(field string) {
		for _, existing := range fields {
			if existing == field {
				return
			}
		}
		fields = append(fields, field)
	}

	if strings.Contains(entitySearchNormalize(source.Name), normalizedQuery) {
		appendField("name")
	}
	if strings.Contains(entitySearchNormalize(source.GraphID), normalizedQuery) {
		appendField("id")
	}
	if strings.Contains(entitySearchNormalize(string(source.Kind)), normalizedQuery) {
		appendField("kind")
	}
	if strings.Contains(entitySearchNormalize(source.Provider), normalizedQuery) {
		appendField("provider")
	}
	if strings.Contains(entitySearchNormalize(source.Region), normalizedQuery) {
		appendField("region")
	}
	return fields
}

func openSearchPrefixPattern(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	return value + "*"
}

func openSearchGraphIDWildcardClause(value string, leading, trailing bool, boost float64) map[string]any {
	value = strings.TrimSpace(value)
	if value == "" || strings.ContainsAny(value, "*?") {
		return nil
	}
	pattern := value
	if leading {
		pattern = "*" + pattern
	}
	if trailing {
		pattern += "*"
	}
	return map[string]any{
		"wildcard": map[string]any{
			"graphId": map[string]any{
				"value":            pattern,
				"case_insensitive": true,
				"boost":            boost,
			},
		},
	}
}

func openSearchAllowedEntityKinds(requested []NodeKind) ([]NodeKind, bool) {
	if len(requested) > 0 {
		allowed := make([]NodeKind, 0, len(requested))
		for _, kind := range uniqueSortedNodeKinds(requested) {
			if entityQueryAllowedNodeKind(kind) {
				allowed = append(allowed, kind)
			}
		}
		return allowed, len(allowed) > 0
	}
	registered := RegisteredNodeKinds()
	allowed := make([]NodeKind, 0, len(registered))
	for _, def := range registered {
		if entityQueryAllowedNodeKind(def.Kind) {
			allowed = append(allowed, def.Kind)
		}
	}
	allowed = uniqueSortedNodeKinds(allowed)
	return allowed, len(allowed) > 0
}

func openSearchEntityKindSet(kinds []NodeKind) map[NodeKind]struct{} {
	set := make(map[NodeKind]struct{}, len(kinds))
	for _, kind := range kinds {
		set[kind] = struct{}{}
	}
	return set
}

func openSearchEntityKindAllowed(kind NodeKind, allowed map[NodeKind]struct{}) bool {
	if len(allowed) == 0 {
		return entityQueryAllowedNodeKind(kind)
	}
	_, ok := allowed[kind]
	return ok
}
