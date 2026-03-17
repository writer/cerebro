package graph

import (
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/evalops/cerebro/internal/metrics"
)

const (
	defaultEntitySearchLimit  = 20
	maxEntitySearchLimit      = 100
	defaultEntitySuggestLimit = 10
	maxEntitySuggestLimit     = 25
)

type entitySearchDocument struct {
	ID                 string
	Kind               NodeKind
	Name               string
	NormalizedID       string
	NormalizedName     string
	NormalizedKind     string
	NormalizedProvider string
	NormalizedAccount  string
	NormalizedRegion   string
	SearchText         string
	Tokens             []string
	Suggestions        []string
}

type EntitySuggestion struct {
	EntityID string   `json:"entity_id"`
	Kind     NodeKind `json:"kind"`
	Name     string   `json:"name,omitempty"`
	Value    string   `json:"value"`
}

type EntitySearchOptions struct {
	Query string     `json:"query"`
	Kinds []NodeKind `json:"kinds,omitempty"`
	Limit int        `json:"limit,omitempty"`
	Fuzzy bool       `json:"fuzzy,omitempty"`
}

type EntitySearchResult struct {
	Entity        EntityRecord `json:"entity"`
	Score         float64      `json:"score"`
	MatchedFields []string     `json:"matched_fields,omitempty"`
}

type EntitySearchCollection struct {
	GeneratedAt time.Time            `json:"generated_at"`
	Query       string               `json:"query"`
	Fuzzy       bool                 `json:"fuzzy"`
	Count       int                  `json:"count"`
	Results     []EntitySearchResult `json:"results,omitempty"`
}

type EntitySuggestOptions struct {
	Prefix string     `json:"prefix"`
	Kinds  []NodeKind `json:"kinds,omitempty"`
	Limit  int        `json:"limit,omitempty"`
}

type EntitySuggestCollection struct {
	GeneratedAt time.Time          `json:"generated_at"`
	Prefix      string             `json:"prefix"`
	Count       int                `json:"count"`
	Suggestions []EntitySuggestion `json:"suggestions,omitempty"`
}

func SearchEntities(g *Graph, opts EntitySearchOptions) EntitySearchCollection {
	start := time.Now()
	defer func() {
		metrics.ObserveGraphSearch("entity_search", time.Since(start))
	}()

	query := normalizeEntitySearchOptions(opts)
	result := EntitySearchCollection{
		GeneratedAt: temporalNowUTC(),
		Query:       query.Query,
		Fuzzy:       query.Fuzzy,
	}
	if g == nil || query.Query == "" {
		return result
	}

	normalizedQuery := entitySearchNormalize(query.Query)
	queryTokens := entitySearchTokens(normalizedQuery)
	queryTrigrams := entitySearchTrigrams(normalizedQuery)
	candidateScores, documents := g.snapshotEntitySearchCandidates(normalizedQuery, queryTokens, queryTrigrams, query.Fuzzy)

	results := make([]EntitySearchResult, 0, len(candidateScores))
	for id, baseScore := range candidateScores {
		doc, ok := documents[id]
		if !ok || !entitySearchKindAllowed(doc.Kind, query.Kinds) {
			continue
		}
		score, fields := scoreEntitySearchDocument(doc, normalizedQuery, queryTokens)
		score += baseScore
		if score <= 0 {
			continue
		}
		record, ok := GetEntityRecord(g, id, temporalNowUTC(), temporalNowUTC())
		if !ok {
			continue
		}
		results = append(results, EntitySearchResult{
			Entity:        record,
			Score:         score,
			MatchedFields: fields,
		})
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

	if len(results) > query.Limit {
		results = results[:query.Limit]
	}
	result.Results = results
	result.Count = len(results)
	return result
}

func SuggestEntities(g *Graph, opts EntitySuggestOptions) EntitySuggestCollection {
	start := time.Now()
	defer func() {
		metrics.ObserveGraphSearch("entity_suggest", time.Since(start))
	}()

	query := normalizeEntitySuggestOptions(opts)
	result := EntitySuggestCollection{
		GeneratedAt: temporalNowUTC(),
		Prefix:      query.Prefix,
	}
	if g == nil || query.Prefix == "" {
		return result
	}

	normalizedPrefix := entitySearchNormalize(query.Prefix)
	candidates := g.snapshotEntitySuggestions(normalizedPrefix)

	if len(candidates) == 0 {
		return result
	}

	filtered := make([]EntitySuggestion, 0, len(candidates))
	seen := make(map[string]struct{})
	for _, candidate := range candidates {
		if !entitySearchKindAllowed(candidate.Kind, query.Kinds) {
			continue
		}
		key := candidate.EntityID + "\x00" + entitySearchNormalize(candidate.Value)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		filtered = append(filtered, candidate)
	}

	sort.Slice(filtered, func(i, j int) bool {
		leftPrefix := entitySearchNormalize(filtered[i].Value)
		rightPrefix := entitySearchNormalize(filtered[j].Value)
		if len(leftPrefix) != len(rightPrefix) {
			return len(leftPrefix) < len(rightPrefix)
		}
		if filtered[i].Kind != filtered[j].Kind {
			return filtered[i].Kind < filtered[j].Kind
		}
		if filtered[i].Value != filtered[j].Value {
			return filtered[i].Value < filtered[j].Value
		}
		return filtered[i].EntityID < filtered[j].EntityID
	})

	if len(filtered) > query.Limit {
		filtered = filtered[:query.Limit]
	}
	result.Suggestions = filtered
	result.Count = len(filtered)
	return result
}

func (g *Graph) snapshotEntitySearchCandidates(normalizedQuery string, queryTokens, queryTrigrams []string, fuzzy bool) (map[string]float64, map[string]entitySearchDocument) {
	needSuggestions := utf8.RuneCountInString(normalizedQuery) < 3

	g.mu.Lock()
	defer g.mu.Unlock()
	g.ensureEntitySearchIndexesLocked(needSuggestions)

	candidateScores := make(map[string]float64)
	for _, token := range queryTokens {
		for _, id := range g.entitySearchTokenIndex[token] {
			candidateScores[id] += 3
		}
	}
	if needSuggestions {
		for _, candidate := range g.entitySuggestIndex[normalizedQuery] {
			candidateScores[candidate.EntityID] += 2
		}
	} else if fuzzy || len(candidateScores) == 0 {
		for _, trigram := range queryTrigrams {
			for _, id := range g.entitySearchTrigramIndex[trigram] {
				candidateScores[id] += 1
			}
		}
	}

	documents := make(map[string]entitySearchDocument, len(candidateScores))
	for id := range candidateScores {
		if doc, ok := g.entitySearchDocs[id]; ok {
			documents[id] = doc
		}
	}
	return candidateScores, documents
}

func (g *Graph) snapshotEntitySuggestions(normalizedPrefix string) []EntitySuggestion {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.ensureEntitySearchIndexesLocked(true)
	return append([]EntitySuggestion(nil), g.entitySuggestIndex[normalizedPrefix]...)
}

func buildEntitySearchDocument(node *Node) (entitySearchDocument, bool) {
	if node == nil || node.DeletedAt != nil || !entityQueryAllowedNodeKind(node.Kind) {
		return entitySearchDocument{}, false
	}
	name := strings.TrimSpace(node.Name)
	id := strings.TrimSpace(node.ID)
	searchParts := []string{
		id,
		string(node.Kind),
		name,
		strings.TrimSpace(node.Provider),
		strings.TrimSpace(node.Account),
		strings.TrimSpace(node.Region),
	}
	for key, value := range node.Tags {
		searchParts = append(searchParts, key, value)
	}
	searchText := entitySearchNormalize(strings.Join(searchParts, " "))
	if searchText == "" {
		return entitySearchDocument{}, false
	}

	suggestions := []string{name, id}
	return entitySearchDocument{
		ID:                 id,
		Kind:               node.Kind,
		Name:               name,
		NormalizedID:       entitySearchNormalize(id),
		NormalizedName:     entitySearchNormalize(name),
		NormalizedKind:     entitySearchNormalize(string(node.Kind)),
		NormalizedProvider: entitySearchNormalize(node.Provider),
		NormalizedAccount:  entitySearchNormalize(node.Account),
		NormalizedRegion:   entitySearchNormalize(node.Region),
		SearchText:         searchText,
		Tokens:             entitySearchTokens(searchText),
		Suggestions:        compactEntitySearchStrings(suggestions),
	}, true
}

func (g *Graph) ensureEntitySearchIndexesLocked(includeSuggestions bool) {
	if !g.indexBuilt {
		g.buildIndexLocked()
	}
	if includeSuggestions {
		g.ensureEntitySuggestIndexBuiltLocked()
	}
}

func (g *Graph) ensureEntitySuggestIndexBuiltLocked() {
	if g.entitySuggestBuilt {
		return
	}
	if g.entitySuggestIndex == nil {
		g.entitySuggestIndex = make(map[string][]EntitySuggestion)
	}
	entitySuggestSets := make(map[string]map[string]EntitySuggestion)
	for _, doc := range g.entitySearchDocs {
		for _, suggestion := range doc.Suggestions {
			normalized := entitySearchNormalize(suggestion)
			if normalized == "" {
				continue
			}
			runes := []rune(normalized)
			for length := 1; length <= len(runes) && length <= 24; length++ {
				prefix := string(runes[:length])
				if entitySuggestSets[prefix] == nil {
					entitySuggestSets[prefix] = make(map[string]EntitySuggestion)
				}
				key := doc.ID + "\x00" + normalized
				entitySuggestSets[prefix][key] = EntitySuggestion{
					EntityID: doc.ID,
					Kind:     doc.Kind,
					Name:     doc.Name,
					Value:    suggestion,
				}
			}
		}
	}
	for prefix, candidates := range entitySuggestSets {
		g.entitySuggestIndex[prefix] = flattenEntitySuggestionSet(candidates)
	}
	g.entitySuggestBuilt = true
}

func scoreEntitySearchDocument(doc entitySearchDocument, query string, queryTokens []string) (float64, []string) {
	fields := make([]string, 0, 4)
	score := 0.0

	appendField := func(field string) {
		for _, existing := range fields {
			if existing == field {
				return
			}
		}
		fields = append(fields, field)
	}

	if doc.NormalizedName != "" && strings.HasPrefix(doc.NormalizedName, query) {
		score += 8
		appendField("name")
	} else if doc.NormalizedName != "" && strings.Contains(doc.NormalizedName, query) {
		score += 5
		appendField("name")
	}
	if doc.NormalizedID != "" && strings.Contains(doc.NormalizedID, query) {
		score += 4
		appendField("id")
	}
	if doc.NormalizedKind != "" && strings.Contains(doc.NormalizedKind, query) {
		score += 3
		appendField("kind")
	}
	if doc.NormalizedProvider != "" && strings.Contains(doc.NormalizedProvider, query) {
		score += 2
		appendField("provider")
	}
	if doc.NormalizedRegion != "" && strings.Contains(doc.NormalizedRegion, query) {
		score += 1
		appendField("region")
	}

	tokenSet := make(map[string]struct{}, len(doc.Tokens))
	for _, token := range doc.Tokens {
		tokenSet[token] = struct{}{}
	}
	for _, token := range queryTokens {
		if _, ok := tokenSet[token]; ok {
			score += 2
		}
	}
	return score, fields
}

func normalizeEntitySearchOptions(opts EntitySearchOptions) EntitySearchOptions {
	opts.Query = strings.TrimSpace(opts.Query)
	opts.Kinds = uniqueSortedNodeKinds(opts.Kinds)
	if opts.Limit <= 0 {
		opts.Limit = defaultEntitySearchLimit
	}
	if opts.Limit > maxEntitySearchLimit {
		opts.Limit = maxEntitySearchLimit
	}
	return opts
}

func normalizeEntitySuggestOptions(opts EntitySuggestOptions) EntitySuggestOptions {
	opts.Prefix = strings.TrimSpace(opts.Prefix)
	opts.Kinds = uniqueSortedNodeKinds(opts.Kinds)
	if opts.Limit <= 0 {
		opts.Limit = defaultEntitySuggestLimit
	}
	if opts.Limit > maxEntitySuggestLimit {
		opts.Limit = maxEntitySuggestLimit
	}
	return opts
}

func entitySearchNormalize(raw string) string {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" {
		return ""
	}
	var b strings.Builder
	lastSpace := false
	for _, r := range raw {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
			lastSpace = false
			continue
		}
		if !lastSpace {
			b.WriteByte(' ')
			lastSpace = true
		}
	}
	return strings.TrimSpace(b.String())
}

func entitySearchTokens(raw string) []string {
	parts := strings.Fields(entitySearchNormalize(raw))
	seen := make(map[string]struct{}, len(parts))
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if _, ok := seen[part]; ok {
			continue
		}
		seen[part] = struct{}{}
		out = append(out, part)
	}
	return out
}

func entitySearchTrigrams(raw string) []string {
	normalized := strings.ReplaceAll(entitySearchNormalize(raw), " ", "")
	if normalized == "" {
		return nil
	}
	runes := []rune(normalized)
	if len(runes) <= 3 {
		return []string{string(runes)}
	}
	seen := make(map[string]struct{})
	out := make([]string, 0, len(runes)-2)
	for i := 0; i <= len(runes)-3; i++ {
		trigram := string(runes[i : i+3])
		if _, ok := seen[trigram]; ok {
			continue
		}
		seen[trigram] = struct{}{}
		out = append(out, trigram)
	}
	return out
}

func compactEntitySearchStrings(values []string) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		key := entitySearchNormalize(value)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, value)
	}
	return out
}

func appendEntitySearchSet(index map[string]map[string]struct{}, key, id string) {
	if index[key] == nil {
		index[key] = make(map[string]struct{})
	}
	index[key][id] = struct{}{}
}

func flattenEntitySearchSet(ids map[string]struct{}) []string {
	out := make([]string, 0, len(ids))
	for id := range ids {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func flattenEntitySuggestionSet(candidates map[string]EntitySuggestion) []EntitySuggestion {
	out := make([]EntitySuggestion, 0, len(candidates))
	for _, candidate := range candidates {
		out = append(out, candidate)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Value != out[j].Value {
			return out[i].Value < out[j].Value
		}
		return out[i].EntityID < out[j].EntityID
	})
	return out
}

func entitySearchKindAllowed(kind NodeKind, allowed []NodeKind) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, candidate := range allowed {
		if candidate == kind {
			return true
		}
	}
	return false
}
