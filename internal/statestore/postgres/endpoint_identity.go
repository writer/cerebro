package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

var ensureEndpointIdentityStatements = []string{
	`CREATE TABLE IF NOT EXISTS endpoint_identity_aliases (
  tenant_id TEXT NOT NULL,
  alias_type TEXT NOT NULL,
  alias_value TEXT NOT NULL,
  alias_value_normalized TEXT NOT NULL,
  canonical_device_id TEXT NOT NULL,
  source_id TEXT NOT NULL,
  confidence DOUBLE PRECISION NOT NULL DEFAULT 0,
  attributes_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  first_seen_at TIMESTAMPTZ NOT NULL,
  last_seen_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (tenant_id, alias_type, alias_value_normalized, canonical_device_id)
)`,
	`CREATE INDEX IF NOT EXISTS endpoint_identity_alias_lookup_idx
        ON endpoint_identity_aliases (tenant_id, alias_type, alias_value_normalized)`,
	`CREATE INDEX IF NOT EXISTS endpoint_identity_alias_device_idx
        ON endpoint_identity_aliases (tenant_id, canonical_device_id)`,
	`CREATE INDEX IF NOT EXISTS endpoint_identity_alias_last_seen_idx
        ON endpoint_identity_aliases (tenant_id, last_seen_at DESC)`,
}

func (s *Store) UpsertEndpointIdentityAliases(ctx context.Context, aliases []ports.EndpointIdentityAlias) error {
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	if err := s.ensureEndpointIdentityTables(ctx); err != nil {
		return err
	}
	for _, alias := range aliases {
		alias = normalizeEndpointAlias(alias)
		if alias.TenantID == "" || alias.CanonicalDeviceID == "" || alias.AliasType == "" || alias.AliasValue == "" {
			continue
		}
		attrs, err := json.Marshal(alias.Attributes)
		if err != nil {
			return fmt.Errorf("marshal endpoint identity attributes: %w", err)
		}
		observedAt := alias.ObservedAt.UTC()
		if observedAt.IsZero() {
			observedAt = time.Now().UTC()
		}
		if _, err := s.db.ExecContext(ctx, `
INSERT INTO endpoint_identity_aliases (
  tenant_id, alias_type, alias_value, alias_value_normalized, canonical_device_id,
  source_id, confidence, attributes_json, first_seen_at, last_seen_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$9)
ON CONFLICT (tenant_id, alias_type, alias_value_normalized, canonical_device_id)
DO UPDATE SET
  alias_value = EXCLUDED.alias_value,
  source_id = EXCLUDED.source_id,
  confidence = GREATEST(endpoint_identity_aliases.confidence, EXCLUDED.confidence),
  attributes_json = endpoint_identity_aliases.attributes_json || EXCLUDED.attributes_json,
  first_seen_at = LEAST(endpoint_identity_aliases.first_seen_at, EXCLUDED.first_seen_at),
  last_seen_at = GREATEST(endpoint_identity_aliases.last_seen_at, EXCLUDED.last_seen_at),
  updated_at = NOW()`,
			alias.TenantID,
			alias.AliasType,
			alias.AliasValue,
			normalizeEndpointAliasValue(alias.AliasValue),
			alias.CanonicalDeviceID,
			alias.SourceID,
			alias.Confidence,
			string(attrs),
			observedAt,
		); err != nil {
			return fmt.Errorf("upsert endpoint identity alias %s/%s: %w", alias.AliasType, alias.AliasValue, err)
		}
	}
	return nil
}

func (s *Store) ResolveEndpointIdentity(ctx context.Context, request ports.EndpointIdentityResolveRequest) (ports.EndpointIdentityResolution, error) {
	if s == nil || s.db == nil {
		return ports.EndpointIdentityResolution{}, errors.New("postgres is not configured")
	}
	if err := s.ensureEndpointIdentityTables(ctx); err != nil {
		return ports.EndpointIdentityResolution{}, err
	}
	tenantID := strings.TrimSpace(request.TenantID)
	if tenantID == "" {
		return ports.EndpointIdentityResolution{}, errors.New("endpoint identity tenant id is required")
	}
	aliases := normalizeEndpointAliases(request.Aliases)
	if len(aliases) == 0 {
		return ports.EndpointIdentityResolution{TenantID: tenantID}, nil
	}
	clauses := make([]string, 0, len(aliases))
	args := []any{tenantID}
	for _, alias := range aliases {
		args = append(args, alias.AliasType, normalizeEndpointAliasValue(alias.AliasValue))
		clauses = append(clauses, fmt.Sprintf("(alias_type = $%d AND alias_value_normalized = $%d)", len(args)-1, len(args)))
	}
	limit := request.Limit
	if limit == 0 {
		limit = 50
	}
	args = append(args, limit)
	query := `
SELECT tenant_id, alias_type, alias_value, canonical_device_id, source_id, confidence,
       attributes_json::text, first_seen_at, last_seen_at
  FROM endpoint_identity_aliases
 WHERE tenant_id = $1 AND (` + strings.Join(clauses, " OR ") + `)
 ORDER BY confidence DESC, last_seen_at DESC
 LIMIT $` + fmt.Sprint(len(args))
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return ports.EndpointIdentityResolution{}, fmt.Errorf("resolve endpoint identity: %w", err)
	}
	defer func() { _ = rows.Close() }()
	matches := []ports.EndpointIdentityAlias{}
	for rows.Next() {
		alias, err := scanEndpointAlias(rows)
		if err != nil {
			return ports.EndpointIdentityResolution{}, err
		}
		matches = append(matches, alias)
	}
	if err := rows.Err(); err != nil {
		return ports.EndpointIdentityResolution{}, err
	}
	candidates := endpointIdentityCandidateIDs(matches)
	resolution := ports.EndpointIdentityResolution{
		TenantID:           tenantID,
		MatchedAliases:     matches,
		CandidateDeviceIDs: candidates,
		Ambiguous:          len(candidates) > 1,
	}
	if len(candidates) > 0 {
		resolution.CanonicalDeviceID = candidates[0]
	}
	return resolution, nil
}

func scanEndpointAlias(scanner interface {
	Scan(dest ...any) error
}) (ports.EndpointIdentityAlias, error) {
	var alias ports.EndpointIdentityAlias
	var attrsJSON string
	var firstSeen time.Time
	if err := scanner.Scan(
		&alias.TenantID,
		&alias.AliasType,
		&alias.AliasValue,
		&alias.CanonicalDeviceID,
		&alias.SourceID,
		&alias.Confidence,
		&attrsJSON,
		&firstSeen,
		&alias.ObservedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ports.EndpointIdentityAlias{}, err
		}
		return ports.EndpointIdentityAlias{}, fmt.Errorf("scan endpoint identity alias: %w", err)
	}
	alias.Attributes = map[string]string{}
	if strings.TrimSpace(attrsJSON) != "" {
		if err := json.Unmarshal([]byte(attrsJSON), &alias.Attributes); err != nil {
			return ports.EndpointIdentityAlias{}, fmt.Errorf("decode endpoint identity attributes: %w", err)
		}
	}
	return alias, nil
}

func normalizeEndpointAliases(aliases []ports.EndpointIdentityAlias) []ports.EndpointIdentityAlias {
	out := make([]ports.EndpointIdentityAlias, 0, len(aliases))
	for _, alias := range aliases {
		alias = normalizeEndpointAlias(alias)
		if alias.AliasType != "" && alias.AliasValue != "" {
			out = append(out, alias)
		}
	}
	return out
}

func normalizeEndpointAlias(alias ports.EndpointIdentityAlias) ports.EndpointIdentityAlias {
	alias.TenantID = strings.TrimSpace(alias.TenantID)
	alias.CanonicalDeviceID = strings.TrimSpace(alias.CanonicalDeviceID)
	alias.AliasType = strings.TrimSpace(alias.AliasType)
	alias.AliasValue = strings.TrimSpace(alias.AliasValue)
	alias.SourceID = strings.TrimSpace(alias.SourceID)
	if alias.Attributes == nil {
		alias.Attributes = map[string]string{}
	}
	if alias.Confidence < 0 {
		alias.Confidence = 0
	}
	if alias.Confidence > 1 {
		alias.Confidence = 1
	}
	return alias
}

func normalizeEndpointAliasValue(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func endpointIdentityCandidateIDs(matches []ports.EndpointIdentityAlias) []string {
	type score struct {
		deviceID   string
		confidence float64
		observedAt time.Time
	}
	byDevice := map[string]score{}
	for _, match := range matches {
		deviceID := strings.TrimSpace(match.CanonicalDeviceID)
		if deviceID == "" {
			continue
		}
		current := byDevice[deviceID]
		if current.deviceID == "" || match.Confidence > current.confidence || (match.Confidence == current.confidence && match.ObservedAt.After(current.observedAt)) {
			byDevice[deviceID] = score{deviceID: deviceID, confidence: match.Confidence, observedAt: match.ObservedAt}
		}
	}
	scores := make([]score, 0, len(byDevice))
	for _, score := range byDevice {
		scores = append(scores, score)
	}
	sort.Slice(scores, func(i, j int) bool {
		if scores[i].confidence != scores[j].confidence {
			return scores[i].confidence > scores[j].confidence
		}
		return scores[i].observedAt.After(scores[j].observedAt)
	})
	out := make([]string, 0, len(scores))
	for _, score := range scores {
		out = append(out, score.deviceID)
	}
	return out
}

func (s *Store) ensureEndpointIdentityTables(ctx context.Context) error {
	return s.ensureStatements(ctx, &s.endpointIdentityReady, "endpoint identity", ensureEndpointIdentityStatements)
}

var _ ports.EndpointIdentityStore = (*Store)(nil)
