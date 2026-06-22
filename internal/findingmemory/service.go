package findingmemory

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/writer/cerebro/internal/agentplatform"
	"github.com/writer/cerebro/internal/ports"
)

const (
	TypeAcceptedRisk       = "accepted_risk"
	TypeFalsePositive      = "false_positive"
	TypePriorInvestigation = "prior_investigation"
	TypeRemediationOutcome = "remediation_outcome"
	TypeDetectorLearning   = "detector_learning"

	defaultEmbeddingDimensions = 32
)

var ErrInvalidRequest = errors.New("invalid finding memory request")

type Embedder interface {
	EmbedText(context.Context, string) ([]float64, error)
}

type HashEmbedder struct {
	Dimensions int
}

func (e HashEmbedder) EmbedText(_ context.Context, text string) ([]float64, error) {
	dimensions := e.Dimensions
	if dimensions <= 0 {
		dimensions = defaultEmbeddingDimensions
	}
	values := make([]float64, dimensions)
	normalized := strings.ToLower(strings.TrimSpace(text))
	if normalized == "" {
		return values, nil
	}
	parts := strings.FieldsFunc(normalized, func(r rune) bool {
		word := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '-'
		return !word
	})
	for _, part := range parts {
		if part == "" {
			continue
		}
		sum := sha256.Sum256([]byte(part))
		idx := int(sum[0]) % dimensions
		sign := 1.0
		if sum[1]&1 == 1 {
			sign = -1
		}
		values[idx] += sign
	}
	NormalizeVector(values)
	return values, nil
}

func MemoryFromFinding(ctx context.Context, embedder Embedder, finding *ports.FindingRecord, memoryType string, summary string, observedAt time.Time) (*ports.FindingMemoryRecord, error) {
	if finding == nil {
		return nil, fmt.Errorf("%w: finding is required", ErrInvalidRequest)
	}
	tenantID := strings.TrimSpace(finding.TenantID)
	if tenantID == "" {
		return nil, fmt.Errorf("%w: tenant_id is required", ErrInvalidRequest)
	}
	memoryType = strings.TrimSpace(memoryType)
	if memoryType == "" {
		return nil, fmt.Errorf("%w: memory type is required", ErrInvalidRequest)
	}
	if strings.TrimSpace(summary) == "" {
		summary = FindingEmbeddingText(finding)
	}
	var embedding []float64
	if embedder != nil {
		vec, err := embedder.EmbedText(ctx, summary)
		if err != nil {
			return nil, err
		}
		embedding = vec
	}
	observedAt = observedAt.UTC()
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	id := CanonicalMemoryID(tenantID, memoryType, finding.ID, finding.Fingerprint)
	return &ports.FindingMemoryRecord{
		ID:           id,
		TenantID:     tenantID,
		Type:         memoryType,
		SourceURN:    firstNonEmpty(primaryResourceURN(finding), finding.ID),
		FindingID:    strings.TrimSpace(finding.ID),
		RuleID:       strings.TrimSpace(finding.RuleID),
		Fingerprint:  strings.TrimSpace(finding.Fingerprint),
		Summary:      strings.TrimSpace(summary),
		EvidenceRefs: append([]string(nil), finding.EventIDs...),
		SubjectURNs:  append([]string(nil), finding.ResourceURNs...),
		Embedding:    embedding,
		Confidence:   confidenceFromFinding(finding),
		ObservedAt:   observedAt,
		Metadata: map[string]string{
			"severity": strings.TrimSpace(finding.Severity),
			"status":   strings.TrimSpace(finding.Status),
		},
	}, nil
}

func SimilarHints(ctx context.Context, store ports.FindingMemoryStore, embedder Embedder, finding *ports.FindingRecord, memoryType string, limit uint32) ([]agentplatform.SecurityMemoryHint, error) {
	if store == nil || embedder == nil || finding == nil {
		return nil, nil
	}
	embedding, err := embedder.EmbedText(ctx, FindingEmbeddingText(finding))
	if err != nil {
		return nil, err
	}
	matches, err := store.SimilarFindingMemory(ctx, ports.SimilarFindingMemoryRequest{
		TenantID:  finding.TenantID,
		Type:      memoryType,
		Embedding: embedding,
		Limit:     limit,
	})
	if err != nil {
		return nil, err
	}
	hints := make([]agentplatform.SecurityMemoryHint, 0, len(matches))
	for _, match := range matches {
		if match.Record == nil || strings.TrimSpace(match.Record.ID) == "" {
			continue
		}
		hints = append(hints, agentplatform.SecurityMemoryHint{
			Type: firstNonEmpty(match.Record.Type, memoryType),
			URN:  "urn:cerebro:" + safeURNPart(match.Record.TenantID) + ":security-memory:" + safeURNPart(match.Record.ID),
			Note: fmt.Sprintf("%.2f %s", match.Score, truncate(match.Record.Summary, 180)),
		})
	}
	return hints, nil
}

func FindingEmbeddingText(finding *ports.FindingRecord) string {
	if finding == nil {
		return ""
	}
	resourceURNs := append([]string(nil), finding.ResourceURNs...)
	sort.Strings(resourceURNs)
	parts := []string{
		finding.Title,
		finding.Summary,
		finding.RuleID,
		finding.Severity,
		finding.Status,
		strings.Join(finding.RiskReasons, " "),
		strings.Join(resourceURNs, " "),
	}
	return strings.Join(nonEmpty(parts), "\n")
}

func CanonicalMemoryID(values ...string) string {
	joined := strings.Join(nonEmpty(values), "\x00")
	sum := sha256.Sum256([]byte(joined))
	return fmt.Sprintf("fm_%x", sum[:12])
}

func CosineSimilarity(a []float64, b []float64) float64 {
	if len(a) == 0 || len(b) == 0 || len(a) != len(b) {
		return 0
	}
	var dot, aa, bb float64
	for i := range a {
		dot += a[i] * b[i]
		aa += a[i] * a[i]
		bb += b[i] * b[i]
	}
	if aa == 0 || bb == 0 {
		return 0
	}
	return dot / (math.Sqrt(aa) * math.Sqrt(bb))
}

func NormalizeVector(values []float64) {
	var norm float64
	for _, value := range values {
		norm += value * value
	}
	if norm == 0 {
		return
	}
	norm = math.Sqrt(norm)
	for i := range values {
		values[i] /= norm
	}
}

func primaryResourceURN(finding *ports.FindingRecord) string {
	if finding == nil {
		return ""
	}
	if value := strings.TrimSpace(finding.Attributes["primary_resource_urn"]); value != "" {
		return value
	}
	if len(finding.ResourceURNs) != 0 {
		return strings.TrimSpace(finding.ResourceURNs[0])
	}
	return ""
}

func confidenceFromFinding(finding *ports.FindingRecord) float64 {
	if finding == nil || finding.ConfidenceScore <= 0 {
		return 0
	}
	if finding.ConfidenceScore > 100 {
		return 1
	}
	return float64(finding.ConfidenceScore) / 100
}

func nonEmpty(values []string) []string {
	out := []string{}
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func safeURNPart(value string) string {
	value = strings.TrimSpace(value)
	var b strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '_' || r == '-' || r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "unknown"
	}
	return b.String()
}

func truncate(value string, max int) string {
	value = strings.TrimSpace(value)
	if max <= 0 || len(value) <= max {
		return value
	}
	for max > 0 && !utf8.ValidString(value[:max]) {
		max--
	}
	return value[:max]
}
