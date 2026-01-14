// Package findings provides storage and management for security findings.
// Findings are created when policy violations are detected during asset scans.
//
// The package provides:
//   - In-memory finding store with deduplication by finding ID
//   - Finding lifecycle management (open, resolved, suppressed)
//   - Statistics and filtering for dashboards and reporting
//   - Snowflake persistence for durable storage
//
// Findings have a lifecycle:
//  1. Created as "open" when first detected
//  2. LastSeen updated on subsequent detections
//  3. Manually marked as "resolved" when fixed
//  4. Marked as "suppressed" for accepted risks
//  5. Re-opened if violation recurs after resolution
//
// Example usage:
//
//	store := findings.NewStore()
//	finding := store.Upsert(ctx, policyFinding)
//	if finding.FirstSeen.Equal(finding.LastSeen) {
//	    // This is a new finding, send notification
//	}
//	stats := store.Stats()
//	fmt.Printf("Open findings: %d critical, %d high", stats.Critical, stats.High)
package findings

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/writerinternal/cerebro/internal/policy"
)

// FindingStore defines the interface for findings persistence backends.
// Implementations include in-memory Store and SnowflakeStore.
type FindingStore interface {
	Upsert(ctx context.Context, pf policy.Finding) *Finding
	Get(id string) (*Finding, bool)
	List(filter FindingFilter) []*Finding
	Resolve(id string) bool
	Suppress(id string) bool
	Stats() Stats
	Sync(ctx context.Context) error // Sync to persistent storage
}

type Finding struct {
	ID           string                 `json:"id"`
	PolicyID     string                 `json:"policy_id"`
	PolicyName   string                 `json:"policy_name"`
	Severity     string                 `json:"severity"`
	Status       string                 `json:"status"` // open, resolved, suppressed
	ResourceID   string                 `json:"resource_id"`
	ResourceType string                 `json:"resource_type"`
	Resource     map[string]interface{} `json:"resource"`
	Description  string                 `json:"description"`
	FirstSeen    time.Time              `json:"first_seen"`
	LastSeen     time.Time              `json:"last_seen"`
	ResolvedAt   *time.Time             `json:"resolved_at,omitempty"`
}

type Store struct {
	findings map[string]*Finding
	mu       sync.RWMutex
}

func NewStore() *Store {
	return &Store{
		findings: make(map[string]*Finding),
	}
}

func (s *Store) Upsert(ctx context.Context, pf policy.Finding) *Finding {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()

	if existing, ok := s.findings[pf.ID]; ok {
		existing.LastSeen = now
		// Only update fields that might change
		if pf.Description != "" {
			existing.Description = pf.Description
		}
		if pf.Severity != "" {
			existing.Severity = pf.Severity
		}
		if len(pf.Resource) > 0 {
			existing.Resource = pf.Resource
		}
		
		if existing.Status == "resolved" {
			existing.Status = "open"
			existing.ResolvedAt = nil
		}
		return existing
	}

	resourceID := extractResourceID(pf.Resource)
	resourceType := extractResourceType(pf.Resource)

	f := &Finding{
		ID:           pf.ID,
		PolicyID:     pf.PolicyID,
		PolicyName:   pf.PolicyName,
		Severity:     pf.Severity,
		Status:       "open",
		ResourceID:   resourceID,
		ResourceType: resourceType,
		Resource:     pf.Resource,
		Description:  pf.Description,
		FirstSeen:    now,
		LastSeen:     now,
	}
	s.findings[pf.ID] = f
	return f
}

// extractResourceID tries multiple fields to find a suitable resource identifier
func extractResourceID(resource map[string]interface{}) string {
	// Priority order for resource ID extraction
	idFields := []string{
		"_cq_id",      // CloudQuery internal ID
		"arn",         // AWS ARN
		"id",          // Generic ID
		"name",        // Resource name
		"self_link",   // GCP self link
		"resource_id", // Azure resource ID
	}

	for _, field := range idFields {
		if val, ok := resource[field]; ok && val != nil {
			if s, ok := val.(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}

// extractResourceType determines the resource type from the resource data
func extractResourceType(resource map[string]interface{}) string {
	// Try CloudQuery table name first
	if rt, ok := resource["_cq_table"].(string); ok && rt != "" {
		return rt
	}

	// Try to infer from ARN
	if arn, ok := resource["arn"].(string); ok && arn != "" {
		// AWS ARN format: arn:aws:service:region:account:resource-type/resource-id
		parts := strings.Split(arn, ":")
		if len(parts) >= 6 {
			return parts[2] // Service name (e.g., s3, ec2, iam)
		}
	}

	// Try GCP self_link
	if link, ok := resource["self_link"].(string); ok && link != "" {
		// GCP format: https://compute.googleapis.com/compute/v1/projects/.../zones/.../instances/...
		if strings.Contains(link, "compute.googleapis.com") {
			return "gcp_compute"
		}
		if strings.Contains(link, "storage.googleapis.com") {
			return "gcp_storage"
		}
	}

	return ""
}

func (s *Store) Get(id string) (*Finding, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	f, ok := s.findings[id]
	return f, ok
}

func (s *Store) List(filter FindingFilter) []*Finding {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*Finding, 0)
	for _, f := range s.findings {
		if filter.Severity != "" && f.Severity != filter.Severity {
			continue
		}
		if filter.Status != "" && f.Status != filter.Status {
			continue
		}
		if filter.PolicyID != "" && f.PolicyID != filter.PolicyID {
			continue
		}
		result = append(result, f)
	}
	return result
}

func (s *Store) Resolve(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	f, ok := s.findings[id]
	if !ok {
		return false
	}
	now := time.Now()
	f.Status = "resolved"
	f.ResolvedAt = &now
	return true
}

func (s *Store) Suppress(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	f, ok := s.findings[id]
	if !ok {
		return false
	}
	f.Status = "suppressed"
	return true
}

func (s *Store) Stats() Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := Stats{
		BySeverity: make(map[string]int),
		ByStatus:   make(map[string]int),
		ByPolicy:   make(map[string]int),
	}

	for _, f := range s.findings {
		stats.Total++
		stats.BySeverity[f.Severity]++
		stats.ByStatus[f.Status]++
		stats.ByPolicy[f.PolicyID]++
	}

	return stats
}

type FindingFilter struct {
	Severity string
	Status   string
	PolicyID string
}

type Stats struct {
	Total      int            `json:"total"`
	BySeverity map[string]int `json:"by_severity"`
	ByStatus   map[string]int `json:"by_status"`
	ByPolicy   map[string]int `json:"by_policy"`
}

// Sync is a no-op for in-memory store
func (s *Store) Sync(ctx context.Context) error {
	return nil
}

// Ensure Store implements FindingStore
var _ FindingStore = (*Store)(nil)
