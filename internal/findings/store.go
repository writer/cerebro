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
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/writer/cerebro/internal/policy"
)

// FindingStore defines the interface for findings persistence backends.
// Implementations include in-memory Store and SnowflakeStore.
type FindingStore interface {
	Upsert(ctx context.Context, pf policy.Finding) *Finding
	Get(id string) (*Finding, bool)
	List(filter FindingFilter) []*Finding
	Count(filter FindingFilter) int
	Resolve(id string) bool
	Suppress(id string) bool
	Stats() Stats
	Sync(ctx context.Context) error // Sync to persistent storage
}

type Finding struct {
	// Core identification
	ID        string `json:"id"`
	IssueID   string `json:"issue_id,omitempty"`
	ControlID string `json:"control_id,omitempty"` // Policy control ID

	// Policy info
	PolicyID    string `json:"policy_id"`
	PolicyName  string `json:"policy_name"`
	Title       string `json:"title,omitempty"` // Human-readable issue title
	Description string `json:"description"`
	Severity    string `json:"severity"`

	// Status & lifecycle
	Status          string     `json:"status"`                      // OPEN, RESOLVED, SUPPRESSED, IN_PROGRESS
	Resolution      string     `json:"resolution,omitempty"`        // How it was resolved
	ResolvedAt      *time.Time `json:"resolved_at,omitempty"`       // When resolved
	DueAt           *time.Time `json:"due_at,omitempty"`            // Due date for remediation
	StatusChangedAt *time.Time `json:"status_changed_at,omitempty"` // When status last changed

	// Timestamps
	CreatedAt time.Time `json:"created_at,omitempty"` // When first created (alias for FirstSeen)
	UpdatedAt time.Time `json:"updated_at,omitempty"` // Last update time
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`

	// Resource details
	ResourceID         string                 `json:"resource_id"`
	ResourceName       string                 `json:"resource_name,omitempty"`
	ResourceType       string                 `json:"resource_type"`
	ResourceExternalID string                 `json:"resource_external_id,omitempty"` // ARN, GCP resource path, etc.
	ResourceRegion     string                 `json:"resource_region,omitempty"`
	ResourceStatus     string                 `json:"resource_status,omitempty"` // Active, Deleted, etc.
	ResourcePlatform   string                 `json:"resource_platform,omitempty"`
	ResourceTags       map[string]string      `json:"resource_tags,omitempty"`
	Resource           map[string]interface{} `json:"resource"`
	ResourceJSON       map[string]interface{} `json:"resource_original_json,omitempty"` // Full resource JSON

	// Cloud context
	SubscriptionID   string   `json:"subscription_id,omitempty"`   // AWS Account ID, GCP Project, etc.
	SubscriptionName string   `json:"subscription_name,omitempty"` // Account/Project name
	ProjectIDs       []string `json:"project_ids,omitempty"`
	ProjectNames     []string `json:"project_names,omitempty"`

	// Kubernetes context (if applicable)
	KubernetesCluster   string `json:"kubernetes_cluster,omitempty"`
	KubernetesNamespace string `json:"kubernetes_namespace,omitempty"`
	ContainerService    string `json:"container_service,omitempty"`

	// Risk & threat analysis
	RiskCategories []string `json:"risks,omitempty"`   // EXTERNAL_EXPOSURE, UNPROTECTED_DATA, etc.
	Threats        []string `json:"threats,omitempty"` // Threat indicators

	// Remediation
	Remediation string `json:"remediation_recommendation,omitempty"`

	// Compliance mapping
	SecurityFrameworks []string                  `json:"security_frameworks,omitempty"`
	SecurityCategories []string                  `json:"security_categories,omitempty"`
	ComplianceMappings []policy.FrameworkMapping `json:"compliance_mappings,omitempty"`
	MitreAttack        []policy.MitreMapping     `json:"mitre_attack,omitempty"`

	// Evidence
	Evidence []Evidence `json:"evidence,omitempty"`

	// Links
	CloudProviderURL string `json:"cloud_provider_url,omitempty"`

	// Assignment & ticketing
	AssigneeName      string   `json:"assignee_name,omitempty"`
	TicketURLs        []string `json:"ticket_urls,omitempty"`
	TicketNames       []string `json:"ticket_names,omitempty"`
	TicketExternalIDs []string `json:"ticket_external_ids,omitempty"`
	Notes             string   `json:"note,omitempty"`
}

// Evidence stores proof data for a finding
type Evidence struct {
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	Data        map[string]interface{} `json:"data,omitempty"`
}

// StoreConfig configures capacity limits for the in-memory Store.
type StoreConfig struct {
	MaxFindings       int           // 0 means unlimited (default for backward compat)
	ResolvedRetention time.Duration // How long to keep resolved findings; 0 means forever
}

type Store struct {
	findings          map[string]*Finding
	attestor          FindingAttestor
	attestReobserved  bool
	maxFindings       int
	resolvedRetention time.Duration
	mu                sync.RWMutex
}

// NewStore creates an unlimited in-memory store (backward compatible).
func NewStore() *Store {
	return &Store{
		findings: make(map[string]*Finding),
	}
}

// NewStoreWithConfig creates an in-memory store with capacity limits.
func NewStoreWithConfig(cfg StoreConfig) *Store {
	return &Store{
		findings:          make(map[string]*Finding),
		maxFindings:       cfg.MaxFindings,
		resolvedRetention: cfg.ResolvedRetention,
	}
}

func (s *Store) SetAttestor(attestor FindingAttestor, attestReobserved bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attestor = attestor
	s.attestReobserved = attestReobserved
}

func (s *Store) Upsert(ctx context.Context, pf policy.Finding) *Finding {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	if s.resolvedRetention > 0 {
		_ = s.cleanupResolvedBeforeLocked(now.Add(-s.resolvedRetention))
	}

	if existing, ok := s.findings[pf.ID]; ok {
		previousStatus := normalizeStatus(existing.Status)
		existing.Status = normalizeStatus(existing.Status)
		existing.LastSeen = now
		existing.UpdatedAt = now
		// Only update fields that might change
		if pf.Description != "" {
			existing.Description = pf.Description
		}
		if pf.Severity != "" {
			existing.Severity = pf.Severity
		}
		if pf.ControlID != "" {
			existing.ControlID = pf.ControlID
		}
		if pf.Title != "" {
			existing.Title = pf.Title
		}
		if pf.Remediation != "" {
			existing.Remediation = pf.Remediation
		}
		if len(pf.Resource) > 0 {
			existing.Resource = pf.Resource
		}
		if pf.ResourceID != "" {
			existing.ResourceID = pf.ResourceID
		}
		if pf.ResourceType != "" {
			existing.ResourceType = pf.ResourceType
		}
		if pf.ResourceName != "" {
			existing.ResourceName = pf.ResourceName
		}
		if len(pf.RiskCategories) > 0 {
			existing.RiskCategories = pf.RiskCategories
		}
		if len(pf.Frameworks) > 0 {
			totalControls := 0
			for _, fm := range pf.Frameworks {
				totalControls += len(fm.Controls)
			}
			frameworks := make([]string, 0, len(pf.Frameworks))
			securityCategories := make([]string, 0, totalControls)
			for _, fm := range pf.Frameworks {
				frameworks = append(frameworks, fm.Name)
				for _, control := range fm.Controls {
					securityCategories = append(securityCategories, fm.Name+":"+control)
				}
			}
			existing.SecurityFrameworks = frameworks
			existing.SecurityCategories = securityCategories
			existing.ComplianceMappings = pf.Frameworks
		}
		if len(pf.MitreAttack) > 0 {
			existing.MitreAttack = pf.MitreAttack
		}

		// Reopen resolved findings if they recur
		if previousStatus == "RESOLVED" {
			existing.Status = "OPEN"
			existing.ResolvedAt = nil
			existing.StatusChangedAt = &now
		}
		EnrichFinding(existing)
		eventType := upsertAttestationEvent(true, previousStatus, s.attestReobserved)
		if eventType != "" {
			_ = attestFindingEvent(ctx, s.attestor, existing, eventType, now)
		}
		return existing
	}

	// Use enhanced fields from policy finding if available, fall back to extraction
	resourceID := pf.ResourceID
	if resourceID == "" {
		resourceID = extractResourceID(pf.Resource)
	}
	resourceType := pf.ResourceType
	if resourceType == "" {
		resourceType = extractResourceType(pf.Resource)
	}
	resourceName := pf.ResourceName
	if resourceName == "" {
		resourceName = extractResourceName(pf.Resource)
	}

	// Extract frameworks and controls for the finding
	frameworks := make([]string, 0, len(pf.Frameworks))
	securityCategories := make([]string, 0)
	for _, fm := range pf.Frameworks {
		frameworks = append(frameworks, fm.Name)
		for _, control := range fm.Controls {
			securityCategories = append(securityCategories, fm.Name+":"+control)
		}
	}

	f := &Finding{
		ID:                 pf.ID,
		IssueID:            pf.ID, // Use same ID as issue ID for now
		ControlID:          pf.ControlID,
		PolicyID:           pf.PolicyID,
		PolicyName:         pf.PolicyName,
		Title:              pf.Title,
		Severity:           pf.Severity,
		Status:             "OPEN",
		ResourceID:         resourceID,
		ResourceName:       resourceName,
		ResourceType:       resourceType,
		Resource:           pf.Resource,
		Description:        pf.Description,
		Remediation:        pf.Remediation,
		RiskCategories:     pf.RiskCategories,
		SecurityFrameworks: frameworks,
		SecurityCategories: securityCategories,
		ComplianceMappings: pf.Frameworks,
		MitreAttack:        pf.MitreAttack,
		CreatedAt:          now,
		UpdatedAt:          now,
		FirstSeen:          now,
		LastSeen:           now,
	}
	f.StatusChangedAt = &now

	EnrichFinding(f)
	_ = attestFindingEvent(ctx, s.attestor, f, upsertAttestationEvent(false, "", s.attestReobserved), now)
	s.findings[pf.ID] = f

	if s.maxFindings > 0 && len(s.findings) > s.maxFindings {
		s.evictToCapacity()
	}

	return f
}

func normalizeStatus(status string) string {
	if status == "" {
		return ""
	}
	return strings.ToUpper(strings.TrimSpace(status))
}

// extractResourceID tries multiple fields to find a suitable resource identifier
func extractResourceID(resource map[string]interface{}) string {
	// Priority order for resource ID extraction
	idFields := []string{
		"_cq_id",      // Sync internal ID
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

// extractResourceName extracts a human-readable name from the resource
func extractResourceName(resource map[string]interface{}) string {
	nameFields := []string{
		"name",
		"role_name",
		"user_name",
		"bucket_name",
		"function_name",
		"instance_id",
		"display_name",
		"title",
	}

	for _, field := range nameFields {
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
	// Try table name first
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

	statusFilter := normalizeStatus(filter.Status)

	result := make([]*Finding, 0)
	for _, f := range s.findings {
		if filter.Severity != "" && f.Severity != filter.Severity {
			continue
		}
		if statusFilter != "" && normalizeStatus(f.Status) != statusFilter {
			continue
		}
		if filter.PolicyID != "" && f.PolicyID != filter.PolicyID {
			continue
		}
		result = append(result, f)
	}

	// Apply pagination if specified
	if filter.Offset > 0 || filter.Limit > 0 {
		if filter.Offset >= len(result) {
			return []*Finding{}
		}
		end := len(result)
		if filter.Limit > 0 && filter.Offset+filter.Limit < end {
			end = filter.Offset + filter.Limit
		}
		result = result[filter.Offset:end]
	}

	return result
}

func (s *Store) Count(filter FindingFilter) int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	statusFilter := normalizeStatus(filter.Status)

	count := 0
	for _, f := range s.findings {
		if filter.Severity != "" && f.Severity != filter.Severity {
			continue
		}
		if statusFilter != "" && normalizeStatus(f.Status) != statusFilter {
			continue
		}
		if filter.PolicyID != "" && f.PolicyID != filter.PolicyID {
			continue
		}
		count++
	}
	return count
}

func (s *Store) Resolve(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	f, ok := s.findings[id]
	if !ok {
		return false
	}
	now := time.Now()
	f.Status = "RESOLVED"
	f.ResolvedAt = &now
	f.StatusChangedAt = &now
	f.UpdatedAt = now
	return true
}

func (s *Store) Suppress(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	f, ok := s.findings[id]
	if !ok {
		return false
	}
	now := time.Now()
	f.Status = "SUPPRESSED"
	f.StatusChangedAt = &now
	f.UpdatedAt = now
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
		stats.ByStatus[normalizeStatus(f.Status)]++
		stats.ByPolicy[f.PolicyID]++
	}

	return stats
}

type FindingFilter struct {
	Severity string
	Status   string
	PolicyID string
	Limit    int
	Offset   int
}

type Stats struct {
	Total      int            `json:"total"`
	BySeverity map[string]int `json:"by_severity"`
	ByStatus   map[string]int `json:"by_status"`
	ByPolicy   map[string]int `json:"by_policy"`
}

// evictToCapacity removes findings until the store is within its configured
// capacity. Eviction prefers RESOLVED, then SUPPRESSED, then all other
// statuses, oldest LastSeen first. Must be called with s.mu held.
func (s *Store) evictToCapacity() {
	excess := len(s.findings) - s.maxFindings
	if excess <= 0 {
		return
	}

	// Collect candidates sorted by status priority and LastSeen (oldest first)
	type entry struct {
		id             string
		lastSeen       time.Time
		statusPriority int
	}
	candidates := make([]entry, 0, len(s.findings))
	for id, f := range s.findings {
		priority := 2
		switch normalizeStatus(f.Status) {
		case "RESOLVED":
			priority = 0
		case "SUPPRESSED":
			priority = 1
		}
		candidates = append(candidates, entry{id: id, lastSeen: f.LastSeen, statusPriority: priority})
	}

	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].statusPriority != candidates[j].statusPriority {
			return candidates[i].statusPriority < candidates[j].statusPriority
		}
		if candidates[i].lastSeen.Equal(candidates[j].lastSeen) {
			return candidates[i].id < candidates[j].id
		}
		return candidates[i].lastSeen.Before(candidates[j].lastSeen)
	})

	for i := 0; i < len(candidates) && excess > 0; i++ {
		delete(s.findings, candidates[i].id)
		excess--
	}
}

// cleanupResolvedBeforeLocked removes resolved findings older than cutoff.
// Must be called with s.mu held.
func (s *Store) cleanupResolvedBeforeLocked(cutoff time.Time) int {
	removed := 0
	for id, f := range s.findings {
		if normalizeStatus(f.Status) == "RESOLVED" && f.LastSeen.Before(cutoff) {
			delete(s.findings, id)
			removed++
		}
	}
	return removed
}

// Cleanup removes resolved findings older than maxAge. Returns the number of
// findings removed. This mirrors the FileStore.Cleanup pattern.
func (s *Store) Cleanup(maxAge time.Duration) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.cleanupResolvedBeforeLocked(time.Now().Add(-maxAge))
}

// Len returns the number of findings in the store.
func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.findings)
}

// Sync is a no-op for in-memory store
func (s *Store) Sync(ctx context.Context) error {
	return nil
}

// Ensure Store implements FindingStore
var _ FindingStore = (*Store)(nil)
