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

	"github.com/writer/cerebro/internal/metrics"
	"github.com/writer/cerebro/internal/policy"
)

// FindingStore defines the interface for findings persistence backends.
// Implementations include in-memory Store and SnowflakeStore.
type FindingStore interface {
	Upsert(ctx context.Context, pf policy.Finding) *Finding
	Get(id string) (*Finding, bool)
	Update(id string, mutate func(*Finding) error) error
	List(filter FindingFilter) []*Finding
	Count(filter FindingFilter) int
	Resolve(id string) bool
	Suppress(id string) bool
	Stats() Stats
	Sync(ctx context.Context) error // Sync to persistent storage
}

const (
	SignalTypeSecurity    = "security"
	SignalTypeBusiness    = "business"
	SignalTypeOperational = "operational"
	SignalTypeCompliance  = "compliance"

	DomainInfra          = "infra"
	DomainRevenue        = "revenue"
	DomainCustomerHealth = "customer_health"
	DomainPipeline       = "pipeline"
	DomainSLA            = "sla"
	DomainFinancial      = "financial"
)

type Finding struct {
	// Core identification
	ID                 string   `json:"id"`
	IssueID            string   `json:"issue_id,omitempty"`
	ControlID          string   `json:"control_id,omitempty"` // Policy control ID
	TenantID           string   `json:"tenant_id,omitempty"`
	SemanticKey        string   `json:"semantic_key,omitempty"`
	ObservedFindingIDs []string `json:"observed_finding_ids,omitempty"`
	ObservedPolicyIDs  []string `json:"observed_policy_ids,omitempty"`

	// Policy info
	PolicyID    string `json:"policy_id"`
	PolicyName  string `json:"policy_name"`
	Title       string `json:"title,omitempty"` // Human-readable issue title
	Description string `json:"description"`
	Severity    string `json:"severity"`
	SignalType  string `json:"signal_type,omitempty"`
	Domain      string `json:"domain,omitempty"`

	// Status & lifecycle
	Status          string     `json:"status"`                      // OPEN, RESOLVED, SUPPRESSED, IN_PROGRESS
	Resolution      string     `json:"resolution,omitempty"`        // How it was resolved
	ResolvedAt      *time.Time `json:"resolved_at,omitempty"`       // When resolved
	DueAt           *time.Time `json:"due_at,omitempty"`            // Due date for remediation
	StatusChangedAt *time.Time `json:"status_changed_at,omitempty"` // When status last changed
	SnoozedUntil    *time.Time `json:"snoozed_until,omitempty"`
	EscalationCount int        `json:"escalation_count,omitempty"`

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
	EntityIDs         []string `json:"entity_ids,omitempty"`

	// Cached raw resource JSON used by SnowflakeStore to avoid repeated marshalling.
	resourceJSONRaw []byte `json:"-"`
}

// Signal is a backward-compatible alias for generalized findings.
type Signal = Finding

// Evidence stores proof data for a finding
type Evidence struct {
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	Data        map[string]interface{} `json:"data,omitempty"`
}

// StoreConfig configures capacity limits for the in-memory Store.
type StoreConfig struct {
	MaxFindings       int           // 0 means unlimited when explicitly configured.
	ResolvedRetention time.Duration // How long to keep resolved findings; 0 means forever
	SemanticDedup     bool
}

const (
	DefaultMaxFindings             = 50000
	DefaultResolvedRetention       = 30 * 24 * time.Hour
	defaultResolvedCleanupInterval = 5 * time.Minute
)

func DefaultStoreConfig() StoreConfig {
	return StoreConfig{
		MaxFindings:       DefaultMaxFindings,
		ResolvedRetention: DefaultResolvedRetention,
		SemanticDedup:     DefaultSemanticDedupEnabled,
	}
}

type Store struct {
	findings          map[string]*Finding
	semanticIndex     map[string]string
	attestor          FindingAttestor
	attestReobserved  bool
	maxFindings       int
	resolvedRetention time.Duration
	semanticDedup     bool
	resolvedCount     int
	lastResolvedSweep time.Time
	mu                sync.RWMutex
}

// NewStore creates a bounded in-memory store with sane defaults.
func NewStore() *Store {
	return NewStoreWithConfig(DefaultStoreConfig())
}

// NewStoreWithConfig creates an in-memory store with capacity limits.
func NewStoreWithConfig(cfg StoreConfig) *Store {
	store := &Store{
		findings:          make(map[string]*Finding),
		semanticIndex:     make(map[string]string),
		maxFindings:       cfg.MaxFindings,
		resolvedRetention: cfg.ResolvedRetention,
		semanticDedup:     cfg.SemanticDedup,
	}
	store.updateMetricsLocked()
	return store
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
	s.maybeCleanupResolvedLocked(now)
	semanticKey := semanticKeyForPolicyFinding(pf)

	if existing, ok := s.findings[pf.ID]; ok {
		previousStatus := s.refreshFindingFromPolicyLocked(existing, pf, now, semanticKey)
		s.adjustResolvedCountLocked(previousStatus, existing.Status)
		EnrichFinding(existing)
		eventType := upsertAttestationEvent(true, previousStatus, s.attestReobserved)
		if eventType != "" {
			_ = attestFindingEvent(ctx, s.attestor, existing, eventType, now)
		}
		s.updateMetricsLocked()
		return existing
	}
	if match := s.findSemanticMatchLocked(semanticKey); match != nil {
		previousStatus := s.refreshFindingFromPolicyLocked(match, pf, now, semanticKey)
		s.adjustResolvedCountLocked(previousStatus, match.Status)
		EnrichFinding(match)
		eventType := upsertAttestationEvent(true, previousStatus, s.attestReobserved)
		if eventType != "" {
			_ = attestFindingEvent(ctx, s.attestor, match, eventType, now)
		}
		s.updateMetricsLocked()
		return match
	}

	f := newFindingFromPolicyFinding(pf, now)
	applySemanticObservation(f, pf, semanticKey)
	EnrichFinding(f)
	_ = attestFindingEvent(ctx, s.attestor, f, upsertAttestationEvent(false, "", s.attestReobserved), now)
	s.findings[pf.ID] = f
	s.indexFindingLocked(f)

	if s.maxFindings > 0 && len(s.findings) > s.maxFindings {
		s.evictToCapacity()
	}
	s.updateMetricsLocked()

	return f
}

func normalizeStatus(status string) string {
	if status == "" {
		return ""
	}
	return strings.ToUpper(strings.TrimSpace(status))
}

func inferDomain(policyID, resourceType string) string {
	lookup := strings.ToLower(strings.TrimSpace(policyID + " " + resourceType))
	switch {
	case strings.Contains(lookup, "stripe"),
		strings.Contains(lookup, "billing"),
		strings.Contains(lookup, "invoice"),
		strings.Contains(lookup, "refund"):
		return DomainFinancial
	case strings.Contains(lookup, "deal"),
		strings.Contains(lookup, "opportunity"),
		strings.Contains(lookup, "salesforce"),
		strings.Contains(lookup, "hubspot"):
		return DomainPipeline
	case strings.Contains(lookup, "sla"),
		strings.Contains(lookup, "ticket"),
		strings.Contains(lookup, "zendesk"):
		return DomainSLA
	case strings.Contains(lookup, "customer"),
		strings.Contains(lookup, "churn"),
		strings.Contains(lookup, "health"):
		return DomainCustomerHealth
	case strings.Contains(lookup, "revenue"):
		return DomainRevenue
	default:
		return DomainInfra
	}
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

func extractTenantID(resource map[string]interface{}) string {
	if len(resource) == 0 {
		return ""
	}
	candidates := []string{"tenant_id", "tenantId", "tenant", "organization_id", "org_id"}
	for _, key := range candidates {
		if raw, ok := resource[key]; ok && raw != nil {
			if value, ok := raw.(string); ok {
				value = strings.TrimSpace(value)
				if value != "" {
					return value
				}
			}
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

func (s *Store) SetSemanticDedup(enabled bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.semanticDedup = enabled
	s.rebuildIndexesLocked()
}

func (s *Store) Update(id string, mutate func(*Finding) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	f, ok := s.findings[id]
	if !ok {
		return ErrIssueNotFound
	}
	previousStatus := normalizeStatus(f.Status)
	oldKey := f.SemanticKey
	if err := mutate(f); err != nil {
		return err
	}
	f.Status = normalizeStatus(f.Status)
	refreshFindingSemanticState(f)
	s.syncSemanticIndexLocked(f, oldKey)
	s.adjustResolvedCountLocked(previousStatus, f.Status)
	EnrichFinding(f)
	s.updateMetricsLocked()
	return nil
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
		if filter.TenantID != "" && !strings.EqualFold(strings.TrimSpace(f.TenantID), strings.TrimSpace(filter.TenantID)) {
			continue
		}
		if filter.SignalType != "" && !strings.EqualFold(f.SignalType, filter.SignalType) {
			continue
		}
		if filter.Domain != "" && !strings.EqualFold(f.Domain, filter.Domain) {
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
		if filter.TenantID != "" && !strings.EqualFold(strings.TrimSpace(f.TenantID), strings.TrimSpace(filter.TenantID)) {
			continue
		}
		if filter.SignalType != "" && !strings.EqualFold(f.SignalType, filter.SignalType) {
			continue
		}
		if filter.Domain != "" && !strings.EqualFold(f.Domain, filter.Domain) {
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
	previousStatus := normalizeStatus(f.Status)
	f.Status = "RESOLVED"
	f.ResolvedAt = &now
	f.SnoozedUntil = nil
	f.StatusChangedAt = &now
	f.UpdatedAt = now
	s.adjustResolvedCountLocked(previousStatus, f.Status)
	s.updateMetricsLocked()
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
	previousStatus := normalizeStatus(f.Status)
	f.Status = "SUPPRESSED"
	f.SnoozedUntil = nil
	f.StatusChangedAt = &now
	f.UpdatedAt = now
	s.adjustResolvedCountLocked(previousStatus, f.Status)
	s.updateMetricsLocked()
	return true
}

func (s *Store) Stats() Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := Stats{
		BySeverity:   make(map[string]int),
		ByStatus:     make(map[string]int),
		ByPolicy:     make(map[string]int),
		BySignalType: make(map[string]int),
		ByDomain:     make(map[string]int),
	}

	for _, f := range s.findings {
		stats.Total++
		stats.BySeverity[f.Severity]++
		stats.ByStatus[normalizeStatus(f.Status)]++
		stats.ByPolicy[f.PolicyID]++
		signalType := strings.ToLower(strings.TrimSpace(f.SignalType))
		if signalType == "" {
			signalType = SignalTypeSecurity
		}
		stats.BySignalType[signalType]++
		domain := strings.ToLower(strings.TrimSpace(f.Domain))
		if domain == "" {
			domain = DomainInfra
		}
		stats.ByDomain[domain]++
	}

	return stats
}

type FindingFilter struct {
	Severity   string
	Status     string
	PolicyID   string
	TenantID   string
	SignalType string
	Domain     string
	Limit      int
	Offset     int
}

type Stats struct {
	Total        int            `json:"total"`
	BySeverity   map[string]int `json:"by_severity"`
	ByStatus     map[string]int `json:"by_status"`
	ByPolicy     map[string]int `json:"by_policy"`
	BySignalType map[string]int `json:"by_signal_type,omitempty"`
	ByDomain     map[string]int `json:"by_domain,omitempty"`
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
		if f, ok := s.findings[candidates[i].id]; ok && normalizeStatus(f.Status) == "RESOLVED" {
			s.resolvedCount--
		}
		s.removeFindingLocked(candidates[i].id)
		excess--
	}
	if s.resolvedCount < 0 {
		s.resolvedCount = s.countResolvedFindingsLocked()
	}
}

// cleanupResolvedBeforeLocked removes resolved findings older than cutoff.
// Must be called with s.mu held.
func (s *Store) cleanupResolvedBeforeLocked(cutoff time.Time) int {
	removed := 0
	for id, f := range s.findings {
		if normalizeStatus(f.Status) == "RESOLVED" && f.LastSeen.Before(cutoff) {
			s.removeFindingLocked(id)
			s.resolvedCount--
			removed++
		}
	}
	if s.resolvedCount < 0 {
		s.resolvedCount = s.countResolvedFindingsLocked()
	}
	return removed
}

func (s *Store) countResolvedFindingsLocked() int {
	count := 0
	for _, f := range s.findings {
		if normalizeStatus(f.Status) == "RESOLVED" {
			count++
		}
	}
	return count
}

func (s *Store) maybeCleanupResolvedLocked(now time.Time) {
	if !s.shouldCleanupResolvedLocked(now) {
		return
	}
	_ = s.cleanupResolvedBeforeLocked(now.Add(-s.resolvedRetention))
	s.lastResolvedSweep = now
}

func (s *Store) shouldCleanupResolvedLocked(now time.Time) bool {
	if s.resolvedRetention <= 0 || s.resolvedCount == 0 {
		return false
	}
	if s.lastResolvedSweep.IsZero() {
		return true
	}
	return now.Sub(s.lastResolvedSweep) >= s.resolvedCleanupInterval()
}

func (s *Store) resolvedCleanupInterval() time.Duration {
	if s.resolvedRetention > 0 && s.resolvedRetention < defaultResolvedCleanupInterval {
		return s.resolvedRetention
	}
	return defaultResolvedCleanupInterval
}

func (s *Store) adjustResolvedCountLocked(previousStatus, currentStatus string) {
	switch {
	case previousStatus != "RESOLVED" && currentStatus == "RESOLVED":
		s.resolvedCount++
	case previousStatus == "RESOLVED" && currentStatus != "RESOLVED" && s.resolvedCount > 0:
		s.resolvedCount--
	}
}

// Cleanup removes resolved findings older than maxAge. Returns the number of
// findings removed. This mirrors the FileStore.Cleanup pattern.
func (s *Store) Cleanup(maxAge time.Duration) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	removed := s.cleanupResolvedBeforeLocked(time.Now().Add(-maxAge))
	s.updateMetricsLocked()
	return removed
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

func (s *Store) Config() StoreConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return StoreConfig{
		MaxFindings:       s.maxFindings,
		ResolvedRetention: s.resolvedRetention,
		SemanticDedup:     s.semanticDedup,
	}
}

func (s *Store) refreshFindingFromPolicyLocked(existing *Finding, pf policy.Finding, now time.Time, semanticKey string) string {
	oldKey := existing.SemanticKey
	previousStatus := applyPolicyFindingUpdate(existing, pf, now)
	applySemanticObservation(existing, pf, semanticKey)
	s.syncSemanticIndexLocked(existing, oldKey)
	return previousStatus
}

func (s *Store) findSemanticMatchLocked(semanticKey string) *Finding {
	if !findingNeedsSemanticMatch(s.semanticDedup, semanticKey) {
		return nil
	}
	id, ok := s.semanticIndex[semanticKey]
	if !ok {
		return nil
	}
	return s.findings[id]
}

func (s *Store) syncSemanticIndexLocked(f *Finding, oldKey string) {
	if !s.semanticDedup {
		return
	}
	ensureFindingSemanticState(f)
	oldKey = strings.TrimSpace(oldKey)
	if oldKey != "" && oldKey != f.SemanticKey && s.semanticIndex[oldKey] == f.ID {
		delete(s.semanticIndex, oldKey)
	}
	if strings.TrimSpace(f.SemanticKey) != "" {
		s.semanticIndex[f.SemanticKey] = f.ID
	}
}

func (s *Store) indexFindingLocked(f *Finding) {
	if !s.semanticDedup {
		return
	}
	ensureFindingSemanticState(f)
	if strings.TrimSpace(f.SemanticKey) != "" {
		s.semanticIndex[f.SemanticKey] = f.ID
	}
}

func (s *Store) removeFindingLocked(id string) {
	if f, ok := s.findings[id]; ok {
		if s.semanticDedup {
			ensureFindingSemanticState(f)
			if key := strings.TrimSpace(f.SemanticKey); key != "" && s.semanticIndex[key] == id {
				delete(s.semanticIndex, key)
			}
		}
		delete(s.findings, id)
	}
}

func (s *Store) rebuildIndexesLocked() {
	s.semanticIndex = make(map[string]string, len(s.findings))
	if !s.semanticDedup {
		return
	}
	for _, f := range s.findings {
		s.indexFindingLocked(f)
	}
}

func (s *Store) updateMetricsLocked() {
	metrics.SetFindingsStoreSize(len(s.findings))
}

// Ensure Store implements FindingStore
var _ FindingStore = (*Store)(nil)
