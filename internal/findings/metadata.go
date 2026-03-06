package findings

import (
	"encoding/json"
	"time"

	"github.com/evalops/cerebro/internal/policy"
)

type findingMetadata struct {
	IssueID             string                    `json:"issue_id,omitempty"`
	ControlID           string                    `json:"control_id,omitempty"`
	Title               string                    `json:"title,omitempty"`
	SignalType          string                    `json:"signal_type,omitempty"`
	Domain              string                    `json:"domain,omitempty"`
	Resolution          string                    `json:"resolution,omitempty"`
	DueAt               *time.Time                `json:"due_at,omitempty"`
	StatusChangedAt     *time.Time                `json:"status_changed_at,omitempty"`
	SnoozedUntil        *time.Time                `json:"snoozed_until,omitempty"`
	EscalationCount     int                       `json:"escalation_count,omitempty"`
	CreatedAt           *time.Time                `json:"created_at,omitempty"`
	UpdatedAt           *time.Time                `json:"updated_at,omitempty"`
	ResourceName        string                    `json:"resource_name,omitempty"`
	ResourceExternalID  string                    `json:"resource_external_id,omitempty"`
	ResourceRegion      string                    `json:"resource_region,omitempty"`
	ResourceStatus      string                    `json:"resource_status,omitempty"`
	ResourcePlatform    string                    `json:"resource_platform,omitempty"`
	ResourceTags        map[string]string         `json:"resource_tags,omitempty"`
	ResourceJSON        map[string]interface{}    `json:"resource_original_json,omitempty"`
	SubscriptionID      string                    `json:"subscription_id,omitempty"`
	SubscriptionName    string                    `json:"subscription_name,omitempty"`
	ProjectIDs          []string                  `json:"project_ids,omitempty"`
	ProjectNames        []string                  `json:"project_names,omitempty"`
	KubernetesCluster   string                    `json:"kubernetes_cluster,omitempty"`
	KubernetesNamespace string                    `json:"kubernetes_namespace,omitempty"`
	ContainerService    string                    `json:"container_service,omitempty"`
	RiskCategories      []string                  `json:"risk_categories,omitempty"`
	Threats             []string                  `json:"threats,omitempty"`
	Remediation         string                    `json:"remediation_recommendation,omitempty"`
	SecurityFrameworks  []string                  `json:"security_frameworks,omitempty"`
	SecurityCategories  []string                  `json:"security_categories,omitempty"`
	ComplianceMappings  []policy.FrameworkMapping `json:"compliance_mappings,omitempty"`
	MitreAttack         []policy.MitreMapping     `json:"mitre_attack,omitempty"`
	Evidence            []Evidence                `json:"evidence,omitempty"`
	CloudProviderURL    string                    `json:"cloud_provider_url,omitempty"`
	AssigneeName        string                    `json:"assignee_name,omitempty"`
	TicketURLs          []string                  `json:"ticket_urls,omitempty"`
	TicketNames         []string                  `json:"ticket_names,omitempty"`
	TicketExternalIDs   []string                  `json:"ticket_external_ids,omitempty"`
	Notes               string                    `json:"note,omitempty"`
	EntityIDs           []string                  `json:"entity_ids,omitempty"`
}

func buildFindingMetadata(f *Finding) ([]byte, error) {
	metadata := findingMetadata{
		IssueID:             f.IssueID,
		ControlID:           f.ControlID,
		Title:               f.Title,
		SignalType:          f.SignalType,
		Domain:              f.Domain,
		Resolution:          f.Resolution,
		DueAt:               f.DueAt,
		StatusChangedAt:     f.StatusChangedAt,
		SnoozedUntil:        f.SnoozedUntil,
		EscalationCount:     f.EscalationCount,
		ResourceName:        f.ResourceName,
		ResourceExternalID:  f.ResourceExternalID,
		ResourceRegion:      f.ResourceRegion,
		ResourceStatus:      f.ResourceStatus,
		ResourcePlatform:    f.ResourcePlatform,
		ResourceTags:        f.ResourceTags,
		ResourceJSON:        f.ResourceJSON,
		SubscriptionID:      f.SubscriptionID,
		SubscriptionName:    f.SubscriptionName,
		ProjectIDs:          f.ProjectIDs,
		ProjectNames:        f.ProjectNames,
		KubernetesCluster:   f.KubernetesCluster,
		KubernetesNamespace: f.KubernetesNamespace,
		ContainerService:    f.ContainerService,
		RiskCategories:      f.RiskCategories,
		Threats:             f.Threats,
		Remediation:         f.Remediation,
		SecurityFrameworks:  f.SecurityFrameworks,
		SecurityCategories:  f.SecurityCategories,
		ComplianceMappings:  f.ComplianceMappings,
		MitreAttack:         f.MitreAttack,
		Evidence:            f.Evidence,
		CloudProviderURL:    f.CloudProviderURL,
		AssigneeName:        f.AssigneeName,
		TicketURLs:          f.TicketURLs,
		TicketNames:         f.TicketNames,
		TicketExternalIDs:   f.TicketExternalIDs,
		Notes:               f.Notes,
		EntityIDs:           f.EntityIDs,
	}
	if !f.CreatedAt.IsZero() {
		metadata.CreatedAt = &f.CreatedAt
	}
	if !f.UpdatedAt.IsZero() {
		metadata.UpdatedAt = &f.UpdatedAt
	}
	return json.Marshal(metadata)
}

func applyFindingMetadata(f *Finding, data []byte) {
	if len(data) == 0 {
		return
	}

	var metadata findingMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return
	}

	if f.IssueID == "" {
		f.IssueID = metadata.IssueID
	}
	if f.ControlID == "" {
		f.ControlID = metadata.ControlID
	}
	if f.Title == "" {
		f.Title = metadata.Title
	}
	if f.SignalType == "" {
		f.SignalType = metadata.SignalType
	}
	if f.Domain == "" {
		f.Domain = metadata.Domain
	}
	if f.Resolution == "" {
		f.Resolution = metadata.Resolution
	}
	if f.DueAt == nil && metadata.DueAt != nil {
		f.DueAt = metadata.DueAt
	}
	if f.StatusChangedAt == nil && metadata.StatusChangedAt != nil {
		f.StatusChangedAt = metadata.StatusChangedAt
	}
	if f.SnoozedUntil == nil && metadata.SnoozedUntil != nil {
		f.SnoozedUntil = metadata.SnoozedUntil
	}
	if f.EscalationCount == 0 && metadata.EscalationCount > 0 {
		f.EscalationCount = metadata.EscalationCount
	}
	if f.CreatedAt.IsZero() && metadata.CreatedAt != nil {
		f.CreatedAt = *metadata.CreatedAt
	}
	if f.UpdatedAt.IsZero() && metadata.UpdatedAt != nil {
		f.UpdatedAt = *metadata.UpdatedAt
	}
	if f.ResourceName == "" {
		f.ResourceName = metadata.ResourceName
	}
	if f.ResourceExternalID == "" {
		f.ResourceExternalID = metadata.ResourceExternalID
	}
	if f.ResourceRegion == "" {
		f.ResourceRegion = metadata.ResourceRegion
	}
	if f.ResourceStatus == "" {
		f.ResourceStatus = metadata.ResourceStatus
	}
	if f.ResourcePlatform == "" {
		f.ResourcePlatform = metadata.ResourcePlatform
	}
	if f.ResourceTags == nil && metadata.ResourceTags != nil {
		f.ResourceTags = metadata.ResourceTags
	}
	if f.ResourceJSON == nil && metadata.ResourceJSON != nil {
		f.ResourceJSON = metadata.ResourceJSON
	}
	if f.SubscriptionID == "" {
		f.SubscriptionID = metadata.SubscriptionID
	}
	if f.SubscriptionName == "" {
		f.SubscriptionName = metadata.SubscriptionName
	}
	if len(f.ProjectIDs) == 0 && len(metadata.ProjectIDs) > 0 {
		f.ProjectIDs = metadata.ProjectIDs
	}
	if len(f.ProjectNames) == 0 && len(metadata.ProjectNames) > 0 {
		f.ProjectNames = metadata.ProjectNames
	}
	if f.KubernetesCluster == "" {
		f.KubernetesCluster = metadata.KubernetesCluster
	}
	if f.KubernetesNamespace == "" {
		f.KubernetesNamespace = metadata.KubernetesNamespace
	}
	if f.ContainerService == "" {
		f.ContainerService = metadata.ContainerService
	}
	if len(f.RiskCategories) == 0 && len(metadata.RiskCategories) > 0 {
		f.RiskCategories = metadata.RiskCategories
	}
	if len(f.Threats) == 0 && len(metadata.Threats) > 0 {
		f.Threats = metadata.Threats
	}
	if f.Remediation == "" {
		f.Remediation = metadata.Remediation
	}
	if len(f.SecurityFrameworks) == 0 && len(metadata.SecurityFrameworks) > 0 {
		f.SecurityFrameworks = metadata.SecurityFrameworks
	}
	if len(f.SecurityCategories) == 0 && len(metadata.SecurityCategories) > 0 {
		f.SecurityCategories = metadata.SecurityCategories
	}
	if len(f.ComplianceMappings) == 0 && len(metadata.ComplianceMappings) > 0 {
		f.ComplianceMappings = metadata.ComplianceMappings
	}
	if len(f.MitreAttack) == 0 && len(metadata.MitreAttack) > 0 {
		f.MitreAttack = metadata.MitreAttack
	}
	if len(f.Evidence) == 0 && len(metadata.Evidence) > 0 {
		f.Evidence = metadata.Evidence
	}
	if f.CloudProviderURL == "" {
		f.CloudProviderURL = metadata.CloudProviderURL
	}
	if f.AssigneeName == "" {
		f.AssigneeName = metadata.AssigneeName
	}
	if len(f.TicketURLs) == 0 && len(metadata.TicketURLs) > 0 {
		f.TicketURLs = metadata.TicketURLs
	}
	if len(f.TicketNames) == 0 && len(metadata.TicketNames) > 0 {
		f.TicketNames = metadata.TicketNames
	}
	if len(f.TicketExternalIDs) == 0 && len(metadata.TicketExternalIDs) > 0 {
		f.TicketExternalIDs = metadata.TicketExternalIDs
	}
	if f.Notes == "" {
		f.Notes = metadata.Notes
	}
	if len(f.EntityIDs) == 0 && len(metadata.EntityIDs) > 0 {
		f.EntityIDs = metadata.EntityIDs
	}
}
