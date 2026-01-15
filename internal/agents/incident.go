package agents

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// IncidentResponse provides pre-built incident response capabilities
type IncidentResponse struct {
	registry *AgentRegistry
}

func NewIncidentResponse(registry *AgentRegistry) *IncidentResponse {
	return &IncidentResponse{registry: registry}
}

// Incident represents a security incident being investigated
type Incident struct {
	ID          string                 `json:"id"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Severity    string                 `json:"severity"`
	Status      string                 `json:"status"` // open, investigating, contained, resolved
	AssetID     string                 `json:"asset_id,omitempty"`
	AssetType   string                 `json:"asset_type,omitempty"`
	Findings    []string               `json:"findings"`
	Timeline    []IncidentEvent        `json:"timeline"`
	BlastRadius *BlastRadius           `json:"blast_radius,omitempty"`
	SessionID   string                 `json:"session_id"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// IncidentEvent represents an event in the incident timeline
type IncidentEvent struct {
	Timestamp   time.Time              `json:"timestamp"`
	Type        string                 `json:"type"`  // detection, investigation, action, resolution
	Actor       string                 `json:"actor"` // system, user, agent
	Description string                 `json:"description"`
	Data        map[string]interface{} `json:"data,omitempty"`
}

// BlastRadius represents the potential impact of an incident
type BlastRadius struct {
	Services     []string `json:"services"`
	Resources    int      `json:"resources"`
	Users        int      `json:"users"`
	DataExposure string   `json:"data_exposure"` // none, limited, significant, critical
	RiskScore    int      `json:"risk_score"`
}

// CreateIncidentRequest is the request to create a new incident
type CreateIncidentRequest struct {
	Title       string   `json:"title"`
	Description string   `json:"description,omitempty"`
	AssetID     string   `json:"asset_id,omitempty"`
	AssetType   string   `json:"asset_type,omitempty"`
	Severity    string   `json:"severity"`
	FindingIDs  []string `json:"finding_ids,omitempty"`
}

// CreateIncident creates a new incident and starts investigation
func (ir *IncidentResponse) CreateIncident(ctx context.Context, req CreateIncidentRequest) (*Incident, error) {
	incident := &Incident{
		ID:          uuid.New().String(),
		Title:       req.Title,
		Description: req.Description,
		Severity:    req.Severity,
		Status:      "open",
		AssetID:     req.AssetID,
		AssetType:   req.AssetType,
		Findings:    req.FindingIDs,
		Timeline:    []IncidentEvent{},
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}

	// Add creation event
	incident.Timeline = append(incident.Timeline, IncidentEvent{
		Timestamp:   time.Now().UTC(),
		Type:        "detection",
		Actor:       "system",
		Description: "Incident created",
	})

	// Determine incident type and get playbook
	incidentType := ir.determineIncidentType(req)
	playbook := ir.GetPlaybook(incidentType)

	// Create investigation session
	session, err := ir.registry.CreateSession("security-investigator", "system", SessionContext{
		FindingIDs: req.FindingIDs,
		AssetIDs:   []string{req.AssetID},
		Investigation: &Investigation{
			ID:       incident.ID,
			Title:    req.Title,
			Severity: req.Severity,
			Status:   "open",
		},
		Playbook: playbook,
	})
	if err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}
	incident.SessionID = session.ID

	// Gather initial context (async in real implementation)
	ir.gatherContext(ctx, incident)

	return incident, nil
}

func (ir *IncidentResponse) determineIncidentType(req CreateIncidentRequest) string {
	if contains(req.AssetType, "s3") && contains(req.Title, "Public") {
		return "s3-exposure"
	}
	if contains(req.AssetType, "iam") && (contains(req.Title, "Key") || contains(req.Title, "Credential")) {
		return "iam-compromise"
	}
	if contains(req.AssetType, "ec2") && contains(req.Title, "Public") {
		return "ec2-exposure"
	}
	if contains(req.AssetType, "lambda") || contains(req.AssetType, "function") || contains(req.Title, "Code") {
		return "code-to-cloud"
	}
	return "default"
}

// gatherContext collects initial investigation context
func (ir *IncidentResponse) gatherContext(ctx context.Context, incident *Incident) {
	// Add investigation start event
	incident.Timeline = append(incident.Timeline, IncidentEvent{
		Timestamp:   time.Now().UTC(),
		Type:        "investigation",
		Actor:       "agent",
		Description: "Starting automated context gathering",
	})

	// Calculate blast radius
	incident.BlastRadius = ir.calculateBlastRadius(ctx, incident)

	incident.Status = "investigating"
	incident.UpdatedAt = time.Now().UTC()
}

// calculateBlastRadius determines potential impact
func (ir *IncidentResponse) calculateBlastRadius(_ context.Context, incident *Incident) *BlastRadius {
	radius := &BlastRadius{
		Services:     []string{},
		Resources:    0,
		Users:        0,
		DataExposure: "none",
		RiskScore:    0,
	}

	// Base score on severity
	switch incident.Severity {
	case "critical":
		radius.RiskScore = 80
		radius.DataExposure = "significant"
	case "high":
		radius.RiskScore = 60
		radius.DataExposure = "limited"
	case "medium":
		radius.RiskScore = 40
		radius.DataExposure = "none"
	default:
		radius.RiskScore = 20
		radius.DataExposure = "none"
	}

	// Determine affected services based on asset type
	if incident.AssetType != "" {
		switch {
		case contains(incident.AssetType, "s3"):
			radius.Services = append(radius.Services, "S3", "Data Storage")
			radius.DataExposure = "significant"
		case contains(incident.AssetType, "iam"):
			radius.Services = append(radius.Services, "IAM", "Access Management")
			radius.RiskScore += 20
		case contains(incident.AssetType, "ec2"):
			radius.Services = append(radius.Services, "EC2", "Compute")
		case contains(incident.AssetType, "rds"):
			radius.Services = append(radius.Services, "RDS", "Database")
			radius.DataExposure = "critical"
		case contains(incident.AssetType, "lambda"):
			radius.Services = append(radius.Services, "Lambda", "Serverless")
		}
	}

	// Adjust based on findings count
	radius.Resources = len(incident.Findings)
	if radius.Resources > 5 {
		radius.RiskScore += 10
	}

	// Cap at 100
	if radius.RiskScore > 100 {
		radius.RiskScore = 100
	}

	return radius
}

// GetPlaybook returns the incident response playbook for a given type
func (ir *IncidentResponse) GetPlaybook(incidentType string) *Playbook {
	playbooks := map[string]*Playbook{
		"s3-exposure": {
			ID:          "s3-exposure",
			Name:        "S3 Bucket Exposure Response",
			Description: "Respond to publicly exposed S3 buckets",
			Steps: []PlaybookStep{
				{Order: 1, Name: "Identify Exposure", Action: "query_assets", Description: "Query S3 bucket configuration and ACLs"},
				{Order: 2, Name: "Assess Data Impact", Action: "query_assets", Description: "Identify sensitive data in the bucket"},
				{Order: 3, Name: "Block Public Access", Action: "remediate", RequiresApproval: true, Description: "Apply block public access settings"},
				{Order: 4, Name: "Review Access Logs", Action: "query_assets", Description: "Check CloudTrail for unauthorized access"},
				{Order: 5, Name: "Create Ticket", Action: "create_ticket", Description: "Document incident and remediation"},
			},
		},
		"iam-compromise": {
			ID:          "iam-compromise",
			Name:        "IAM Credential Compromise Response",
			Description: "Respond to potentially compromised IAM credentials",
			Steps: []PlaybookStep{
				{Order: 1, Name: "Identify User/Role", Action: "query_assets", Description: "Get IAM user/role details"},
				{Order: 2, Name: "Disable Credentials", Action: "remediate", RequiresApproval: true, Description: "Disable access keys and console access"},
				{Order: 3, Name: "Review Activity", Action: "query_assets", Description: "Query CloudTrail for recent API calls"},
				{Order: 4, Name: "Identify Resources", Action: "query_assets", Description: "Find resources accessed by the credential"},
				{Order: 5, Name: "Rotate Credentials", Action: "remediate", RequiresApproval: true, Description: "Generate new access keys"},
				{Order: 6, Name: "Create Ticket", Action: "create_ticket", Description: "Document incident timeline"},
			},
		},
		"ec2-exposure": {
			ID:          "ec2-exposure",
			Name:        "EC2 Instance Exposure Response",
			Description: "Respond to publicly exposed EC2 instances",
			Steps: []PlaybookStep{
				{Order: 1, Name: "Identify Instance", Action: "query_assets", Description: "Get EC2 instance details and security groups"},
				{Order: 2, Name: "Review Security Groups", Action: "query_assets", Description: "Check for overly permissive rules"},
				{Order: 3, Name: "Restrict Access", Action: "remediate", RequiresApproval: true, Description: "Update security group rules"},
				{Order: 4, Name: "Check for Compromise", Action: "query_assets", Description: "Review VPC flow logs and CloudTrail"},
				{Order: 5, Name: "Create Ticket", Action: "create_ticket", Description: "Document remediation"},
			},
		},
		"code-to-cloud": {
			ID:          "code-to-cloud",
			Name:        "Code-to-Cloud Deep Research",
			Description: "Investigate code repositories linked to vulnerable cloud assets",
			Steps: []PlaybookStep{
				{Order: 1, Name: "Map Asset to Code", Action: "query_assets", Description: "Identify the Git repository linked to the asset via tags"},
				{Order: 2, Name: "Analyze Codebase", Action: "analyze_repo", Description: "Clone and scan the repository for vulnerabilities matching the cloud finding"},
				{Order: 3, Name: "Verify Cloud State", Action: "inspect_cloud_resource", Description: "Use live API calls (aws_inspect or gcp_inspect) to verify the current configuration of the deployed resource"},
				{Order: 4, Name: "Contextualize Risk", Action: "evaluate_policy", Description: "Determine if the code vulnerability is reachable based on verified cloud configuration"},
				{Order: 5, Name: "Report Findings", Action: "create_ticket", Description: "Create a ticket with linked code and cloud context"},
			},
		},
		"default": {
			ID:          "default",
			Name:        "Generic Security Incident Response",
			Description: "Standard incident response playbook",
			Steps: []PlaybookStep{
				{Order: 1, Name: "Gather Context", Action: "query_assets", Description: "Collect asset and finding information"},
				{Order: 2, Name: "Assess Impact", Action: "query_assets", Description: "Determine blast radius and affected resources"},
				{Order: 3, Name: "Contain Threat", Action: "remediate", RequiresApproval: true, Description: "Apply containment measures"},
				{Order: 4, Name: "Investigate Root Cause", Action: "query_assets", Description: "Review logs and audit trail"},
				{Order: 5, Name: "Remediate", Action: "remediate", RequiresApproval: true, Description: "Apply fixes"},
				{Order: 6, Name: "Document", Action: "create_ticket", Description: "Create incident report"},
			},
		},
	}

	if playbook, ok := playbooks[incidentType]; ok {
		return playbook
	}
	return playbooks["default"]
}

// Playbook represents an incident response playbook
type Playbook struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Steps       []PlaybookStep `json:"steps"`
}

// PlaybookStep represents a step in the playbook
type PlaybookStep struct {
	Order            int    `json:"order"`
	Name             string `json:"name"`
	Action           string `json:"action"`
	Description      string `json:"description"`
	RequiresApproval bool   `json:"requires_approval"`
}

// ListPlaybooks returns all available playbooks
func (ir *IncidentResponse) ListPlaybooks() []*Playbook {
	return []*Playbook{
		ir.GetPlaybook("s3-exposure"),
		ir.GetPlaybook("iam-compromise"),
		ir.GetPlaybook("ec2-exposure"),
		ir.GetPlaybook("default"),
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || (len(s) > 0 && containsAt(s, substr)))
}

func containsAt(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
