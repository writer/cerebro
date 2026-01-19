# Cerebro Wiz Parity Enhancement Specification

## Overview

This document outlines the enhancements needed to bring Cerebro's findings and reporting closer to Wiz's capabilities.

## 1. Enhanced Policy Schema

Add new fields to the Policy struct to support Wiz-like metadata:

```go
type Policy struct {
    // Existing fields
    ID          string   `json:"id"`
    Name        string   `json:"name"`
    Description string   `json:"description"`
    Effect      string   `json:"effect"`
    Resource    string   `json:"resource"`
    Conditions  []string `json:"conditions"`
    Severity    string   `json:"severity"`
    Tags        []string `json:"tags"`
    
    // NEW: Wiz compatibility
    WizControlID string `json:"wiz_control_id,omitempty"` // e.g., "wc-id-1211"
    
    // NEW: Detailed remediation
    Remediation         string   `json:"remediation,omitempty"`
    RemediationSteps    []string `json:"remediation_steps,omitempty"`
    
    // NEW: Risk categorization (matches Wiz's Risks field)
    RiskCategories []string `json:"risk_categories,omitempty"` // EXTERNAL_EXPOSURE, UNPROTECTED_DATA, VULNERABILITY, etc.
    
    // NEW: Compliance framework mappings
    Frameworks []FrameworkMapping `json:"frameworks,omitempty"`
    
    // NEW: MITRE ATT&CK mapping
    MitreAttack []MitreMapping `json:"mitre_attack,omitempty"`
}

type FrameworkMapping struct {
    Name     string   `json:"name"`     // "CIS Controls v8", "NIST 800-53", "PCI DSS v4.0.1", etc.
    Controls []string `json:"controls"` // Specific control IDs
}

type MitreMapping struct {
    Tactic    string `json:"tactic"`    // "Initial Access", "Execution", etc.
    Technique string `json:"technique"` // "T1190", etc.
}
```

## 2. Enhanced Finding Schema

Update the Finding struct to match Wiz's Issue format:

```go
type Finding struct {
    // Core identification
    ID           string    `json:"id"`
    IssueID      string    `json:"issue_id"`       // Unique issue identifier
    ControlID    string    `json:"control_id"`     // Policy/control that triggered this
    
    // Policy info
    PolicyID     string    `json:"policy_id"`
    PolicyName   string    `json:"policy_name"`
    Title        string    `json:"title"`          // Human-readable issue title
    Description  string    `json:"description"`
    Severity     string    `json:"severity"`
    
    // Status & lifecycle
    Status       string     `json:"status"`        // OPEN, RESOLVED, SUPPRESSED, IN_PROGRESS
    Resolution   string     `json:"resolution,omitempty"` // How it was resolved
    ResolvedAt   *time.Time `json:"resolved_at,omitempty"`
    DueAt        *time.Time `json:"due_at,omitempty"`
    
    // Timestamps
    CreatedAt    time.Time  `json:"created_at"`
    UpdatedAt    time.Time  `json:"updated_at"`
    FirstSeen    time.Time  `json:"first_seen"`
    LastSeen     time.Time  `json:"last_seen"`
    StatusChangedAt *time.Time `json:"status_changed_at,omitempty"`
    
    // Resource details
    ResourceID       string                 `json:"resource_id"`
    ResourceName     string                 `json:"resource_name"`
    ResourceType     string                 `json:"resource_type"`
    ResourceExternalID string               `json:"resource_external_id"` // ARN, GCP resource path, etc.
    ResourceRegion   string                 `json:"resource_region"`
    ResourceStatus   string                 `json:"resource_status"`      // Active, Deleted, etc.
    ResourcePlatform string                 `json:"resource_platform"`    // AWS, GCP, Azure
    ResourceTags     map[string]string      `json:"resource_tags,omitempty"`
    ResourceJSON     map[string]interface{} `json:"resource_original_json,omitempty"`
    
    // Cloud context
    SubscriptionID   string   `json:"subscription_id,omitempty"`   // AWS Account ID, GCP Project, etc.
    SubscriptionName string   `json:"subscription_name,omitempty"`
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
    RemediationRecommendation string `json:"remediation_recommendation,omitempty"`
    
    // Compliance mapping
    SecurityFrameworks  []string `json:"security_frameworks,omitempty"`
    SecurityCategories  []string `json:"security_categories,omitempty"`
    
    // Evidence
    Evidence []Evidence `json:"evidence,omitempty"`
    
    // Links
    WizURL          string `json:"wiz_url,omitempty"`
    CloudProviderURL string `json:"cloud_provider_url,omitempty"`
    
    // Assignment & ticketing
    AssigneeName    string   `json:"assignee_name,omitempty"`
    TicketURLs      []string `json:"ticket_urls,omitempty"`
    TicketNames     []string `json:"ticket_names,omitempty"`
    TicketExternalIDs []string `json:"ticket_external_ids,omitempty"`
    Notes           string   `json:"note,omitempty"`
}

type Evidence struct {
    Type        string                 `json:"type"`
    Description string                 `json:"description"`
    Data        map[string]interface{} `json:"data,omitempty"`
}
```

## 3. Risk Categories

Define standard risk categories matching Wiz:

```go
const (
    RiskExternalExposure       = "EXTERNAL_EXPOSURE"
    RiskExternalAttackSurface  = "EXTERNAL_ATTACK_SURFACE"
    RiskUnprotectedData        = "UNPROTECTED_DATA"
    RiskUnprotectedPrincipal   = "UNPROTECTED_PRINCIPAL"
    RiskVulnerability          = "VULNERABILITY"
    RiskMisconfiguration       = "MISCONFIGURATION"
    RiskIdentityRisk           = "IDENTITY_RISK"
    RiskDataExfiltration       = "DATA_EXFILTRATION"
    RiskLateralMovement        = "LATERAL_MOVEMENT"
    RiskPrivilegeEscalation    = "PRIVILEGE_ESCALATION"
)
```

## 4. Compliance Framework Definitions

Create a compliance mapping registry:

```go
var ComplianceFrameworks = map[string]Framework{
    "cis-aws-2.0": {
        Name: "CIS AWS Foundations Benchmark v2.0",
        Controls: map[string]Control{
            "1.5": {ID: "1.5", Name: "Ensure MFA is enabled for the root account"},
            "1.12": {ID: "1.12", Name: "Ensure credentials unused for 45 days are disabled"},
            // ... more controls
        },
    },
    "nist-800-53-r5": {
        Name: "NIST SP 800-53 Revision 5",
        Controls: map[string]Control{
            "AC-1": {ID: "AC-1", Name: "Access Control Policy and Procedures"},
            // ... more controls
        },
    },
    "pci-dss-4.0.1": {
        Name: "PCI DSS v4.0.1",
        Controls: map[string]Control{
            "1.4": {ID: "1.4", Name: "Network connections between trusted and untrusted networks are controlled"},
            // ... more controls
        },
    },
    "soc2": {
        Name: "SOC 2",
        Controls: map[string]Control{
            "CC6": {ID: "CC6", Name: "Logical and Physical Access Controls"},
            // ... more controls
        },
    },
    // Add: ISO 27001, HIPAA, GDPR, etc.
}
```

## 5. Cloud Provider URL Generation

Add functions to generate direct links to cloud consoles:

```go
func GenerateCloudProviderURL(resource map[string]interface{}) string {
    platform := extractPlatform(resource)
    
    switch platform {
    case "AWS":
        return generateAWSConsoleURL(resource)
    case "GCP":
        return generateGCPConsoleURL(resource)
    case "Azure":
        return generateAzurePortalURL(resource)
    }
    return ""
}

func generateAWSConsoleURL(resource map[string]interface{}) string {
    arn := resource["arn"].(string)
    region := resource["region"].(string)
    
    // Parse ARN and generate appropriate console URL
    // e.g., arn:aws:iam::123456789012:role/MyRole
    // -> https://console.aws.amazon.com/iam/home?region=us-east-1#/roles/MyRole
}
```

## 6. Export Formats

### CSV Export (Wiz-compatible)

Add CSV export matching Wiz's format:

```go
type CSVExporter struct{}

func (e *CSVExporter) Export(findings []*Finding) []byte {
    headers := []string{
        "Created At", "Title", "Severity", "Status", "Description",
        "Resource Type", "Resource external ID", "Subscription ID",
        "Project IDs", "Project Names", "Resolved Time", "Resolution",
        "Control ID", "Resource Name", "Resource Region", "Resource Status",
        "Resource Platform", "Resource OS", "Resource original JSON",
        "Issue ID", "Resource vertex ID", "Ticket URLs", "Note", "Due At",
        "Remediation Recommendation", "Subscription Name", "Wiz URL",
        "Cloud Provider URL", "Resource Tags", "Kubernetes Cluster",
        "Kubernetes Namespace", "Container Service", "Provider ID",
        "Risks", "Threats", "Status Changed At", "Updated At",
        "Assignee Name", "Ticket Names", "Ticket External IDs",
        "Security Frameworks", "Security Categories", "Evidence",
    }
    // ... implementation
}
```

### JSON Export

```go
type JSONExporter struct{}

func (e *JSONExporter) Export(findings []*Finding) []byte {
    // Export full finding details as JSON
}
```

## 7. Issue Lifecycle Management

Add issue management capabilities:

```go
type IssueManager struct {
    store FindingStore
}

func (m *IssueManager) Assign(issueID, assignee string) error
func (m *IssueManager) SetDueDate(issueID string, dueAt time.Time) error
func (m *IssueManager) AddNote(issueID, note string) error
func (m *IssueManager) LinkTicket(issueID, ticketURL, ticketName string) error
func (m *IssueManager) Resolve(issueID, resolution string) error
func (m *IssueManager) Suppress(issueID, reason string) error
func (m *IssueManager) Reopen(issueID string) error
```

## 8. Attack Path Analysis

Add attack path correlation (like Wiz's toxic combinations):

```go
type AttackPathAnalyzer struct {
    graph *SecurityGraph
}

func (a *AttackPathAnalyzer) AnalyzeResource(resourceID string) []AttackPath {
    // Find attack paths involving this resource
    // e.g., "Internet-facing VM + vulnerability + data access"
}

type AttackPath struct {
    ID          string
    Severity    string
    Description string
    Steps       []AttackStep
    Risks       []string
}

type AttackStep struct {
    Resource    string
    Condition   string
    Description string
}
```

## 9. API Enhancements

### New Endpoints

```
GET  /api/v1/issues                    # List all issues (paginated)
GET  /api/v1/issues/{id}               # Get issue details
PUT  /api/v1/issues/{id}/status        # Update issue status
PUT  /api/v1/issues/{id}/assign        # Assign issue
POST /api/v1/issues/{id}/notes         # Add note
POST /api/v1/issues/{id}/tickets       # Link ticket
GET  /api/v1/issues/export             # Export issues (CSV/JSON)
GET  /api/v1/compliance/frameworks     # List compliance frameworks
GET  /api/v1/compliance/coverage       # Get compliance coverage report
GET  /api/v1/attack-paths              # List attack paths
GET  /api/v1/attack-paths/{id}         # Get attack path details
```

## 10. Implementation Phases

### Phase 1: Schema Enhancement (Week 1)
- [ ] Update Policy struct with new fields
- [ ] Update Finding struct with Wiz-compatible fields
- [ ] Add risk category constants
- [ ] Update existing policies with new fields

### Phase 2: Resource Enrichment (Week 2)
- [ ] Add cloud provider URL generation
- [ ] Extract and populate resource metadata (tags, region, status)
- [ ] Add Kubernetes context extraction
- [ ] Store full resource JSON

### Phase 3: Compliance Mapping (Week 3)
- [ ] Define compliance framework registry
- [ ] Map existing policies to frameworks (CIS, NIST, PCI DSS, SOC2)
- [ ] Add compliance coverage reporting
- [ ] Add MITRE ATT&CK mappings

### Phase 4: Export & Reporting (Week 4)
- [ ] Implement CSV export (Wiz-compatible format)
- [ ] Implement JSON export
- [ ] Add filtering and search capabilities
- [ ] Create dashboard widgets

### Phase 5: Issue Management (Week 5)
- [ ] Add assignment functionality
- [ ] Add ticket linking (Jira, ServiceNow, Linear)
- [ ] Add notes and comments
- [ ] Add due date management
- [ ] Add bulk operations

### Phase 6: Attack Path Analysis (Week 6)
- [ ] Enhance security graph with attack path detection
- [ ] Implement toxic combination detection
- [ ] Add attack path visualization
- [ ] Create attack path findings

## 11. Sample Enhanced Policy

```json
{
  "id": "aws-vm-internet-vuln-data",
  "wiz_control_id": "wc-id-1211",
  "name": "Internet-facing VM/serverless with initial access vulnerabilities and data access to sensitive data",
  "description": "This VM/serverless is exposed to the public Internet with high exposure level, has a role with access to sensitive data, and has a critical/high severity initial access vulnerability.",
  "effect": "forbid",
  "resource": "aws::ec2::instance",
  "conditions": [
    "public_ip != null",
    "vulnerabilities ANY (severity IN ['critical', 'high'] AND exploitable == true)",
    "iam_role.has_data_access == true"
  ],
  "severity": "critical",
  "risk_categories": ["EXTERNAL_EXPOSURE", "UNPROTECTED_DATA", "UNPROTECTED_PRINCIPAL", "VULNERABILITY"],
  "remediation": "### Limit external exposure\n* Restrict access to resources that do not need to be accessible from the internet.\n* Ensure that exposed ports allow only encrypted communications.\n\n### Patch vulnerabilities\n* Update all software running in your environment to the latest version.\n\n### Protect sensitive data\n* Sensitive information should not be directly accessible from the internet.",
  "remediation_steps": [
    "Restrict internet access if not required",
    "Patch critical and high vulnerabilities",
    "Review and reduce IAM role permissions",
    "Enable encryption for data at rest and in transit"
  ],
  "frameworks": [
    {"name": "CIS Controls v8", "controls": ["3", "7", "11", "16"]},
    {"name": "NIST 800-53 r5", "controls": ["AC-1", "SA-1", "SC-1"]},
    {"name": "PCI DSS v4.0.1", "controls": ["1.4", "6.5", "7.2"]},
    {"name": "SOC 2", "controls": ["CC6", "CC8"]}
  ],
  "mitre_attack": [
    {"tactic": "Initial Access", "technique": "T1190"},
    {"tactic": "Collection", "technique": "T1530"}
  ],
  "tags": ["aws", "compute", "vulnerability", "data-access", "internet-facing"]
}
```
