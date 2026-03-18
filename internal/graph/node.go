package graph

import "time"

// NodeKind represents the type of node in the graph platform.
type NodeKind string

const (
	// Wildcard kind used by graph patterns.
	NodeKindAny NodeKind = "any"

	// Identity nodes
	NodeKindUser           NodeKind = "user"
	NodeKindPerson         NodeKind = "person"
	NodeKindIdentityAlias  NodeKind = "identity_alias"
	NodeKindRole           NodeKind = "role"
	NodeKindGroup          NodeKind = "group"
	NodeKindServiceAccount NodeKind = "service_account"

	// Resource nodes
	NodeKindService                 NodeKind = "service"
	NodeKindWorkload                NodeKind = "workload"
	NodeKindBucket                  NodeKind = "bucket"
	NodeKindBucketPolicyStatement   NodeKind = "bucket_policy_statement"
	NodeKindBucketPublicAccessBlock NodeKind = "bucket_public_access_block"
	NodeKindBucketEncryptionConfig  NodeKind = "bucket_encryption_config"
	NodeKindBucketLoggingConfig     NodeKind = "bucket_logging_config"
	NodeKindBucketVersioningConfig  NodeKind = "bucket_versioning_config"
	NodeKindInstance                NodeKind = "instance"
	NodeKindDatabase                NodeKind = "database"
	NodeKindSecret                  NodeKind = "secret"
	NodeKindFunction                NodeKind = "function"
	NodeKindWorkloadScan            NodeKind = "workload_scan"
	NodeKindPackage                 NodeKind = "package"
	NodeKindVulnerability           NodeKind = "vulnerability"
	NodeKindTechnology              NodeKind = "technology"
	NodeKindNetwork                 NodeKind = "network"
	NodeKindApplication             NodeKind = "application"
	NodeKindOrganization            NodeKind = "organization"
	NodeKindFolder                  NodeKind = "folder"
	NodeKindProject                 NodeKind = "project"

	// Kubernetes nodes
	NodeKindPod                NodeKind = "pod"
	NodeKindDeployment         NodeKind = "deployment"
	NodeKindNamespace          NodeKind = "namespace"
	NodeKindClusterRole        NodeKind = "cluster_role"
	NodeKindClusterRoleBinding NodeKind = "cluster_role_binding"
	NodeKindRoleBinding        NodeKind = "role_binding"
	NodeKindConfigMap          NodeKind = "configmap"
	NodeKindPersistentVolume   NodeKind = "persistent_volume"

	// SCM nodes
	NodeKindRepository NodeKind = "repository"
	NodeKindCIWorkflow NodeKind = "ci_workflow"

	// Abstract nodes
	NodeKindInternet NodeKind = "internet"

	// Policy nodes
	NodeKindSCP                NodeKind = "scp"                 // Service Control Policy
	NodeKindPermissionBoundary NodeKind = "permission_boundary" // AWS Permission Boundary

	// Business entities
	NodeKindCustomer       NodeKind = "customer"
	NodeKindContact        NodeKind = "contact"
	NodeKindCompany        NodeKind = "company"
	NodeKindVendor         NodeKind = "vendor"
	NodeKindDeal           NodeKind = "deal"
	NodeKindOpportunity    NodeKind = "opportunity"
	NodeKindSubscription   NodeKind = "subscription"
	NodeKindInvoice        NodeKind = "invoice"
	NodeKindTicket         NodeKind = "ticket"
	NodeKindLead           NodeKind = "lead"
	NodeKindActivity       NodeKind = "activity"
	NodeKindPullRequest    NodeKind = "pull_request"
	NodeKindDeploymentRun  NodeKind = "deployment_run"
	NodeKindPipelineRun    NodeKind = "pipeline_run"
	NodeKindCheckRun       NodeKind = "check_run"
	NodeKindMeeting        NodeKind = "meeting"
	NodeKindDocument       NodeKind = "document"
	NodeKindThread         NodeKind = "communication_thread"
	NodeKindIncident       NodeKind = "incident"
	NodeKindDecision       NodeKind = "decision"
	NodeKindOutcome        NodeKind = "outcome"
	NodeKindEvidence       NodeKind = "evidence"
	NodeKindObservation    NodeKind = "observation"
	NodeKindAttackSequence NodeKind = "attack_sequence"
	NodeKindSource         NodeKind = "source"
	NodeKindClaim          NodeKind = "claim"
	NodeKindAction         NodeKind = "action"
	NodeKindDepartment     NodeKind = "department"
	NodeKindLocation       NodeKind = "location"
)

// RiskLevel represents the risk level of a node or edge
type RiskLevel string

const (
	RiskCritical RiskLevel = "critical"
	RiskHigh     RiskLevel = "high"
	RiskMedium   RiskLevel = "medium"
	RiskLow      RiskLevel = "low"
	RiskNone     RiskLevel = "none"
)

// PropertySnapshot captures one point-in-time value for a node property.
type PropertySnapshot struct {
	Timestamp time.Time `json:"timestamp"`
	Value     any       `json:"value"`
}

// Node represents an entity in the graph platform.
type Node struct {
	ID                  string                        `json:"id"`
	Kind                NodeKind                      `json:"kind"`
	Name                string                        `json:"name"`
	TenantID            string                        `json:"tenant_id,omitempty"`
	Provider            string                        `json:"provider"`
	Account             string                        `json:"account"`
	Region              string                        `json:"region,omitempty"`
	Properties          map[string]any                `json:"properties,omitempty"`
	Tags                map[string]string             `json:"tags,omitempty"`
	Risk                RiskLevel                     `json:"risk"`
	Findings            []string                      `json:"findings,omitempty"`
	CreatedAt           time.Time                     `json:"created_at"`
	UpdatedAt           time.Time                     `json:"updated_at"`
	DeletedAt           *time.Time                    `json:"deleted_at,omitempty"`
	Version             int                           `json:"version"`
	PreviousProperties  map[string]any                `json:"previous_properties,omitempty"`
	PropertyHistory     map[string][]PropertySnapshot `json:"property_history,omitempty"`
	observationProps    *ObservationProperties        `json:"-"`
	attackSequenceProps *AttackSequenceProperties     `json:"-"`
}

// IsIdentity returns true if the node is an identity type
func (n *Node) IsIdentity() bool {
	return n != nil && IsNodeKindInCategory(n.Kind, NodeCategoryIdentity)
}

// IsResource returns true if the node is a resource type
func (n *Node) IsResource() bool {
	return n != nil && IsNodeKindInCategory(n.Kind, NodeCategoryResource)
}

// IsKubernetes returns true if the node is a Kubernetes type
func (n *Node) IsKubernetes() bool {
	return n != nil && IsNodeKindInCategory(n.Kind, NodeCategoryKubernetes)
}

// IsBusinessEntity returns true if the node is a business domain entity.
func (n *Node) IsBusinessEntity() bool {
	return n != nil && IsNodeKindInCategory(n.Kind, NodeCategoryBusiness)
}
