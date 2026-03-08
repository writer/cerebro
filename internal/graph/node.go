package graph

import "time"

// NodeKind represents the type of node in the security graph
type NodeKind string

const (
	// Wildcard kind used by graph patterns.
	NodeKindAny NodeKind = "any"

	// Identity nodes
	NodeKindUser           NodeKind = "user"
	NodeKindRole           NodeKind = "role"
	NodeKindGroup          NodeKind = "group"
	NodeKindServiceAccount NodeKind = "service_account"

	// Resource nodes
	NodeKindBucket      NodeKind = "bucket"
	NodeKindInstance    NodeKind = "instance"
	NodeKindDatabase    NodeKind = "database"
	NodeKindSecret      NodeKind = "secret"
	NodeKindFunction    NodeKind = "function"
	NodeKindNetwork     NodeKind = "network"
	NodeKindApplication NodeKind = "application"

	// Kubernetes nodes
	NodeKindPod                NodeKind = "pod"
	NodeKindDeployment         NodeKind = "deployment"
	NodeKindNamespace          NodeKind = "namespace"
	NodeKindClusterRole        NodeKind = "cluster_role"
	NodeKindClusterRoleBinding NodeKind = "cluster_role_binding"
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
	NodeKindCustomer     NodeKind = "customer"
	NodeKindContact      NodeKind = "contact"
	NodeKindCompany      NodeKind = "company"
	NodeKindDeal         NodeKind = "deal"
	NodeKindOpportunity  NodeKind = "opportunity"
	NodeKindSubscription NodeKind = "subscription"
	NodeKindInvoice      NodeKind = "invoice"
	NodeKindTicket       NodeKind = "ticket"
	NodeKindLead         NodeKind = "lead"
	NodeKindActivity     NodeKind = "activity"
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

// Node represents an entity in the security graph
type Node struct {
	ID                 string            `json:"id"`
	Kind               NodeKind          `json:"kind"`
	Name               string            `json:"name"`
	Provider           string            `json:"provider"`
	Account            string            `json:"account"`
	Region             string            `json:"region,omitempty"`
	Properties         map[string]any    `json:"properties,omitempty"`
	Tags               map[string]string `json:"tags,omitempty"`
	Risk               RiskLevel         `json:"risk"`
	Findings           []string          `json:"findings,omitempty"`
	CreatedAt          time.Time         `json:"created_at"`
	UpdatedAt          time.Time         `json:"updated_at"`
	DeletedAt          *time.Time        `json:"deleted_at,omitempty"`
	Version            int               `json:"version"`
	PreviousProperties map[string]any    `json:"previous_properties,omitempty"`
}

// IsIdentity returns true if the node is an identity type
func (n *Node) IsIdentity() bool {
	switch n.Kind {
	case NodeKindUser, NodeKindRole, NodeKindGroup, NodeKindServiceAccount:
		return true
	}
	return false
}

// IsResource returns true if the node is a resource type
func (n *Node) IsResource() bool {
	switch n.Kind {
	case NodeKindBucket, NodeKindInstance, NodeKindDatabase, NodeKindSecret, NodeKindFunction, NodeKindNetwork, NodeKindApplication,
		NodeKindPod, NodeKindDeployment, NodeKindConfigMap, NodeKindPersistentVolume:
		return true
	}
	return false
}

// IsKubernetes returns true if the node is a Kubernetes type
func (n *Node) IsKubernetes() bool {
	switch n.Kind {
	case NodeKindPod, NodeKindDeployment, NodeKindNamespace, NodeKindClusterRole,
		NodeKindClusterRoleBinding, NodeKindConfigMap, NodeKindPersistentVolume:
		return true
	}
	return false
}

// IsBusinessEntity returns true if the node is a business domain entity.
func (n *Node) IsBusinessEntity() bool {
	switch n.Kind {
	case NodeKindCustomer, NodeKindContact, NodeKindCompany, NodeKindDeal,
		NodeKindOpportunity, NodeKindSubscription, NodeKindInvoice,
		NodeKindTicket, NodeKindLead:
		return true
	}
	return false
}
