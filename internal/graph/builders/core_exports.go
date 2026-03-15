package builders

import graph "github.com/evalops/cerebro/internal/graph"

type (
	Graph                = graph.Graph
	GraphMutationSummary = graph.GraphMutationSummary
	Metadata             = graph.Metadata
	Node                 = graph.Node
	Edge                 = graph.Edge
	EdgeKind             = graph.EdgeKind
	NodeKind             = graph.NodeKind
	RiskLevel            = graph.RiskLevel
	ToxicCombination     = graph.ToxicCombination
)

const (
	SchemaValidationWarn         = graph.SchemaValidationWarn
	SchemaValidationEnforce      = graph.SchemaValidationEnforce
	GraphMutationModeFullRebuild = graph.GraphMutationModeFullRebuild
	GraphMutationModeIncremental = graph.GraphMutationModeIncremental

	EdgeEffectAllow = graph.EdgeEffectAllow
	EdgeEffectDeny  = graph.EdgeEffectDeny

	EdgeKindCanAdmin       = graph.EdgeKindCanAdmin
	EdgeKindCanAssume      = graph.EdgeKindCanAssume
	EdgeKindCanDelete      = graph.EdgeKindCanDelete
	EdgeKindCanRead        = graph.EdgeKindCanRead
	EdgeKindCanWrite       = graph.EdgeKindCanWrite
	EdgeKindConnectsTo     = graph.EdgeKindConnectsTo
	EdgeKindDeployedFrom   = graph.EdgeKindDeployedFrom
	EdgeKindExposedTo      = graph.EdgeKindExposedTo
	EdgeKindInteractedWith = graph.EdgeKindInteractedWith
	EdgeKindLocatedIn      = graph.EdgeKindLocatedIn
	EdgeKindManagedBy      = graph.EdgeKindManagedBy
	EdgeKindMemberOf       = graph.EdgeKindMemberOf
	EdgeKindReportsTo      = graph.EdgeKindReportsTo
	EdgeKindResolvesTo     = graph.EdgeKindResolvesTo

	NodeKindApplication        = graph.NodeKindApplication
	NodeKindBucket             = graph.NodeKindBucket
	NodeKindClusterRole        = graph.NodeKindClusterRole
	NodeKindClusterRoleBinding = graph.NodeKindClusterRoleBinding
	NodeKindConfigMap          = graph.NodeKindConfigMap
	NodeKindDatabase           = graph.NodeKindDatabase
	NodeKindDepartment         = graph.NodeKindDepartment
	NodeKindDeployment         = graph.NodeKindDeployment
	NodeKindFunction           = graph.NodeKindFunction
	NodeKindGroup              = graph.NodeKindGroup
	NodeKindInstance           = graph.NodeKindInstance
	NodeKindInternet           = graph.NodeKindInternet
	NodeKindLocation           = graph.NodeKindLocation
	NodeKindNamespace          = graph.NodeKindNamespace
	NodeKindNetwork            = graph.NodeKindNetwork
	NodeKindOrganization       = graph.NodeKindOrganization
	NodeKindPersistentVolume   = graph.NodeKindPersistentVolume
	NodeKindPerson             = graph.NodeKindPerson
	NodeKindPod                = graph.NodeKindPod
	NodeKindProject            = graph.NodeKindProject
	NodeKindRepository         = graph.NodeKindRepository
	NodeKindRole               = graph.NodeKindRole
	NodeKindRoleBinding        = graph.NodeKindRoleBinding
	NodeKindSecret             = graph.NodeKindSecret
	NodeKindService            = graph.NodeKindService
	NodeKindServiceAccount     = graph.NodeKindServiceAccount
	NodeKindUser               = graph.NodeKindUser
	NodeKindFolder             = graph.NodeKindFolder
	NodeKindVendor             = graph.NodeKindVendor

	RiskNone     = graph.RiskNone
	RiskLow      = graph.RiskLow
	RiskMedium   = graph.RiskMedium
	RiskHigh     = graph.RiskHigh
	RiskCritical = graph.RiskCritical
)

var (
	New                         = graph.New
	NewToxicCombinationEngine   = graph.NewToxicCombinationEngine
	NormalizeEntityAssetSupport = graph.NormalizeEntityAssetSupport
	ParseARN                    = graph.ParseARN
	ParseAWSPolicy              = graph.ParseAWSPolicy
	ParseTrustPolicy            = graph.ParseTrustPolicy
	FindMatchingNodes           = graph.FindMatchingNodes
	ActionsToEdgeKind           = graph.ActionsToEdgeKind
	ExtractAccountFromARN       = graph.ExtractAccountFromARN
)
