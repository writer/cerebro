package reports

import (
	"sort"
	"strings"
	"time"
)

const defaultAIWorkloadMaxResults = 50

// AIWorkloadInventoryReportOptions controls AI workload inventory generation.
type AIWorkloadInventoryReportOptions struct {
	Now           time.Time
	MaxWorkloads  int
	MinRiskScore  int
	IncludeShadow bool
}

// AIWorkloadSummary captures top-line AI workload posture metrics.
type AIWorkloadSummary struct {
	WorkloadCount                int `json:"workload_count"`
	ReturnedWorkloadCount        int `json:"returned_workload_count"`
	HighRiskWorkloadCount        int `json:"high_risk_workload_count"`
	InternetExposedWorkloadCount int `json:"internet_exposed_workload_count"`
	ShadowAIWorkloadCount        int `json:"shadow_ai_workload_count"`
	SensitiveDataWorkloadCount   int `json:"sensitive_data_workload_count"`
	PlaintextKeyWorkloadCount    int `json:"plaintext_key_workload_count"`
	CloudManagedWorkloadCount    int `json:"cloud_managed_workload_count"`
	SelfHostedWorkloadCount      int `json:"self_hosted_workload_count"`
}

// AIWorkloadRiskDriver describes one risk factor contributing to workload posture.
type AIWorkloadRiskDriver struct {
	Type     string   `json:"type"`
	Severity Severity `json:"severity"`
	Summary  string   `json:"summary"`
	Value    int      `json:"value,omitempty"`
}

// AIWorkloadRecord describes one detected AI workload or AI-adjacent application.
type AIWorkloadRecord struct {
	NodeID                  string                 `json:"node_id"`
	Name                    string                 `json:"name"`
	Kind                    string                 `json:"kind"`
	Provider                string                 `json:"provider,omitempty"`
	DeploymentModel         string                 `json:"deployment_model"`
	AIServiceType           string                 `json:"ai_service_type"`
	RiskLevel               RiskLevel              `json:"risk_level"`
	RiskScore               int                    `json:"risk_score"`
	ShadowAI                bool                   `json:"shadow_ai"`
	InternetExposed         bool                   `json:"internet_exposed"`
	SensitiveDataAccess     bool                   `json:"sensitive_data_access"`
	DataStoreCount          int                    `json:"data_store_count"`
	SensitiveDataStoreCount int                    `json:"sensitive_data_store_count"`
	PlaintextProviderKeys   []string               `json:"plaintext_provider_keys,omitempty"`
	DataStoreKinds          []string               `json:"data_store_kinds,omitempty"`
	SensitiveDataStoreIDs   []string               `json:"sensitive_data_store_ids,omitempty"`
	AdminIdentityIDs        []string               `json:"admin_identity_ids,omitempty"`
	DetectorSources         []string               `json:"detector_sources,omitempty"`
	Indicators              []string               `json:"indicators,omitempty"`
	RiskDrivers             []AIWorkloadRiskDriver `json:"risk_drivers,omitempty"`
}

// AIWorkloadExposure describes the highest-signal exposure slice for one workload.
type AIWorkloadExposure struct {
	WorkloadID              string    `json:"workload_id"`
	WorkloadName            string    `json:"workload_name"`
	AIServiceType           string    `json:"ai_service_type"`
	RiskLevel               RiskLevel `json:"risk_level"`
	RiskScore               int       `json:"risk_score"`
	InternetExposed         bool      `json:"internet_exposed"`
	SensitiveDataStoreCount int       `json:"sensitive_data_store_count"`
	SensitiveDataStoreIDs   []string  `json:"sensitive_data_store_ids,omitempty"`
	PlaintextProviderKeys   []string  `json:"plaintext_provider_keys,omitempty"`
}

// AIWorkloadRecommendation describes one suggested AI-SPM remediation step.
type AIWorkloadRecommendation struct {
	Priority        string `json:"priority"`
	Category        string `json:"category"`
	Title           string `json:"title"`
	Detail          string `json:"detail"`
	SuggestedAction string `json:"suggested_action,omitempty"`
}

// AIWorkloadInventoryReport summarizes AI workload inventory and posture.
type AIWorkloadInventoryReport struct {
	GeneratedAt       time.Time                  `json:"generated_at"`
	Summary           AIWorkloadSummary          `json:"summary"`
	Workloads         []AIWorkloadRecord         `json:"workloads,omitempty"`
	DataExposures     []AIWorkloadExposure       `json:"data_exposures,omitempty"`
	ShadowAIWorkloads []AIWorkloadRecord         `json:"shadow_ai_workloads,omitempty"`
	Recommendations   []AIWorkloadRecommendation `json:"recommendations,omitempty"`
}

type aiIndicatorSpec struct {
	Needle         string
	ServiceType    string
	DetectorSource string
	Score          int
	CloudManaged   bool
	SelfHosted     bool
}

type aiNodeSignal struct {
	ServiceTypeScores map[string]int
	DetectorSources   map[string]struct{}
	Indicators        map[string]struct{}
	ProviderKeys      map[string]struct{}
	CloudManaged      bool
	SelfHosted        bool
}

type aiWorkloadAccumulator struct {
	Node                  *Node
	ServiceTypeScores     map[string]int
	DetectorSources       map[string]struct{}
	Indicators            map[string]struct{}
	ProviderKeys          map[string]struct{}
	CloudManaged          bool
	SelfHosted            bool
	DataStoreKinds        map[string]struct{}
	SensitiveDataStoreIDs map[string]struct{}
	AdminIdentityIDs      map[string]struct{}
}

var aiIndicatorCatalog = []aiIndicatorSpec{
	{Needle: "sagemaker endpoint", ServiceType: "serving", DetectorSource: "cloud_service", Score: 96, CloudManaged: true},
	{Needle: "sagemaker notebook", ServiceType: "notebook", DetectorSource: "cloud_service", Score: 94, CloudManaged: true},
	{Needle: "sagemaker training", ServiceType: "training", DetectorSource: "cloud_service", Score: 94, CloudManaged: true},
	{Needle: "sagemaker", ServiceType: "serving", DetectorSource: "cloud_service", Score: 88, CloudManaged: true},
	{Needle: "bedrock", ServiceType: "foundation_model", DetectorSource: "cloud_service", Score: 88, CloudManaged: true},
	{Needle: "vertex ai", ServiceType: "serving", DetectorSource: "cloud_service", Score: 88, CloudManaged: true},
	{Needle: "azure ml", ServiceType: "training", DetectorSource: "cloud_service", Score: 88, CloudManaged: true},
	{Needle: "azure openai", ServiceType: "serving", DetectorSource: "cloud_service", Score: 88, CloudManaged: true},
	{Needle: "cognitive services", ServiceType: "serving", DetectorSource: "cloud_service", Score: 78, CloudManaged: true},
	{Needle: "openai deployment", ServiceType: "serving", DetectorSource: "cloud_service", Score: 86, CloudManaged: true},
	{Needle: "vllm", ServiceType: "serving", DetectorSource: "package_indicator", Score: 90, SelfHosted: true},
	{Needle: "ollama", ServiceType: "serving", DetectorSource: "package_indicator", Score: 90, SelfHosted: true},
	{Needle: "pytorch", ServiceType: "training", DetectorSource: "package_indicator", Score: 86, SelfHosted: true},
	{Needle: "tensorflow", ServiceType: "training", DetectorSource: "package_indicator", Score: 86, SelfHosted: true},
	{Needle: "jax", ServiceType: "training", DetectorSource: "package_indicator", Score: 84, SelfHosted: true},
	{Needle: "cuda", ServiceType: "gpu_compute", DetectorSource: "technology_indicator", Score: 76, SelfHosted: true},
	{Needle: "gguf", ServiceType: "serving", DetectorSource: "package_indicator", Score: 82, SelfHosted: true},
	{Needle: "safetensors", ServiceType: "training", DetectorSource: "package_indicator", Score: 82, SelfHosted: true},
	{Needle: "onnx", ServiceType: "serving", DetectorSource: "package_indicator", Score: 80, SelfHosted: true},
	{Needle: "weaviate", ServiceType: "vector_store", DetectorSource: "technology_indicator", Score: 92, SelfHosted: true},
	{Needle: "chroma", ServiceType: "vector_store", DetectorSource: "technology_indicator", Score: 88, SelfHosted: true},
	{Needle: "chromadb", ServiceType: "vector_store", DetectorSource: "technology_indicator", Score: 88, SelfHosted: true},
	{Needle: "pinecone", ServiceType: "vector_store", DetectorSource: "technology_indicator", Score: 92, SelfHosted: true},
	{Needle: "pgvector", ServiceType: "vector_store", DetectorSource: "technology_indicator", Score: 90, SelfHosted: true},
	{Needle: "qdrant", ServiceType: "vector_store", DetectorSource: "technology_indicator", Score: 90, SelfHosted: true},
	{Needle: "milvus", ServiceType: "vector_store", DetectorSource: "technology_indicator", Score: 90, SelfHosted: true},
	{Needle: "faiss", ServiceType: "vector_store", DetectorSource: "technology_indicator", Score: 84, SelfHosted: true},
}

var aiProviderKeyNeedles = []string{
	"openai api key",
	"anthropic api key",
	"cohere api key",
	"azure openai api key",
}

// BuildAIWorkloadInventoryReport detects AI workloads from the existing graph and
// scores their posture using graph-native access and exposure signals.
func BuildAIWorkloadInventoryReport(g *Graph, opts AIWorkloadInventoryReportOptions) AIWorkloadInventoryReport {
	now := opts.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	maxWorkloads := opts.MaxWorkloads
	if maxWorkloads <= 0 {
		maxWorkloads = defaultAIWorkloadMaxResults
	}
	if maxWorkloads > 200 {
		maxWorkloads = 200
	}
	minRiskScore := opts.MinRiskScore
	if minRiskScore < 0 {
		minRiskScore = 0
	}
	if minRiskScore > 100 {
		minRiskScore = 100
	}

	report := AIWorkloadInventoryReport{GeneratedAt: now}
	if g == nil {
		report.Recommendations = []AIWorkloadRecommendation{{
			Priority:        "high",
			Category:        "graph_unavailable",
			Title:           "Graph platform is not initialized",
			Detail:          "No AI workload inventory is available because the graph is nil.",
			SuggestedAction: "Initialize and populate the graph before requesting AI workload posture insights.",
		}}
		return report
	}

	internetFacing := make(map[string]struct{})
	for _, node := range g.GetInternetFacingNodes() {
		if node == nil {
			continue
		}
		internetFacing[node.ID] = struct{}{}
	}

	candidates := make(map[string]*aiWorkloadAccumulator)
	for _, node := range g.GetAllNodes() {
		signal := aiAnalyzeNodeSignals(node)
		if !signal.present() {
			continue
		}
		targetIDs := aiPromotionTargetIDs(g, node)
		for _, targetID := range targetIDs {
			target, ok := g.GetNode(targetID)
			if !ok || target == nil || target.DeletedAt != nil || !aiWorkloadCandidateKind(target.Kind) {
				continue
			}
			acc := candidates[targetID]
			if acc == nil {
				acc = &aiWorkloadAccumulator{
					Node:                  target,
					ServiceTypeScores:     make(map[string]int),
					DetectorSources:       make(map[string]struct{}),
					Indicators:            make(map[string]struct{}),
					ProviderKeys:          make(map[string]struct{}),
					DataStoreKinds:        make(map[string]struct{}),
					SensitiveDataStoreIDs: make(map[string]struct{}),
					AdminIdentityIDs:      make(map[string]struct{}),
				}
				candidates[targetID] = acc
			}
			acc.merge(signal)
		}
	}

	allRecords := make([]AIWorkloadRecord, 0, len(candidates))
	for _, acc := range candidates {
		if acc == nil || acc.Node == nil {
			continue
		}
		record := aiFinalizeWorkloadRecord(g, acc, internetFacing)
		allRecords = append(allRecords, record)
	}
	sort.Slice(allRecords, func(i, j int) bool {
		if allRecords[i].RiskScore != allRecords[j].RiskScore {
			return allRecords[i].RiskScore > allRecords[j].RiskScore
		}
		if allRecords[i].Name != allRecords[j].Name {
			return allRecords[i].Name < allRecords[j].Name
		}
		return allRecords[i].NodeID < allRecords[j].NodeID
	})

	report.Summary = aiBuildSummary(allRecords)

	filtered := make([]AIWorkloadRecord, 0, len(allRecords))
	for _, record := range allRecords {
		if record.RiskScore < minRiskScore {
			continue
		}
		if !opts.IncludeShadow && record.ShadowAI {
			continue
		}
		filtered = append(filtered, record)
	}
	if len(filtered) > maxWorkloads {
		filtered = filtered[:maxWorkloads]
	}
	report.Workloads = filtered
	report.Summary.ReturnedWorkloadCount = len(filtered)

	report.DataExposures = aiBuildExposureSlice(filtered)
	report.ShadowAIWorkloads = aiBuildShadowSlice(filtered)
	report.Recommendations = aiBuildRecommendations(allRecords)
	return report
}

func (s aiNodeSignal) present() bool {
	return len(s.ServiceTypeScores) > 0 || len(s.ProviderKeys) > 0
}

func (acc *aiWorkloadAccumulator) merge(signal aiNodeSignal) {
	if acc == nil {
		return
	}
	for serviceType, score := range signal.ServiceTypeScores {
		if existing, ok := acc.ServiceTypeScores[serviceType]; !ok || score > existing {
			acc.ServiceTypeScores[serviceType] = score
		}
	}
	for source := range signal.DetectorSources {
		acc.DetectorSources[source] = struct{}{}
	}
	for indicator := range signal.Indicators {
		acc.Indicators[indicator] = struct{}{}
	}
	for key := range signal.ProviderKeys {
		acc.ProviderKeys[key] = struct{}{}
	}
	acc.CloudManaged = acc.CloudManaged || signal.CloudManaged
	acc.SelfHosted = acc.SelfHosted || signal.SelfHosted || len(signal.ProviderKeys) > 0
}

func aiBuildSummary(records []AIWorkloadRecord) AIWorkloadSummary {
	summary := AIWorkloadSummary{WorkloadCount: len(records)}
	for _, record := range records {
		switch record.RiskLevel {
		case RiskCritical, RiskHigh:
			summary.HighRiskWorkloadCount++
		}
		if record.InternetExposed {
			summary.InternetExposedWorkloadCount++
		}
		if record.ShadowAI {
			summary.ShadowAIWorkloadCount++
		}
		if record.SensitiveDataAccess {
			summary.SensitiveDataWorkloadCount++
		}
		if len(record.PlaintextProviderKeys) > 0 {
			summary.PlaintextKeyWorkloadCount++
		}
		switch record.DeploymentModel {
		case "cloud_managed":
			summary.CloudManagedWorkloadCount++
		case "self_hosted", "hybrid":
			summary.SelfHostedWorkloadCount++
		}
	}
	return summary
}

func aiBuildExposureSlice(records []AIWorkloadRecord) []AIWorkloadExposure {
	exposures := make([]AIWorkloadExposure, 0)
	for _, record := range records {
		if !record.InternetExposed && !record.SensitiveDataAccess && len(record.PlaintextProviderKeys) == 0 {
			continue
		}
		exposures = append(exposures, AIWorkloadExposure{
			WorkloadID:              record.NodeID,
			WorkloadName:            record.Name,
			AIServiceType:           record.AIServiceType,
			RiskLevel:               record.RiskLevel,
			RiskScore:               record.RiskScore,
			InternetExposed:         record.InternetExposed,
			SensitiveDataStoreCount: record.SensitiveDataStoreCount,
			SensitiveDataStoreIDs:   append([]string(nil), record.SensitiveDataStoreIDs...),
			PlaintextProviderKeys:   append([]string(nil), record.PlaintextProviderKeys...),
		})
	}
	return exposures
}

func aiBuildShadowSlice(records []AIWorkloadRecord) []AIWorkloadRecord {
	shadow := make([]AIWorkloadRecord, 0)
	for _, record := range records {
		if record.ShadowAI {
			shadow = append(shadow, record)
		}
	}
	return shadow
}

func aiBuildRecommendations(records []AIWorkloadRecord) []AIWorkloadRecommendation {
	summary := aiBuildSummary(records)
	recommendations := make([]AIWorkloadRecommendation, 0, 4)
	add := func(priority, category, title, detail, action string) {
		recommendations = append(recommendations, AIWorkloadRecommendation{
			Priority:        priority,
			Category:        category,
			Title:           title,
			Detail:          detail,
			SuggestedAction: strings.TrimSpace(action),
		})
	}

	if summary.WorkloadCount == 0 {
		add("low", "baseline", "No AI workloads detected", "Current graph data does not expose explicit cloud-managed or self-hosted AI indicators.", "Keep cloud syncs and workload scans enabled so AI-specific inventory remains current.")
		return recommendations
	}
	if summary.InternetExposedWorkloadCount > 0 {
		add("high", "internet_exposure", "Reduce internet exposure on AI endpoints", "One or more AI workloads are reachable from the internet, increasing prompt abuse and model endpoint exposure risk.", "Require authentication and private ingress for public AI endpoints before expanding external access.")
	}
	if summary.PlaintextKeyWorkloadCount > 0 {
		add("high", "plaintext_keys", "Move provider keys into managed secret storage", "AI provider credentials appear directly on workload metadata instead of being abstracted through secret storage.", "Migrate OpenAI/Anthropic/Cohere credentials into the platform secret manager and rotate the exposed keys.")
	}
	if summary.ShadowAIWorkloadCount > 0 {
		add("medium", "shadow_ai", "Review self-hosted and shadow AI deployments", "Self-hosted AI indicators were detected outside the explicit cloud-managed AI service footprint.", "Inventory unapproved Ollama/vLLM/vector-store workloads and attach owners, data boundaries, and policy controls.")
	}
	if summary.SensitiveDataWorkloadCount > 0 {
		add("medium", "data_scope", "Constrain AI data access", "Detected AI workloads have graph-visible reach into sensitive databases, buckets, or secrets.", "Scope AI workloads to least-privilege data stores and separate high-sensitivity training or retrieval paths.")
	}
	if len(recommendations) == 0 {
		add("low", "steady_state", "Maintain AI workload guardrails", "Detected AI workloads do not currently show the highest-risk posture combinations in graph data.", "Keep provider-key hygiene, exposure controls, and data-scope reviews in the AI deployment checklist.")
	}
	sort.SliceStable(recommendations, func(i, j int) bool {
		if aiRecommendationPriorityRank(recommendations[i].Priority) != aiRecommendationPriorityRank(recommendations[j].Priority) {
			return aiRecommendationPriorityRank(recommendations[i].Priority) > aiRecommendationPriorityRank(recommendations[j].Priority)
		}
		if recommendations[i].Category != recommendations[j].Category {
			return recommendations[i].Category < recommendations[j].Category
		}
		return recommendations[i].Title < recommendations[j].Title
	})
	return recommendations
}

func aiFinalizeWorkloadRecord(g *Graph, acc *aiWorkloadAccumulator, internetFacing map[string]struct{}) AIWorkloadRecord {
	node := acc.Node
	internetExposed := aiNodeInternetExposed(g, node, internetFacing)
	dataStoreKinds, sensitiveDataStoreIDs, adminIdentityIDs := aiCollectAdjacentSignals(g, node)
	for _, kind := range dataStoreKinds {
		acc.DataStoreKinds[kind] = struct{}{}
	}
	for _, id := range sensitiveDataStoreIDs {
		acc.SensitiveDataStoreIDs[id] = struct{}{}
	}
	for _, id := range adminIdentityIDs {
		acc.AdminIdentityIDs[id] = struct{}{}
	}

	shadowAI := acc.SelfHosted && !acc.CloudManaged
	deploymentModel := "self_hosted"
	switch {
	case acc.CloudManaged && acc.SelfHosted:
		deploymentModel = "hybrid"
	case acc.CloudManaged:
		deploymentModel = "cloud_managed"
	}
	serviceType := aiPrimaryServiceType(acc.ServiceTypeScores)

	record := AIWorkloadRecord{
		NodeID:                  node.ID,
		Name:                    strings.TrimSpace(node.Name),
		Kind:                    string(node.Kind),
		Provider:                strings.TrimSpace(node.Provider),
		DeploymentModel:         deploymentModel,
		AIServiceType:           serviceType,
		ShadowAI:                shadowAI,
		InternetExposed:         internetExposed,
		SensitiveDataAccess:     len(acc.SensitiveDataStoreIDs) > 0,
		DataStoreCount:          len(acc.DataStoreKinds),
		SensitiveDataStoreCount: len(acc.SensitiveDataStoreIDs),
		PlaintextProviderKeys:   sortedStringSet(acc.ProviderKeys),
		DataStoreKinds:          sortedStringSet(acc.DataStoreKinds),
		SensitiveDataStoreIDs:   sortedStringSet(acc.SensitiveDataStoreIDs),
		AdminIdentityIDs:        sortedStringSet(acc.AdminIdentityIDs),
		DetectorSources:         sortedStringSet(acc.DetectorSources),
		Indicators:              sortedStringSet(acc.Indicators),
	}
	record.RiskScore, record.RiskDrivers = aiRiskScore(record)
	record.RiskLevel = aiRiskLevel(record.RiskScore)
	return record
}

func aiAnalyzeNodeSignals(node *Node) aiNodeSignal {
	signal := aiNodeSignal{
		ServiceTypeScores: make(map[string]int),
		DetectorSources:   make(map[string]struct{}),
		Indicators:        make(map[string]struct{}),
		ProviderKeys:      make(map[string]struct{}),
	}
	if node == nil || node.DeletedAt != nil {
		return signal
	}

	text := aiNormalizedSearchText(node)
	keys := aiNormalizedNodeKeys(node)
	for _, spec := range aiIndicatorCatalog {
		if !aiContainsNeedle(text, keys, spec.Needle) {
			continue
		}
		signal.Indicators[spec.Needle] = struct{}{}
		signal.DetectorSources[spec.DetectorSource] = struct{}{}
		if existing, ok := signal.ServiceTypeScores[spec.ServiceType]; !ok || spec.Score > existing {
			signal.ServiceTypeScores[spec.ServiceType] = spec.Score
		}
		signal.CloudManaged = signal.CloudManaged || spec.CloudManaged
		signal.SelfHosted = signal.SelfHosted || spec.SelfHosted
	}
	for _, key := range keys {
		for _, needle := range aiProviderKeyNeedles {
			if !strings.Contains(key, needle) {
				continue
			}
			signal.ProviderKeys[needle] = struct{}{}
			signal.Indicators[needle] = struct{}{}
			signal.DetectorSources["credential_indicator"] = struct{}{}
			if existing, ok := signal.ServiceTypeScores["llm_application"]; !ok || 78 > existing {
				signal.ServiceTypeScores["llm_application"] = 78
			}
			signal.SelfHosted = true
		}
	}

	switch {
	case strings.Contains(text, " notebook"):
		aiUpdateScore(signal.ServiceTypeScores, "notebook", 82)
	case strings.Contains(text, " training"):
		aiUpdateScore(signal.ServiceTypeScores, "training", 82)
	case strings.Contains(text, " endpoint"), strings.Contains(text, " inference"), strings.Contains(text, " serving"):
		aiUpdateScore(signal.ServiceTypeScores, "serving", 80)
	}
	return signal
}

func aiUpdateScore(scores map[string]int, key string, score int) {
	if existing, ok := scores[key]; !ok || score > existing {
		scores[key] = score
	}
}

func aiPromotionTargetIDs(g *Graph, node *Node) []string {
	if node == nil {
		return nil
	}
	if aiWorkloadCandidateKind(node.Kind) {
		return []string{node.ID}
	}
	ids := make(map[string]struct{})
	for _, edge := range append(g.GetOutEdges(node.ID), g.GetInEdges(node.ID)...) {
		if edge == nil {
			continue
		}
		otherID := edge.Source
		if otherID == node.ID {
			otherID = edge.Target
		}
		other, ok := g.GetNode(otherID)
		if !ok || other == nil || other.DeletedAt != nil || !aiWorkloadCandidateKind(other.Kind) {
			continue
		}
		ids[other.ID] = struct{}{}
	}
	return sortedStringSet(ids)
}

func aiWorkloadCandidateKind(kind NodeKind) bool {
	switch kind {
	case NodeKindService, NodeKindWorkload, NodeKindApplication, NodeKindInstance, NodeKindFunction, NodeKindAPIEndpoint, NodeKindPod, NodeKindDeployment, NodeKindDatabase:
		return true
	default:
		return false
	}
}

func aiCollectAdjacentSignals(g *Graph, node *Node) ([]string, []string, []string) {
	dataStoreKinds := make(map[string]struct{})
	sensitiveDataStoreIDs := make(map[string]struct{})
	adminIdentityIDs := make(map[string]struct{})
	if g == nil || node == nil {
		return nil, nil, nil
	}
	for _, edge := range append(g.GetOutEdges(node.ID), g.GetInEdges(node.ID)...) {
		if edge == nil {
			continue
		}
		otherID := edge.Source
		if otherID == node.ID {
			otherID = edge.Target
		}
		other, ok := g.GetNode(otherID)
		if !ok || other == nil || other.DeletedAt != nil {
			continue
		}
		if aiDataStoreKind(other.Kind) {
			dataStoreKinds[string(other.Kind)] = struct{}{}
			if aiNodeLooksSensitive(other) {
				sensitiveDataStoreIDs[other.ID] = struct{}{}
			}
		}
		if aiAdminIdentity(other) {
			adminIdentityIDs[other.ID] = struct{}{}
		}
	}
	return sortedStringSet(dataStoreKinds), sortedStringSet(sensitiveDataStoreIDs), sortedStringSet(adminIdentityIDs)
}

func aiNodeInternetExposed(g *Graph, node *Node, internetFacing map[string]struct{}) bool {
	if node == nil {
		return false
	}
	if _, ok := internetFacing[node.ID]; ok {
		return true
	}
	for _, key := range []string{"internet_exposed", "public_access", "publicly_accessible", "internet_accessible", "public_endpoint", "public"} {
		if aiPropertyBool(node.Properties, key) {
			return true
		}
	}
	for _, edge := range g.GetInEdges(node.ID) {
		if edge == nil || edge.Kind != EdgeKindExposedTo {
			continue
		}
		if edge.Source == "internet" || edge.Source == string(NodeKindInternet) {
			return true
		}
	}
	return false
}

func aiDataStoreKind(kind NodeKind) bool {
	switch kind {
	case NodeKindDatabase, NodeKindBucket, NodeKindSecret:
		return true
	default:
		return false
	}
}

func aiNodeLooksSensitive(node *Node) bool {
	if node == nil {
		return false
	}
	if node.Kind == NodeKindSecret {
		return true
	}
	if aiPropertyBool(node.Properties, "contains_sensitive_data") || aiPropertyBool(node.Properties, "sensitive") {
		return true
	}
	for _, key := range []string{"data_classification", "classification", "sensitivity", "sensitivity_level", "information_type"} {
		value := strings.ToLower(node.PropertyString(key))
		switch value {
		case "sensitive", "confidential", "restricted", "pii", "phi", "pci", "secret", "high":
			return true
		}
	}
	return false
}

func aiAdminIdentity(node *Node) bool {
	if node == nil {
		return false
	}
	switch node.Kind {
	case NodeKindRole, NodeKindServiceAccount:
	default:
		return false
	}
	text := aiNormalizedSearchText(node)
	return strings.Contains(text, " admin") || strings.Contains(text, " administrator") || strings.Contains(text, " cluster admin") || strings.Contains(text, " root")
}

func aiRiskScore(record AIWorkloadRecord) (int, []AIWorkloadRiskDriver) {
	score := 0
	drivers := make([]AIWorkloadRiskDriver, 0, 6)
	add := func(value int, driver AIWorkloadRiskDriver) {
		score += value
		drivers = append(drivers, driver)
	}

	if record.InternetExposed {
		add(30, AIWorkloadRiskDriver{Type: "internet_exposure", Severity: SeverityHigh, Summary: "AI workload is reachable from the internet.", Value: 1})
	}
	if record.SensitiveDataAccess {
		value := 20
		severity := SeverityHigh
		if record.SensitiveDataStoreCount >= 3 {
			value = 25
			severity = SeverityCritical
		}
		add(value, AIWorkloadRiskDriver{Type: "sensitive_data_access", Severity: severity, Summary: "AI workload has graph-visible reach into sensitive data stores.", Value: record.SensitiveDataStoreCount})
	}
	if len(record.PlaintextProviderKeys) > 0 {
		add(25, AIWorkloadRiskDriver{Type: "plaintext_provider_keys", Severity: SeverityCritical, Summary: "AI provider credentials appear directly on workload metadata.", Value: len(record.PlaintextProviderKeys)})
	}
	if len(record.AdminIdentityIDs) > 0 {
		add(15, AIWorkloadRiskDriver{Type: "admin_identity", Severity: SeverityHigh, Summary: "AI workload is adjacent to an administrative runtime identity.", Value: len(record.AdminIdentityIDs)})
	}
	if record.ShadowAI {
		add(12, AIWorkloadRiskDriver{Type: "shadow_ai", Severity: SeverityMedium, Summary: "Self-hosted AI indicators were detected outside the cloud-managed AI footprint.", Value: 1})
	}
	if record.DataStoreCount >= 2 {
		add(8, AIWorkloadRiskDriver{Type: "broad_data_scope", Severity: SeverityMedium, Summary: "AI workload touches multiple storage classes or data stores.", Value: record.DataStoreCount})
	}
	if record.DeploymentModel == "hybrid" {
		add(5, AIWorkloadRiskDriver{Type: "hybrid_surface", Severity: SeverityLow, Summary: "Both cloud-managed and self-hosted AI indicators were detected.", Value: 1})
	}
	if score > 100 {
		score = 100
	}
	sort.SliceStable(drivers, func(i, j int) bool {
		if aiSeverityRank(drivers[i].Severity) != aiSeverityRank(drivers[j].Severity) {
			return aiSeverityRank(drivers[i].Severity) > aiSeverityRank(drivers[j].Severity)
		}
		if drivers[i].Type != drivers[j].Type {
			return drivers[i].Type < drivers[j].Type
		}
		return drivers[i].Summary < drivers[j].Summary
	})
	return score, drivers
}

func aiRiskLevel(score int) RiskLevel {
	switch {
	case score >= 80:
		return RiskCritical
	case score >= 60:
		return RiskHigh
	case score >= 30:
		return RiskMedium
	case score > 0:
		return RiskLow
	default:
		return RiskNone
	}
}

func aiPrimaryServiceType(scores map[string]int) string {
	bestType := ""
	bestScore := -1
	for serviceType, score := range scores {
		if score > bestScore || (score == bestScore && serviceType < bestType) {
			bestType = serviceType
			bestScore = score
		}
	}
	if bestType == "" {
		return "llm_application"
	}
	return bestType
}

func aiRecommendationPriorityRank(priority string) int {
	switch strings.ToLower(strings.TrimSpace(priority)) {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func aiSeverityRank(severity Severity) int {
	switch severity {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

func aiContainsNeedle(text string, keys []string, needle string) bool {
	normalizedNeedle := normalizeAISearchToken(needle)
	if normalizedNeedle == "" {
		return false
	}
	if strings.Contains(text, normalizedNeedle) {
		return true
	}
	for _, key := range keys {
		if strings.Contains(key, normalizedNeedle) {
			return true
		}
	}
	return false
}

func aiNormalizedSearchText(node *Node) string {
	if node == nil {
		return ""
	}
	parts := []string{node.ID, node.Name, node.Provider, node.Account, node.Region, string(node.Kind)}
	for key, value := range node.Properties {
		parts = append(parts, key)
		parts = append(parts, aiFlattenTextValue(value)...)
	}
	for key, value := range node.Tags {
		parts = append(parts, key, value)
	}
	return normalizeAISearchToken(strings.Join(parts, " "))
}

func aiNormalizedNodeKeys(node *Node) []string {
	keys := make([]string, 0, len(node.Properties)+len(node.Tags))
	for key := range node.Properties {
		keys = append(keys, normalizeAISearchToken(key))
	}
	for key := range node.Tags {
		keys = append(keys, normalizeAISearchToken(key))
	}
	sort.Strings(keys)
	return keys
}

func normalizeAISearchToken(value string) string {
	if strings.TrimSpace(value) == "" {
		return ""
	}
	var b strings.Builder
	lastSpace := true
	for _, r := range strings.ToLower(value) {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
			lastSpace = false
		case r >= '0' && r <= '9':
			b.WriteRune(r)
			lastSpace = false
		default:
			if !lastSpace {
				b.WriteByte(' ')
				lastSpace = true
			}
		}
	}
	return " " + strings.TrimSpace(b.String()) + " "
}

func aiFlattenTextValue(value any) []string {
	switch typed := value.(type) {
	case nil:
		return nil
	case string:
		return []string{typed}
	case []string:
		return append([]string(nil), typed...)
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			out = append(out, aiFlattenTextValue(item)...)
		}
		return out
	case map[string]any:
		out := make([]string, 0, len(typed)*2)
		for key, item := range typed {
			out = append(out, key)
			out = append(out, aiFlattenTextValue(item)...)
		}
		return out
	default:
		return nil
	}
}

func aiPropertyBool(properties map[string]any, key string) bool {
	if len(properties) == 0 {
		return false
	}
	value, ok := properties[key]
	if !ok {
		return false
	}
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		switch strings.ToLower(strings.TrimSpace(typed)) {
		case "true", "yes", "on", "enabled", "public", "internet":
			return true
		}
	}
	return false
}

func sortedStringSet(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
