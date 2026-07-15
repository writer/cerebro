// Package grammarproof compiles the declared connector grammar through
// sourcegen. Each advertised feature gets a minimal witness definition; a
// feature is proven only when classification accepts the witness and sourcegen
// can render its complete output plan.
package grammarproof

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/writer/cerebro/internal/connectordefinitions"
	"github.com/writer/cerebro/internal/sourcegen"
)

const (
	ProofStatusPassed = "passed"
	ProofStatusFailed = "failed"
)

// Report records whether every feature declared by a grammar has an executable
// sourcegen witness.
type Report struct {
	GrammarVersion     string             `json:"grammar_version"`
	DeclaredFeatures   int                `json:"declared_features"`
	ProvenFeatures     int                `json:"proven_features"`
	FailedFeatures     int                `json:"failed_features"`
	PairwiseWitnesses  int                `json:"pairwise_witnesses"`
	ProvenInteractions int                `json:"proven_interactions"`
	FailedInteractions int                `json:"failed_interactions"`
	Proofs             []FeatureProof     `json:"proofs"`
	InteractionProofs  []InteractionProof `json:"interaction_proofs"`
}

// FeatureProof is one executable witness for a declared grammar feature.
type FeatureProof struct {
	FeatureID       string `json:"feature_id"`
	Category        string `json:"category"`
	Value           string `json:"value"`
	WitnessSourceID string `json:"witness_source_id"`
	Status          string `json:"status"`
	Error           string `json:"error,omitempty"`
}

// InteractionProof is one generated connector selected by the deterministic
// pairwise covering plan.
type InteractionProof struct {
	WitnessSourceID string            `json:"witness_source_id"`
	Features        map[string]string `json:"features"`
	Status          string            `json:"status"`
	Error           string            `json:"error,omitempty"`
}

type witness struct {
	category string
	value    string
}

// Prove renders one minimal connector for every declared grammar feature.
func Prove(outputRoot string, grammar connectordefinitions.Grammar) (Report, error) {
	if strings.TrimSpace(outputRoot) == "" {
		return Report{}, fmt.Errorf("grammar proof output root is required")
	}
	if strings.TrimSpace(grammar.Version) == "" {
		grammar = connectordefinitions.DefaultGrammar()
	}
	witnesses := grammarWitnesses(grammar)
	report := Report{GrammarVersion: grammar.Version, DeclaredFeatures: len(witnesses)}
	for _, item := range witnesses {
		proof := proveWitness(outputRoot, grammar, item)
		report.Proofs = append(report.Proofs, proof)
		if proof.Status == ProofStatusPassed {
			report.ProvenFeatures++
		} else {
			report.FailedFeatures++
		}
	}
	combinations := pairwiseCombinations(grammar)
	report.PairwiseWitnesses = len(combinations)
	for index, combination := range combinations {
		proof := proveInteraction(outputRoot, grammar, index, combination)
		report.InteractionProofs = append(report.InteractionProofs, proof)
		if proof.Status == ProofStatusPassed {
			report.ProvenInteractions++
		} else {
			report.FailedInteractions++
		}
	}
	return report, nil
}

func grammarWitnesses(grammar connectordefinitions.Grammar) []witness {
	values := map[string][]string{
		"auth":        grammar.AuthModels,
		"incremental": grammar.IncrementalStates,
		"method":      grammar.Methods,
		"pagination":  grammar.PaginationTypes,
		"projection":  grammar.ProjectionTemplates,
		"runtime":     grammar.Runtimes,
	}
	categories := make([]string, 0, len(values))
	for category := range values {
		categories = append(categories, category)
	}
	sort.Strings(categories)
	witnesses := make([]witness, 0)
	for _, category := range categories {
		seen := map[string]struct{}{}
		for _, raw := range values[category] {
			value := strings.TrimSpace(raw)
			if value == "" {
				continue
			}
			if _, exists := seen[value]; exists {
				continue
			}
			seen[value] = struct{}{}
			witnesses = append(witnesses, witness{category: category, value: value})
		}
	}
	return witnesses
}

type grammarAxis struct {
	name   string
	values []string
}

func pairwiseCombinations(grammar connectordefinitions.Grammar) []map[string]string {
	axes := []grammarAxis{
		{name: "auth", values: uniqueValues(grammar.AuthModels)},
		{name: "incremental", values: uniqueValues(append([]string{"none"}, grammar.IncrementalStates...))},
		{name: "method", values: uniqueValues(grammar.Methods)},
		{name: "pagination", values: uniqueValues(grammar.PaginationTypes)},
		{name: "projection", values: uniqueValues(grammar.ProjectionTemplates)},
		{name: "runtime", values: uniqueValues(grammar.Runtimes)},
	}
	candidates := cartesianCombinations(axes)
	uncovered := map[string]struct{}{}
	for _, candidate := range candidates {
		for _, key := range interactionKeys(axes, candidate) {
			uncovered[key] = struct{}{}
		}
	}
	selected := make([]map[string]string, 0)
	for len(uncovered) > 0 {
		bestIndex := -1
		bestScore := 0
		for index, candidate := range candidates {
			score := 0
			for _, key := range interactionKeys(axes, candidate) {
				if _, exists := uncovered[key]; exists {
					score++
				}
			}
			if score > bestScore {
				bestIndex = index
				bestScore = score
			}
		}
		if bestIndex < 0 {
			break
		}
		best := candidates[bestIndex]
		selected = append(selected, cloneFeatures(best))
		for _, key := range interactionKeys(axes, best) {
			delete(uncovered, key)
		}
	}
	return selected
}

func cartesianCombinations(axes []grammarAxis) []map[string]string {
	combinations := []map[string]string{{}}
	for _, axis := range axes {
		if len(axis.values) == 0 {
			continue
		}
		next := make([]map[string]string, 0, len(combinations)*len(axis.values))
		for _, combination := range combinations {
			for _, value := range axis.values {
				candidate := cloneFeatures(combination)
				candidate[axis.name] = value
				next = append(next, candidate)
			}
		}
		combinations = next
	}
	return combinations
}

func interactionKeys(axes []grammarAxis, combination map[string]string) []string {
	keys := make([]string, 0, len(axes)*(len(axes)-1)/2)
	for left := 0; left < len(axes); left++ {
		leftValue := combination[axes[left].name]
		if leftValue == "" {
			continue
		}
		for right := left + 1; right < len(axes); right++ {
			rightValue := combination[axes[right].name]
			if rightValue == "" {
				continue
			}
			keys = append(keys, axes[left].name+"\x00"+leftValue+"\x00"+axes[right].name+"\x00"+rightValue)
		}
	}
	return keys
}

func uniqueValues(values []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func cloneFeatures(values map[string]string) map[string]string {
	cloned := make(map[string]string, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}

func proveWitness(outputRoot string, grammar connectordefinitions.Grammar, item witness) FeatureProof {
	featureID := item.category + "." + item.value
	sourceID := "proof_" + sanitizeID(item.category) + "_" + sanitizeID(item.value)
	proof := FeatureProof{
		FeatureID:       featureID,
		Category:        item.category,
		Value:           item.value,
		WitnessSourceID: sourceID,
		Status:          ProofStatusFailed,
	}
	definition := witnessDefinition(sourceID, map[string]string{item.category: item.value})
	report, err := connectordefinitions.Classify(definition, grammar)
	if err != nil {
		proof.Error = "classify witness: " + err.Error()
		return proof
	}
	if report.Verdict != connectordefinitions.SupportVerdictSupported {
		proof.Error = "classifier rejected witness: " + strings.Join(report.MissingFeatures, ", ")
		return proof
	}
	if !contains(report.SupportedFeatures, featureID) {
		proof.Error = "classifier did not record the declared feature"
		return proof
	}
	_, err = sourcegen.GenerateDefinition(sourcegen.DefinitionRequest{
		Definition: definition,
		OutputDir:  filepath.Join(outputRoot, sourceID),
		DryRun:     true,
	})
	if err != nil {
		proof.Error = "render witness: " + err.Error()
		return proof
	}
	proof.Status = ProofStatusPassed
	return proof
}

func proveInteraction(outputRoot string, grammar connectordefinitions.Grammar, index int, features map[string]string) InteractionProof {
	sourceID := fmt.Sprintf("proof_pair_%03d", index+1)
	proof := InteractionProof{WitnessSourceID: sourceID, Features: features, Status: ProofStatusFailed}
	definition := witnessDefinition(sourceID, features)
	report, err := connectordefinitions.Classify(definition, grammar)
	if err != nil {
		proof.Error = "classify witness: " + err.Error()
		return proof
	}
	if report.Verdict != connectordefinitions.SupportVerdictSupported {
		proof.Error = "classifier rejected witness: " + strings.Join(report.MissingFeatures, ", ")
		return proof
	}
	_, err = sourcegen.GenerateDefinition(sourcegen.DefinitionRequest{
		Definition: definition,
		OutputDir:  filepath.Join(outputRoot, sourceID),
		DryRun:     true,
	})
	if err != nil {
		proof.Error = "render witness: " + err.Error()
		return proof
	}
	proof.Status = ProofStatusPassed
	return proof
}

func witnessDefinition(sourceID string, features map[string]string) connectordefinitions.Definition {
	auth := witnessAuth(sourcegen.AuthModelBearerToken)
	method := "GET"
	var pagination *connectordefinitions.PaginationSpec
	projection := "asset"
	runtime := connectordefinitions.RuntimeJSONAPI
	var incremental *connectordefinitions.IncrementalSpec

	if value := features["auth"]; value != "" {
		auth = witnessAuth(value)
	}
	if value := features["incremental"]; value != "" && value != "none" {
		incremental = witnessIncremental(value)
	}
	if value := features["method"]; value != "" {
		method = value
	}
	if value := features["pagination"]; value != "" {
		pagination = witnessPagination(value)
	}
	if value := features["projection"]; value != "" {
		projection = value
	}
	if value := features["runtime"]; value != "" {
		runtime = value
	}

	return connectordefinitions.Definition{
		ID:          "builtin-" + sourceID,
		TenantID:    "builtin",
		SourceID:    sourceID,
		DisplayName: "Grammar proof " + sourceID,
		Runtime:     runtime,
		Auth:        auth,
		Transport: &connectordefinitions.TransportSpec{
			BaseURL:      "https://api.example.test",
			Verification: &connectordefinitions.VerificationSpec{Path: "/health"},
		},
		ResourceFamilies: []connectordefinitions.ResourceFamily{{
			ID:             "resources",
			Path:           "/v1/resources",
			Method:         method,
			RecordSelector: "$.data[*]",
			IDField:        "id",
			NameField:      "name",
			Pagination:     pagination,
			Incremental:    incremental,
			Event: connectordefinitions.EventMappingSpec{
				Kind:      sourceID + ".resources",
				SchemaRef: sourceID + "/resources/v1",
			},
			Projection: &connectordefinitions.ProjectionSpec{Template: projection},
			Coverage: []connectordefinitions.CoverageDimensionSpec{{
				ID:             "resources",
				Type:           "entity_family",
				Title:          "Resources",
				Families:       []string{"resources"},
				Support:        "supported",
				HighValue:      true,
				EvidenceTypes:  []string{"asset_inventory"},
				ControlDomains: []string{"asset_inventory"},
				ControlRefs: []connectordefinitions.CoverageControlRefSpec{{
					FrameworkName: "SOC 2",
					ControlID:     "CC7.2",
				}},
			}},
		}},
	}
}

func witnessAuth(model string) connectordefinitions.AuthSpec {
	auth := connectordefinitions.AuthSpec{Model: model}
	field := func(key string, secret bool) connectordefinitions.Field {
		return connectordefinitions.Field{Key: key, Secret: secret, ReferenceOnly: true}
	}
	switch model {
	case sourcegen.AuthModelNone:
	case sourcegen.AuthModelBearerToken, sourcegen.AuthModelAPIKey:
		auth.CredentialFields = []connectordefinitions.Field{field("token", true)}
	case sourcegen.AuthModelBasic:
		auth.CredentialFields = []connectordefinitions.Field{field("username", false), field("password", true)}
	case sourcegen.AuthModelOAuthAuthorizationCode:
		auth.AuthorizationURL = "https://auth.example.test/authorize"
		auth.TokenURL = "https://auth.example.test/token"
		auth.CredentialFields = []connectordefinitions.Field{field("token", true), field("refresh_token", true)}
	case sourcegen.AuthModelOAuthClientCredentials:
		auth.TokenURL = "https://auth.example.test/token"
		auth.CredentialFields = []connectordefinitions.Field{field("client_id", false), field("client_secret", true)}
	case sourcegen.AuthModelTwoStep:
		auth.TokenURL = "https://auth.example.test/token"
		auth.CredentialFields = []connectordefinitions.Field{field("api_key", true), field("client_secret", true)}
	case sourcegen.AuthModelJWT:
		auth.CredentialFields = []connectordefinitions.Field{field("private_key", true)}
	case sourcegen.AuthModelSignature:
		auth.CredentialFields = []connectordefinitions.Field{field("client_id", false), field("client_secret", true)}
	case sourcegen.AuthModelAWSSigV4:
		auth.CredentialFields = []connectordefinitions.Field{field("access_key", false), field("secret_key", true)}
	case sourcegen.AuthModelDuoHMAC, sourcegen.AuthModelDuoHMACV5:
		auth.CredentialFields = []connectordefinitions.Field{field("client_id", false), field("client_secret", true)}
	}
	return auth
}

func witnessPagination(kind string) *connectordefinitions.PaginationSpec {
	switch kind {
	case "none":
		return nil
	case "cursor":
		return &connectordefinitions.PaginationSpec{Type: kind, CursorParam: "after", CursorJSONPath: "$.paging.next"}
	case "page":
		return &connectordefinitions.PaginationSpec{Type: kind, PageParam: "page", PageSizeParam: "per_page", StartPage: 1}
	case "offset":
		return &connectordefinitions.PaginationSpec{Type: kind, OffsetParam: "offset", LimitParam: "limit", PageSize: 100}
	case "link":
		return &connectordefinitions.PaginationSpec{Type: kind, LinkHeader: "Link"}
	case "next_url":
		return &connectordefinitions.PaginationSpec{Type: kind, NextURLJSONPath: "$.paging.next"}
	default:
		return &connectordefinitions.PaginationSpec{Type: kind}
	}
}

func witnessIncremental(state string) *connectordefinitions.IncrementalSpec {
	return &connectordefinitions.IncrementalSpec{
		State:       state,
		CursorField: "updated_at",
		RequestKey:  "updated_since",
		RequestIn:   "query",
	}
}

func sanitizeID(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var b strings.Builder
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return strings.Trim(b.String(), "_")
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
