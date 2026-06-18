package connectordefinitions

import (
	"fmt"
	"sort"
	"strings"
)

const (
	SupportVerdictSupported         = "supported"
	SupportVerdictExtensionRequired = "extension_required"
	SupportVerdictBespokeRequired   = "bespoke_required"

	SupportStatusReady   = "ready"
	SupportStatusMissing = "missing"
)

// Grammar describes the bounded integration language that the generic engine
// can prove. Add features here before claiming a broad integration wave.
type Grammar struct {
	Version             string
	Runtimes            []string
	AuthModels          []string
	Methods             []string
	PaginationTypes     []string
	IncrementalStates   []string
	ProjectionTemplates []string
}

// SupportReport is a machine-readable proof that a definition is expressible,
// or a precise list of the generic features it still needs.
type SupportReport struct {
	DefinitionID      string           `json:"definition_id"`
	SourceID          string           `json:"source_id"`
	GrammarVersion    string           `json:"grammar_version"`
	Verdict           string           `json:"verdict"`
	SupportedFeatures []string         `json:"supported_features,omitempty"`
	MissingFeatures   []string         `json:"missing_features,omitempty"`
	Checks            []SupportCheck   `json:"checks"`
	Validation        ValidationResult `json:"validation"`
}

// SupportSummary aggregates classifier output for an integration target set.
type SupportSummary struct {
	GrammarVersion    string          `json:"grammar_version"`
	Targets           int             `json:"targets"`
	Supported         int             `json:"supported"`
	ExtensionRequired int             `json:"extension_required"`
	BespokeRequired   int             `json:"bespoke_required"`
	ByVerdict         map[string]int  `json:"by_verdict"`
	ByAuthModel       map[string]int  `json:"by_auth_model"`
	MissingFeatures   map[string]int  `json:"missing_features,omitempty"`
	Reports           []SupportReport `json:"reports"`
}

// SupportCheck is one classifier proof obligation.
type SupportCheck struct {
	ID       string `json:"id"`
	Category string `json:"category"`
	Status   string `json:"status"`
	Detail   string `json:"detail,omitempty"`
}

// DefaultGrammar returns the first broad generic engine target. The coverage is
// intentionally explicit: unsupported providers should fail classification with
// actionable missing-feature identifiers.
func DefaultGrammar() Grammar {
	return Grammar{
		Version: "cerebro.integration/v1",
		Runtimes: []string{
			RuntimeJSONAPI,
		},
		AuthModels: []string{
			"none",
			"api_key",
			"bearer_token",
			"basic",
			"oauth_authorization_code",
			"oauth_client_credentials",
			"two_step",
			"jwt",
			"signature",
			"aws_sigv4",
		},
		Methods: []string{
			"GET",
			"POST",
		},
		PaginationTypes: []string{
			"none",
			"cursor",
			"page",
			"offset",
			"link",
			"next_url",
		},
		IncrementalStates: []string{
			"high_watermark",
			"opaque_cursor",
		},
		ProjectionTemplates: []string{
			"app_entitlement",
			"asset",
			"audit_event",
			"cloud_resource",
			"endpoint_device",
			"finding",
			"group_membership",
			"identity_group",
			"identity_user",
			"repository",
			"vulnerability",
		},
	}
}

// Classify evaluates whether a definition fits the provided generic engine grammar.
func Classify(definition Definition, grammar Grammar) (SupportReport, error) {
	if strings.TrimSpace(grammar.Version) == "" {
		grammar = DefaultGrammar()
	}
	normalized, err := Normalize(definition)
	if err != nil {
		return SupportReport{}, err
	}
	report := SupportReport{
		DefinitionID:   normalized.ID,
		SourceID:       normalized.SourceID,
		GrammarVersion: grammar.Version,
		Verdict:        SupportVerdictSupported,
		Validation:     normalized.Validation,
	}
	check := func(category string, feature string, supported bool, detail string) {
		id := category + "." + feature
		if supported {
			report.Checks = append(report.Checks, SupportCheck{ID: id, Category: category, Status: SupportStatusReady, Detail: detail})
			report.SupportedFeatures = append(report.SupportedFeatures, id)
			return
		}
		report.Checks = append(report.Checks, SupportCheck{ID: id, Category: category, Status: SupportStatusMissing, Detail: detail})
		report.MissingFeatures = append(report.MissingFeatures, id)
	}
	runtimes := setOf(grammar.Runtimes)
	authModels := setOf(grammar.AuthModels)
	methods := setOf(grammar.Methods)
	pagination := setOf(grammar.PaginationTypes)
	incremental := setOf(grammar.IncrementalStates)
	projectionTemplates := setOf(grammar.ProjectionTemplates)

	check("runtime", normalized.Runtime, contains(runtimes, normalized.Runtime), "runtime executor")
	check("auth", normalized.Auth.Model, contains(authModels, normalized.Auth.Model), "provider auth model")
	if normalized.Transport == nil || strings.TrimSpace(normalized.Transport.BaseURL) == "" {
		check("transport", "base_url_template", false, "transport base URL is required for generic execution proof")
	} else {
		check("transport", "base_url_template", true, "transport base URL is declared")
	}
	if normalized.Transport == nil || normalized.Transport.Verification == nil {
		check("transport", "verification", false, "connection verification endpoint is required for generic acceptance")
	} else {
		check("transport", "verification", true, "connection verification endpoint is declared")
	}

	for _, family := range normalized.ResourceFamilies {
		method := strings.ToUpper(strings.TrimSpace(family.Method))
		check("method", method, contains(methods, method), fmt.Sprintf("family %s", family.ID))
		pageType := "none"
		if family.Pagination != nil && strings.TrimSpace(family.Pagination.Type) != "" {
			pageType = strings.TrimSpace(family.Pagination.Type)
		}
		check("pagination", pageType, contains(pagination, pageType), fmt.Sprintf("family %s", family.ID))
		if family.Incremental != nil {
			state := strings.TrimSpace(family.Incremental.State)
			if state == "" {
				state = "high_watermark"
			}
			check("incremental", state, contains(incremental, state), fmt.Sprintf("family %s", family.ID))
		}
		if family.RecordSelector == "" && family.ListKey == "" {
			check("record_selector", "jsonpath_or_list_key", false, fmt.Sprintf("family %s needs record_selector or list_key", family.ID))
		} else {
			check("record_selector", "jsonpath_or_list_key", true, fmt.Sprintf("family %s", family.ID))
		}
		if family.Event.Kind == "" || family.Event.SchemaRef == "" {
			check("event_contract", "kind_schema_ref", false, fmt.Sprintf("family %s needs event kind and schema ref", family.ID))
		} else {
			check("event_contract", "kind_schema_ref", true, fmt.Sprintf("family %s", family.ID))
		}
		if family.Projection == nil || strings.TrimSpace(family.Projection.Template) == "" {
			check("projection", "template", false, fmt.Sprintf("family %s needs a projection template or bespoke projector", family.ID))
		} else {
			template := strings.TrimSpace(family.Projection.Template)
			check("projection", template, contains(projectionTemplates, template), fmt.Sprintf("family %s", family.ID))
		}
		if len(family.Coverage) == 0 {
			check("coverage", "dimensions", false, fmt.Sprintf("family %s needs coverage dimensions", family.ID))
		} else {
			check("coverage", "dimensions", true, fmt.Sprintf("family %s", family.ID))
		}
	}
	if normalized.Validation.Status == ValidationBlocked {
		report.MissingFeatures = append(report.MissingFeatures, "definition.validation_blocked")
		report.Checks = append(report.Checks, SupportCheck{ID: "definition.validation_blocked", Category: "definition", Status: SupportStatusMissing, Detail: normalized.Validation.Summary})
	}
	report.MissingFeatures = uniqueSorted(report.MissingFeatures)
	report.SupportedFeatures = uniqueSortedExcept(report.SupportedFeatures, report.MissingFeatures)
	sort.SliceStable(report.Checks, func(i int, j int) bool {
		if report.Checks[i].Status != report.Checks[j].Status {
			return report.Checks[i].Status == SupportStatusMissing
		}
		return report.Checks[i].ID < report.Checks[j].ID
	})
	switch {
	case len(report.MissingFeatures) == 0:
		report.Verdict = SupportVerdictSupported
	case onlyExtensionMissing(report.MissingFeatures):
		report.Verdict = SupportVerdictExtensionRequired
	default:
		report.Verdict = SupportVerdictBespokeRequired
	}
	return report, nil
}

// ClassifyAll evaluates a target set and returns both per-definition reports and
// aggregate coverage counts suitable for CI artifacts.
func ClassifyAll(definitions []Definition, grammar Grammar) (SupportSummary, error) {
	if strings.TrimSpace(grammar.Version) == "" {
		grammar = DefaultGrammar()
	}
	summary := SupportSummary{
		GrammarVersion:  grammar.Version,
		Targets:         len(definitions),
		ByVerdict:       map[string]int{},
		ByAuthModel:     map[string]int{},
		MissingFeatures: map[string]int{},
		Reports:         make([]SupportReport, 0, len(definitions)),
	}
	for index, definition := range definitions {
		report, err := Classify(definition, grammar)
		if err != nil {
			return SupportSummary{}, fmt.Errorf("classify definitions[%d]: %w", index, err)
		}
		summary.Reports = append(summary.Reports, report)
		summary.ByVerdict[report.Verdict]++
		normalized, err := Normalize(definition)
		if err != nil {
			return SupportSummary{}, fmt.Errorf("normalize definitions[%d]: %w", index, err)
		}
		summary.ByAuthModel[normalized.Auth.Model]++
		for _, missing := range report.MissingFeatures {
			summary.MissingFeatures[missing]++
		}
	}
	summary.Supported = summary.ByVerdict[SupportVerdictSupported]
	summary.ExtensionRequired = summary.ByVerdict[SupportVerdictExtensionRequired]
	summary.BespokeRequired = summary.ByVerdict[SupportVerdictBespokeRequired]
	if len(summary.MissingFeatures) == 0 {
		summary.MissingFeatures = nil
	}
	sort.SliceStable(summary.Reports, func(i int, j int) bool {
		if summary.Reports[i].Verdict != summary.Reports[j].Verdict {
			return summary.Reports[i].Verdict < summary.Reports[j].Verdict
		}
		return summary.Reports[i].SourceID < summary.Reports[j].SourceID
	})
	return summary, nil
}

func onlyExtensionMissing(features []string) bool {
	if len(features) == 0 {
		return false
	}
	for _, feature := range features {
		switch {
		case strings.HasPrefix(feature, "auth."),
			strings.HasPrefix(feature, "method."),
			strings.HasPrefix(feature, "pagination."),
			strings.HasPrefix(feature, "incremental."),
			strings.HasPrefix(feature, "projection."):
			continue
		default:
			return false
		}
	}
	return true
}

func setOf(values []string) map[string]struct{} {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		set[value] = struct{}{}
	}
	return set
}

func contains(set map[string]struct{}, value string) bool {
	_, ok := set[strings.TrimSpace(value)]
	return ok
}

func uniqueSorted(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func uniqueSortedExcept(values []string, excluded []string) []string {
	excludedSet := setOf(excluded)
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := excludedSet[value]; ok {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
