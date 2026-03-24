package nlq

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/graph"
)

var (
	// ErrMutationNotAllowed guards the NLQ layer against write-style requests.
	ErrMutationNotAllowed = errors.New("natural language queries are read-only")
	// ErrUnsupportedQuestion is returned when translation cannot produce a safe
	// bounded read-only plan.
	ErrUnsupportedQuestion = errors.New("unsupported natural language query")
)

type PlanKind string

const (
	PlanKindEntityQuery         PlanKind = "entity_query"
	PlanKindFindingsQuery       PlanKind = "findings_query"
	PlanKindEntityFindingsQuery PlanKind = "entity_findings_query"
	PlanKindReverseAccessQuery  PlanKind = "reverse_access_query"
	PlanKindGraphChangeDiff     PlanKind = "graph_change_diff_query"
)

// CompletionProvider is an optional structured-translation fallback.
type CompletionProvider interface {
	Complete(ctx context.Context, systemPrompt, userPrompt string) (string, error)
}

// Context carries enough prior state to support bounded follow-up filters.
type Context struct {
	PreviousPlan *Plan `json:"previous_plan,omitempty"`
}

type TranslateRequest struct {
	Question string   `json:"question"`
	Context  *Context `json:"context,omitempty"`
}

type Plan struct {
	Question       string               `json:"question"`
	Intent         string               `json:"intent"`
	Kind           PlanKind             `json:"kind"`
	TemplateID     string               `json:"template_id,omitempty"`
	ReadOnly       bool                 `json:"read_only"`
	Confidence     float64              `json:"confidence"`
	Reasoning      []string             `json:"reasoning,omitempty"`
	GeneratedQuery string               `json:"generated_query"`
	EntityQuery    *EntityQuery         `json:"entity_query,omitempty"`
	FindingsQuery  *FindingsQuery       `json:"findings_query,omitempty"`
	CompositeQuery *EntityFindingsQuery `json:"composite_query,omitempty"`
	ReverseAccess  *ReverseAccessQuery  `json:"reverse_access,omitempty"`
	ChangeQuery    *ChangeQuery         `json:"change_query,omitempty"`
}

type EntityQuery struct {
	Kinds        []graph.NodeKind           `json:"kinds,omitempty"`
	Categories   []graph.NodeKindCategory   `json:"categories,omitempty"`
	Capabilities []graph.NodeKindCapability `json:"capabilities,omitempty"`
	Provider     string                     `json:"provider,omitempty"`
	Account      string                     `json:"account,omitempty"`
	Region       string                     `json:"region,omitempty"`
	Risk         graph.RiskLevel            `json:"risk,omitempty"`
	Search       string                     `json:"search,omitempty"`
	HasFindings  *bool                      `json:"has_findings,omitempty"`
	Limit        int                        `json:"limit,omitempty"`
}

type FindingsQuery struct {
	Severity string `json:"severity,omitempty"`
	Status   string `json:"status,omitempty"`
	PolicyID string `json:"policy_id,omitempty"`
	Query    string `json:"query,omitempty"`
	Domain   string `json:"domain,omitempty"`
	Limit    int    `json:"limit,omitempty"`
}

type EntityFindingsQuery struct {
	Entities EntityQuery   `json:"entities"`
	Findings FindingsQuery `json:"findings"`
	JoinOn   string        `json:"join_on"`
}

type ReverseAccessQuery struct {
	Targets   EntityQuery `json:"targets"`
	MaxDepth  int         `json:"max_depth,omitempty"`
	AdminOnly bool        `json:"admin_only,omitempty"`
}

type ChangeQuery struct {
	Since time.Time `json:"since,omitempty"`
	Until time.Time `json:"until,omitempty"`
}

type Translator struct {
	Schema SchemaContext
	Model  CompletionProvider
	Now    func() time.Time
}

const (
	defaultNLQEntityLimit        = 25
	defaultNLQFindingsLimit      = 50
	maxNLQResultLimit            = 500
	defaultNLQReverseAccessDepth = 6
	maxNLQReverseAccessDepth     = 12
	maxLLMPlanConfidence         = 0.85
)

func NewTranslator(schema SchemaContext, model CompletionProvider) *Translator {
	if len(schema.NodeKinds) == 0 && len(schema.EdgeKinds) == 0 {
		schema = DefaultSchemaContext()
	}
	return &Translator{
		Schema: schema,
		Model:  model,
		Now: func() time.Time {
			return time.Now().UTC()
		},
	}
}

func (t *Translator) Translate(ctx context.Context, req TranslateRequest) (*Plan, error) {
	question := strings.TrimSpace(req.Question)
	if question == "" {
		return nil, fmt.Errorf("question is required")
	}
	if isMutationRequest(question) {
		return nil, ErrMutationNotAllowed
	}

	if plan, ok := t.translateFollowUp(question, req.Context); ok {
		if finalized, err := t.finalizePlan(plan); err == nil {
			return finalized, nil
		}
	}
	if plan, ok := t.translateDeterministic(question); ok {
		if finalized, err := t.finalizePlan(plan); err == nil {
			return finalized, nil
		}
	}
	if t != nil && t.Model != nil {
		if plan, err := t.translateWithModel(ctx, question, req.Context); err == nil && plan != nil {
			if finalized, finalizeErr := t.finalizePlan(*plan); finalizeErr == nil {
				return finalized, nil
			}
		}
	}

	fallback := t.fallbackEntityPlan(question)
	return t.finalizePlan(fallback)
}

func (t *Translator) finalizePlan(plan Plan) (*Plan, error) {
	plan.ReadOnly = true
	plan.Confidence = clampConfidence(plan.Confidence)
	if plan.Confidence == 0 {
		plan.Confidence = 0.5
	}
	normalizePlan(&plan)
	if err := t.validatePlan(plan); err != nil {
		return nil, err
	}
	if plan.GeneratedQuery == "" {
		plan.GeneratedQuery = generatedQuery(plan)
	}
	return &plan, nil
}

func (t *Translator) validatePlan(plan Plan) error {
	if !plan.ReadOnly {
		return ErrMutationNotAllowed
	}
	if err := validatePlanPayload(plan); err != nil {
		return err
	}

	for _, entityQuery := range []*EntityQuery{
		plan.EntityQuery,
		plan.queryEntities(),
		plan.queryReverseAccessTargets(),
	} {
		if entityQuery == nil {
			continue
		}
		for _, kind := range entityQuery.Kinds {
			if !t.Schema.hasNodeKind(kind) {
				return fmt.Errorf("unsupported node kind in plan: %s", kind)
			}
		}
	}
	return nil
}

func (p Plan) queryEntities() *EntityQuery {
	if p.CompositeQuery == nil {
		return nil
	}
	query := p.CompositeQuery.Entities
	return &query
}

func (p Plan) queryReverseAccessTargets() *EntityQuery {
	if p.ReverseAccess == nil {
		return nil
	}
	query := p.ReverseAccess.Targets
	return &query
}

func (t *Translator) translateDeterministic(question string) (Plan, bool) {
	normalized := normalizeQuestion(question)

	switch {
	case isGraphChangeQuestion(normalized):
		return t.translateGraphChange(question, normalized), true
	case isAdminAccessQuestion(normalized):
		return t.translateAdminAccess(question, normalized), true
	case isInternetFindingQuestion(normalized):
		return t.translateInternetFindings(question, normalized), true
	case isCriticalFindingQuestion(normalized):
		return t.translateCriticalFindings(question, normalized), true
	case isInternetExposureQuestion(normalized):
		return t.translateInternetExposure(question, normalized), true
	default:
		return Plan{}, false
	}
}

func (t *Translator) translateFollowUp(question string, ctx *Context) (Plan, bool) {
	if ctx == nil || ctx.PreviousPlan == nil {
		return Plan{}, false
	}
	normalized := normalizeQuestion(question)
	if !containsAny(normalized, "those", "them", "that list", "those resources", "those entities") {
		return Plan{}, false
	}

	plan := clonePlan(*ctx.PreviousPlan)
	changed := false

	provider := inferProvider(normalized)
	if provider != "" {
		for _, entityQuery := range mutableEntityQueries(&plan) {
			entityQuery.Provider = provider
			changed = true
		}
	}
	if containsAny(normalized, "production", "prod") {
		for _, entityQuery := range mutableEntityQueries(&plan) {
			entityQuery.Search = mergeSearchTerms(entityQuery.Search, "prod")
			changed = true
		}
	}
	if risk := inferRisk(normalized); risk != "" {
		for _, entityQuery := range mutableEntityQueries(&plan) {
			entityQuery.Risk = risk
			changed = true
		}
	}
	if severity := inferFollowUpSeverity(normalized); severity != "" {
		if plan.FindingsQuery != nil {
			plan.FindingsQuery.Severity = severity
			changed = true
		}
		if plan.CompositeQuery != nil {
			plan.CompositeQuery.Findings.Severity = severity
			changed = true
		}
	}
	if !changed {
		return Plan{}, false
	}

	plan.Question = strings.TrimSpace(question)
	plan.Intent = "follow_up_filter"
	plan.TemplateID = "follow_up_filter"
	plan.Confidence = 0.93
	plan.Reasoning = append([]string{}, "Applied bounded follow-up filters to the previous read-only plan.")
	return plan, true
}

func (t *Translator) translateGraphChange(question, normalized string) Plan {
	now := t.now()
	since := now.Add(-7 * 24 * time.Hour)
	switch {
	case containsAny(normalized, "today", "last 24 hours", "past day", "yesterday"):
		since = now.Add(-24 * time.Hour)
	case containsAny(normalized, "this month", "past month", "last month"):
		since = now.Add(-30 * 24 * time.Hour)
	case containsAny(normalized, "this week", "past week", "last week"):
		since = now.Add(-7 * 24 * time.Hour)
	}
	return Plan{
		Question:   question,
		Intent:     "graph_change_diff",
		Kind:       PlanKindGraphChangeDiff,
		TemplateID: "what-changed",
		ReadOnly:   true,
		Confidence: 0.95,
		Reasoning: []string{
			"Matched a temporal change question.",
			"Compiled to a bounded graph diff over the requested time window.",
		},
		ChangeQuery: &ChangeQuery{
			Since: since,
			Until: now,
		},
	}
}

func (t *Translator) translateAdminAccess(question, normalized string) Plan {
	targetPhrase := extractTargetPhrase(normalized)
	targetQuery := EntityQuery{
		Kinds:    inferKinds(targetPhrase),
		Provider: inferProvider(normalized),
		Search:   inferSearch(targetPhrase),
		Limit:    25,
	}
	if containsAny(targetPhrase, "production", "prod") {
		targetQuery.Search = mergeSearchTerms(targetQuery.Search, "prod")
	}
	if len(targetQuery.Kinds) == 0 {
		targetQuery.Categories = []graph.NodeKindCategory{graph.NodeCategoryResource}
	}

	return Plan{
		Question:   question,
		Intent:     "reverse_admin_access",
		Kind:       PlanKindReverseAccessQuery,
		TemplateID: "admin-access-to-target",
		ReadOnly:   true,
		Confidence: 0.94,
		Reasoning: []string{
			"Matched an admin access question.",
			"Compiled to reverse access traversal scoped to target resources.",
		},
		ReverseAccess: &ReverseAccessQuery{
			Targets:   targetQuery,
			MaxDepth:  6,
			AdminOnly: true,
		},
	}
}

func (t *Translator) translateInternetFindings(question, normalized string) Plan {
	entityQuery := EntityQuery{
		Kinds:        filterOutKinds(inferKinds(normalized), graph.NodeKindVulnerability),
		Capabilities: []graph.NodeKindCapability{graph.NodeCapabilityInternetExposable},
		Provider:     inferProvider(normalized),
		Search:       inferSearch(normalized),
		Limit:        50,
	}
	if len(entityQuery.Kinds) == 0 {
		entityQuery.Categories = []graph.NodeKindCategory{graph.NodeCategoryResource}
	}

	findingsQuery := FindingsQuery{
		Severity: inferSeverity(normalized),
		Query:    inferFindingSearch(normalized),
		Limit:    100,
	}
	if findingsQuery.Severity == "" {
		findingsQuery.Severity = "critical"
	}

	return Plan{
		Question:   question,
		Intent:     "internet_exposure_findings",
		Kind:       PlanKindEntityFindingsQuery,
		TemplateID: "internet-facing-critical-vulns",
		ReadOnly:   true,
		Confidence: 0.97,
		Reasoning: []string{
			"Matched a question combining internet exposure with vulnerabilities/findings.",
			"Compiled to a resource query joined against filtered findings.",
		},
		CompositeQuery: &EntityFindingsQuery{
			Entities: entityQuery,
			Findings: findingsQuery,
			JoinOn:   "entity_or_resource_id",
		},
	}
}

func (t *Translator) translateCriticalFindings(question, normalized string) Plan {
	query := FindingsQuery{
		Severity: inferSeverity(normalized),
		Query:    inferFindingSearch(normalized),
		Limit:    100,
	}
	if query.Severity == "" {
		query.Severity = "critical"
	}
	return Plan{
		Question:   question,
		Intent:     "critical_findings",
		Kind:       PlanKindFindingsQuery,
		TemplateID: "critical-vulnerabilities",
		ReadOnly:   true,
		Confidence: 0.93,
		Reasoning: []string{
			"Matched a findings/vulnerability question.",
			"Compiled to a bounded findings query.",
		},
		FindingsQuery: &query,
	}
}

func (t *Translator) translateInternetExposure(question, normalized string) Plan {
	query := EntityQuery{
		Kinds:        filterOutKinds(inferKinds(normalized), graph.NodeKindVulnerability),
		Capabilities: []graph.NodeKindCapability{graph.NodeCapabilityInternetExposable},
		Provider:     inferProvider(normalized),
		Search:       inferSearch(normalized),
		Limit:        50,
	}
	if len(query.Kinds) == 0 {
		query.Categories = []graph.NodeKindCategory{graph.NodeCategoryResource}
	}
	return Plan{
		Question:   question,
		Intent:     "internet_exposure",
		Kind:       PlanKindEntityQuery,
		TemplateID: "internet-exposed-assets",
		ReadOnly:   true,
		Confidence: 0.92,
		Reasoning: []string{
			"Matched an internet exposure question.",
			"Compiled to an entity query over internet-exposable resources.",
		},
		EntityQuery: &query,
	}
}

func (t *Translator) fallbackEntityPlan(question string) Plan {
	normalized := normalizeQuestion(question)
	query := EntityQuery{
		Kinds:    inferKinds(normalized),
		Provider: inferProvider(normalized),
		Risk:     inferRisk(normalized),
		Search:   inferSearch(normalized),
		Limit:    25,
	}
	if len(query.Kinds) == 0 {
		query.Categories = []graph.NodeKindCategory{graph.NodeCategoryResource}
	}
	return Plan{
		Question:   question,
		Intent:     "entity_search",
		Kind:       PlanKindEntityQuery,
		TemplateID: "entity-search-fallback",
		ReadOnly:   true,
		Confidence: 0.51,
		Reasoning: []string{
			"Used the bounded entity-search fallback because no higher-confidence template matched.",
		},
		EntityQuery: &query,
	}
}

func (t *Translator) translateWithModel(ctx context.Context, question string, reqCtx *Context) (*Plan, error) {
	if t.Model == nil {
		return nil, ErrUnsupportedQuestion
	}

	userPrompt := "Question: " + strings.TrimSpace(question) + "\n"
	userPrompt += "Current time: " + t.now().Format(time.RFC3339) + "\n"
	if reqCtx != nil && reqCtx.PreviousPlan != nil {
		previous, _ := json.Marshal(reqCtx.PreviousPlan)
		userPrompt += "Previous plan: " + string(previous) + "\n"
	}
	userPrompt += "Return JSON matching the planner fields only."

	raw, err := t.Model.Complete(ctx, t.Schema.Prompt(), userPrompt)
	if err != nil {
		return nil, err
	}

	payload := strings.TrimSpace(raw)
	payload = strings.TrimPrefix(payload, "```json")
	payload = strings.TrimPrefix(payload, "```")
	payload = strings.TrimSuffix(payload, "```")
	payload = strings.TrimSpace(payload)

	var plan Plan
	if err := json.Unmarshal([]byte(payload), &plan); err != nil {
		return nil, err
	}
	if strings.TrimSpace(plan.Question) == "" {
		plan.Question = question
	}
	plan.Confidence = min(plan.Confidence, maxLLMPlanConfidence)
	return &plan, nil
}

func normalizePlan(plan *Plan) {
	if plan == nil {
		return
	}
	if plan.EntityQuery != nil {
		normalizeEntityQuery(plan.EntityQuery)
	}
	if plan.FindingsQuery != nil {
		normalizeFindingsQuery(plan.FindingsQuery)
	}
	if plan.CompositeQuery != nil {
		normalizeEntityQuery(&plan.CompositeQuery.Entities)
		normalizeFindingsQuery(&plan.CompositeQuery.Findings)
		if strings.TrimSpace(plan.CompositeQuery.JoinOn) == "" {
			plan.CompositeQuery.JoinOn = "entity_or_resource_id"
		}
	}
	if plan.ReverseAccess != nil {
		normalizeEntityQuery(&plan.ReverseAccess.Targets)
		plan.ReverseAccess.MaxDepth = clampInt(plan.ReverseAccess.MaxDepth, defaultNLQReverseAccessDepth, 1, maxNLQReverseAccessDepth)
	}
	if plan.ChangeQuery != nil {
		plan.ChangeQuery.Since = plan.ChangeQuery.Since.UTC()
		plan.ChangeQuery.Until = plan.ChangeQuery.Until.UTC()
	}
}

func normalizeEntityQuery(query *EntityQuery) {
	if query == nil {
		return
	}
	query.Provider = strings.ToLower(strings.TrimSpace(query.Provider))
	query.Account = strings.TrimSpace(query.Account)
	query.Region = strings.ToLower(strings.TrimSpace(query.Region))
	query.Search = strings.TrimSpace(query.Search)
	query.Limit = clampInt(query.Limit, defaultNLQEntityLimit, 1, maxNLQResultLimit)
	query.Kinds = uniqueNodeKinds(query.Kinds)
	query.Categories = uniqueNodeCategories(query.Categories)
	query.Capabilities = uniqueNodeCapabilities(query.Capabilities)
}

func normalizeFindingsQuery(query *FindingsQuery) {
	if query == nil {
		return
	}
	query.Severity = strings.ToLower(strings.TrimSpace(query.Severity))
	query.Status = strings.ToUpper(strings.TrimSpace(query.Status))
	query.PolicyID = strings.TrimSpace(query.PolicyID)
	query.Domain = strings.ToLower(strings.TrimSpace(query.Domain))
	query.Query = strings.TrimSpace(query.Query)
	query.Limit = clampInt(query.Limit, defaultNLQFindingsLimit, 1, maxNLQResultLimit)
}

func generatedEntityQuery(query *EntityQuery) string {
	if query == nil {
		return "entities(invalid)"
	}
	return fmt.Sprintf("entities(kinds=%s,categories=%s,capabilities=%s,provider=%q,risk=%q,search=%q,has_findings=%s,limit=%d)",
		formatNodeKinds(query.Kinds),
		formatNodeCategories(query.Categories),
		formatNodeCapabilities(query.Capabilities),
		query.Provider,
		query.Risk,
		query.Search,
		formatOptionalBool(query.HasFindings),
		query.Limit,
	)
}

func generatedFindingsQuery(query *FindingsQuery) string {
	if query == nil {
		return "findings(invalid)"
	}
	return fmt.Sprintf("findings(severity=%q,status=%q,policy_id=%q,domain=%q,query=%q,limit=%d)",
		query.Severity,
		query.Status,
		query.PolicyID,
		query.Domain,
		query.Query,
		query.Limit,
	)
}

func generatedQuery(plan Plan) string {
	switch plan.Kind {
	case PlanKindEntityQuery:
		return generatedEntityQuery(plan.EntityQuery)
	case PlanKindFindingsQuery:
		return generatedFindingsQuery(plan.FindingsQuery)
	case PlanKindEntityFindingsQuery:
		if plan.CompositeQuery == nil {
			return "entity_findings(invalid)"
		}
		return fmt.Sprintf("%s + findings(severity=%q,query=%q,limit=%d) join(%s)",
			generatedEntityQuery(&plan.CompositeQuery.Entities),
			plan.CompositeQuery.Findings.Severity,
			plan.CompositeQuery.Findings.Query,
			plan.CompositeQuery.Findings.Limit,
			plan.CompositeQuery.JoinOn,
		)
	case PlanKindReverseAccessQuery:
		if plan.ReverseAccess == nil {
			return "reverse_access(invalid)"
		}
		return fmt.Sprintf("reverse_access(targets=%s,admin_only=%t,max_depth=%d)",
			generatedEntityQuery(&plan.ReverseAccess.Targets),
			plan.ReverseAccess.AdminOnly,
			plan.ReverseAccess.MaxDepth,
		)
	case PlanKindGraphChangeDiff:
		if plan.ChangeQuery == nil {
			return "graph_diff(invalid)"
		}
		return fmt.Sprintf("graph_diff(since=%s,until=%s)",
			plan.ChangeQuery.Since.Format(time.RFC3339),
			plan.ChangeQuery.Until.Format(time.RFC3339),
		)
	default:
		return string(plan.Kind)
	}
}

func mutableEntityQueries(plan *Plan) []*EntityQuery {
	if plan == nil {
		return nil
	}
	queries := make([]*EntityQuery, 0, 3)
	if plan.EntityQuery != nil {
		queries = append(queries, plan.EntityQuery)
	}
	if plan.CompositeQuery != nil {
		queries = append(queries, &plan.CompositeQuery.Entities)
	}
	if plan.ReverseAccess != nil {
		queries = append(queries, &plan.ReverseAccess.Targets)
	}
	return queries
}

func clonePlan(plan Plan) Plan {
	payload, err := json.Marshal(plan)
	if err != nil {
		return plan
	}
	var clone Plan
	if err := json.Unmarshal(payload, &clone); err != nil {
		return plan
	}
	return clone
}

func normalizeQuestion(question string) string {
	replacer := strings.NewReplacer(
		"?", " ",
		"!", " ",
		".", " ",
		",", " ",
		":", " ",
		";", " ",
		"(", " ",
		")", " ",
		"[", " ",
		"]", " ",
		"{", " ",
		"}", " ",
		"\"", " ",
		"'", " ",
		"/", " ",
		"-", " ",
	)
	question = replacer.Replace(question)
	question = strings.ToLower(strings.TrimSpace(question))
	fields := strings.Fields(question)
	return strings.Join(fields, " ")
}

func isMutationRequest(question string) bool {
	tokens := questionTokens(question)
	for len(tokens) > 0 && isMutationPreambleToken(tokens[0]) {
		tokens = tokens[1:]
	}
	if len(tokens) == 0 {
		return false
	}
	switch tokens[0] {
	case "delete", "remove", "update", "add", "create", "grant", "revoke", "modify", "patch", "change", "disable", "enable", "write", "record":
		return true
	default:
		return false
	}
}

func isMutationPreambleToken(token string) bool {
	switch token {
	case "can", "could", "would", "will", "please", "kindly", "you", "help", "me", "i", "want", "need", "to":
		return true
	default:
		return false
	}
}

func isInternetExposureQuestion(question string) bool {
	return containsAny(question, "internet-facing", "internet facing", "exposed to the internet", "publicly exposed", "public exposure", "publicly reachable")
}

func isInternetFindingQuestion(question string) bool {
	return isInternetExposureQuestion(question) && containsAny(question, "cve", "vulnerability", "vulnerabilities", "finding", "findings", "unpatched")
}

func isCriticalFindingQuestion(question string) bool {
	return containsAny(question, "critical vulnerabilities", "critical vulnerability", "critical cves", "critical cve", "critical findings", "critical finding")
}

func isAdminAccessQuestion(question string) bool {
	return containsAny(question, "admin access", "admin paths", "administrator access", "who has admin", "who can admin")
}

func isGraphChangeQuestion(question string) bool {
	return strings.HasPrefix(question, "what changed") || strings.HasPrefix(question, "show changes") || containsAny(question, "changed this")
}

func extractTargetPhrase(question string) string {
	for _, marker := range []string{" access to ", " paths to ", " path to ", " to "} {
		if idx := strings.Index(question, marker); idx >= 0 {
			return strings.TrimSpace(question[idx+len(marker):])
		}
	}
	return question
}

func inferKinds(question string) []graph.NodeKind {
	tokens := questionTokens(question)
	set := make(map[graph.NodeKind]struct{})
	match := func(kind graph.NodeKind, phrases ...string) {
		if containsAnyTokenPhrase(tokens, phrases...) {
			set[kind] = struct{}{}
		}
	}

	match(graph.NodeKindInstance, "instance", "instances", "server", "servers", "vm", "vms", "ec2")
	match(graph.NodeKindDatabase, "database", "databases", "db", "dbs", "rds")
	match(graph.NodeKindBucket, "bucket", "buckets", "s3")
	match(graph.NodeKindSecret, "secret", "secrets")
	match(graph.NodeKindFunction, "function", "functions", "lambda", "lambdas")
	match(graph.NodeKindRole, "role", "roles")
	match(graph.NodeKindUser, "user", "users")
	match(graph.NodeKindPerson, "person", "people")
	serviceAccount := containsAnyTokenPhrase(tokens, "service account", "service accounts")
	if serviceAccount {
		set[graph.NodeKindServiceAccount] = struct{}{}
	}
	if containsAnyTokenPhrase(tokens, "services") || containsTokenExcludingFollowers(tokens, "service", "account", "accounts") {
		set[graph.NodeKindService] = struct{}{}
	}
	match(graph.NodeKindApplication, "application", "applications", "app", "apps")
	match(graph.NodeKindVulnerability, "cve", "cves", "vulnerability", "vulnerabilities")

	out := make([]graph.NodeKind, 0, len(set))
	for kind := range set {
		out = append(out, kind)
	}
	return uniqueNodeKinds(out)
}

func inferProvider(question string) string {
	switch {
	case containsAny(question, "aws", "amazon web services"):
		return "aws"
	case containsAny(question, "gcp", "google cloud"):
		return "gcp"
	case containsAny(question, "azure", "microsoft azure"):
		return "azure"
	default:
		return ""
	}
}

func inferRisk(question string) graph.RiskLevel {
	switch {
	case containsAny(question, "critical risk", "critical risks"):
		return graph.RiskCritical
	case containsAny(question, "high risk", "high risks"):
		return graph.RiskHigh
	case containsAny(question, "medium risk", "medium risks"):
		return graph.RiskMedium
	case containsAny(question, "low risk", "low risks"):
		return graph.RiskLow
	default:
		return ""
	}
}

func inferSeverity(question string) string {
	tokens := questionTokens(question)
	switch {
	case containsAnyTokenPhrase(tokens, "critical severity", "critical finding", "critical findings", "critical vulnerability", "critical vulnerabilities", "critical cve", "critical cves"):
		return "critical"
	case containsAnyTokenPhrase(tokens, "high severity", "high finding", "high findings", "high vulnerability", "high vulnerabilities"):
		return "high"
	case containsAnyTokenPhrase(tokens, "medium severity", "medium finding", "medium findings", "medium vulnerability", "medium vulnerabilities"):
		return "medium"
	case containsAnyTokenPhrase(tokens, "low severity", "low finding", "low findings", "low vulnerability", "low vulnerabilities"):
		return "low"
	default:
		return ""
	}
}

func inferFollowUpSeverity(question string) string {
	if severity := inferSeverity(question); severity != "" {
		return severity
	}

	tokens := questionTokens(question)
	switch {
	case containsAnyTokenPhrase(tokens, "make those critical", "make them critical", "make that list critical", "make those resources critical", "make those entities critical"):
		return "critical"
	case containsAnyTokenPhrase(tokens, "make those high", "make them high", "make that list high", "make those resources high", "make those entities high"):
		return "high"
	case containsAnyTokenPhrase(tokens, "make those medium", "make them medium", "make that list medium", "make those resources medium", "make those entities medium"):
		return "medium"
	case containsAnyTokenPhrase(tokens, "make those low", "make them low", "make that list low", "make those resources low", "make those entities low"):
		return "low"
	default:
		return ""
	}
}

func inferFindingSearch(question string) string {
	switch {
	case containsAny(question, "cve", "cves"):
		return "cve"
	case containsAny(question, "unpatched"):
		return "unpatched"
	case containsAny(question, "vulnerability", "vulnerabilities"):
		return "vulnerability"
	default:
		return ""
	}
}

func inferSearch(question string) string {
	replacer := strings.NewReplacer(
		"which", " ",
		"what", " ",
		"show", " ",
		"me", " ",
		"all", " ",
		"have", " ",
		"has", " ",
		"with", " ",
		"who", " ",
		"can", " ",
		"admin", " ",
		"access", " ",
		"paths", " ",
		"path", " ",
		"to", " ",
		"internet", " ",
		"facing", " ",
		"exposed", " ",
		"critical", " ",
		"unpatched", " ",
		"cve", " ",
		"cves", " ",
		"vulnerability", " ",
		"vulnerabilities", " ",
		"instances", " ",
		"instance", " ",
		"servers", " ",
		"server", " ",
		"databases", " ",
		"database", " ",
		"db", " ",
		"dbs", " ",
		"resources", " ",
		"resource", " ",
		"our", " ",
		"the", " ",
		"are", " ",
		"is", " ",
	)
	candidate := strings.Join(strings.Fields(replacer.Replace(question)), " ")
	return strings.TrimSpace(candidate)
}

func mergeSearchTerms(existing, extra string) string {
	existing = strings.TrimSpace(existing)
	extra = strings.TrimSpace(extra)
	switch {
	case existing == "":
		return extra
	case extra == "":
		return existing
	case strings.Contains(existing, extra):
		return existing
	default:
		return existing + " " + extra
	}
}

func containsAny(value string, candidates ...string) bool {
	return containsAnyTokenPhrase(questionTokens(value), candidates...)
}

func containsAnyTokenPhrase(tokens []string, candidates ...string) bool {
	for _, candidate := range candidates {
		if containsTokenPhrase(tokens, questionTokens(candidate)) {
			return true
		}
	}
	return false
}

func containsTokenPhrase(tokens, phrase []string) bool {
	if len(tokens) == 0 || len(phrase) == 0 || len(phrase) > len(tokens) {
		return false
	}
	for start := 0; start <= len(tokens)-len(phrase); start++ {
		matched := true
		for index := range phrase {
			if tokens[start+index] != phrase[index] {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}

func containsTokenExcludingFollowers(tokens []string, token string, excludedFollowers ...string) bool {
	for index, current := range tokens {
		if current != token {
			continue
		}
		next := ""
		if index+1 < len(tokens) {
			next = tokens[index+1]
		}
		blocked := false
		for _, excluded := range excludedFollowers {
			if next == excluded {
				blocked = true
				break
			}
		}
		if !blocked {
			return true
		}
	}
	return false
}

func questionTokens(value string) []string {
	return strings.Fields(normalizeQuestion(value))
}

func clampInt(value, defaultValue, minValue, maxValue int) int {
	if value <= 0 {
		value = defaultValue
	}
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
}

func validatePlanPayload(plan Plan) error {
	switch plan.Kind {
	case PlanKindEntityQuery:
		if plan.EntityQuery == nil {
			return fmt.Errorf("entity_query plan missing entity_query payload")
		}
	case PlanKindFindingsQuery:
		if plan.FindingsQuery == nil {
			return fmt.Errorf("findings_query plan missing findings_query payload")
		}
	case PlanKindEntityFindingsQuery:
		if plan.CompositeQuery == nil {
			return fmt.Errorf("entity_findings_query plan missing composite_query payload")
		}
	case PlanKindReverseAccessQuery:
		if plan.ReverseAccess == nil {
			return fmt.Errorf("reverse_access_query plan missing reverse_access payload")
		}
	case PlanKindGraphChangeDiff:
		if plan.ChangeQuery == nil {
			return fmt.Errorf("graph_change_diff_query plan missing change_query payload")
		}
	default:
		return ErrUnsupportedQuestion
	}
	return nil
}
func formatNodeKinds(values []graph.NodeKind) string {
	items := make([]string, 0, len(values))
	for _, value := range values {
		items = append(items, string(value))
	}
	return "[" + strings.Join(items, ",") + "]"
}

func formatNodeCategories(values []graph.NodeKindCategory) string {
	items := make([]string, 0, len(values))
	for _, value := range values {
		items = append(items, string(value))
	}
	return "[" + strings.Join(items, ",") + "]"
}

func formatNodeCapabilities(values []graph.NodeKindCapability) string {
	items := make([]string, 0, len(values))
	for _, value := range values {
		items = append(items, string(value))
	}
	return "[" + strings.Join(items, ",") + "]"
}

func formatOptionalBool(value *bool) string {
	if value == nil {
		return "unset"
	}
	if *value {
		return "true"
	}
	return "false"
}

func uniqueNodeKinds(values []graph.NodeKind) []graph.NodeKind {
	set := make(map[graph.NodeKind]struct{}, len(values))
	out := make([]graph.NodeKind, 0, len(values))
	for _, value := range values {
		value = graph.NodeKind(strings.TrimSpace(string(value)))
		if value == "" {
			continue
		}
		if _, ok := set[value]; ok {
			continue
		}
		set[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func filterOutKinds(values []graph.NodeKind, excluded ...graph.NodeKind) []graph.NodeKind {
	if len(values) == 0 || len(excluded) == 0 {
		return values
	}
	excludedSet := make(map[graph.NodeKind]struct{}, len(excluded))
	for _, kind := range excluded {
		excludedSet[kind] = struct{}{}
	}
	filtered := make([]graph.NodeKind, 0, len(values))
	for _, kind := range values {
		if _, ok := excludedSet[kind]; ok {
			continue
		}
		filtered = append(filtered, kind)
	}
	return filtered
}

func uniqueNodeCategories(values []graph.NodeKindCategory) []graph.NodeKindCategory {
	set := make(map[graph.NodeKindCategory]struct{}, len(values))
	out := make([]graph.NodeKindCategory, 0, len(values))
	for _, value := range values {
		value = graph.NodeKindCategory(strings.TrimSpace(string(value)))
		if value == "" {
			continue
		}
		if _, ok := set[value]; ok {
			continue
		}
		set[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func uniqueNodeCapabilities(values []graph.NodeKindCapability) []graph.NodeKindCapability {
	set := make(map[graph.NodeKindCapability]struct{}, len(values))
	out := make([]graph.NodeKindCapability, 0, len(values))
	for _, value := range values {
		value = graph.NodeKindCapability(strings.TrimSpace(string(value)))
		if value == "" {
			continue
		}
		if _, ok := set[value]; ok {
			continue
		}
		set[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func clampConfidence(value float64) float64 {
	if value < 0 {
		return 0
	}
	if value > 1 {
		return 1
	}
	return value
}

func (t *Translator) now() time.Time {
	if t != nil && t.Now != nil {
		return t.Now().UTC()
	}
	return time.Now().UTC()
}
