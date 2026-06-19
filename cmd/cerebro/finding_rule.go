package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"go/format"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/ports"
)

const findingRuleNewUsage = "usage: %s finding-rule new <rule-id> source_id=<source> event_kinds=<kind[,kind]> [name=<name>] [output_kind=<kind>] [severity=<severity>] [status=<status>] [maturity=<maturity>] [tags=<tag[,tag]>] [references=<ref[,ref]>] [false_positives=<fp[,fp]>] [runbook=<text>] [control_refs=<framework:control[,framework:control]>] [required_attributes=<attr[,attr]>] [fingerprint_fields=<field[,field]>] [lifecycle_kind=<kind>] [lifecycle_anchor=<anchor>] [lifecycle_ttl=<duration>] [pack=<pack>] [output_dir=<dir>] [dry_run=true] [force=true]"

const findingRuleGraphEvaluateUsage = "usage: %s finding-rule graph-evaluate <runtime-id> rule_id=<graph-rule-id>"

var errScaffoldDurableStateDefaultFingerprint = errors.New("lifecycle_kind=durable_state requires fingerprint_fields to include stable non-default fields; default [event_id] is event-scoped")

type findingRuleScaffoldRequest struct {
	Definition findings.RuleDefinition
	Pack       string
	OutputDir  string
	DryRun     bool
	Force      bool
}

type findingRuleScaffoldResult struct {
	RuleID    string   `json:"rule_id"`
	Pack      string   `json:"pack"`
	DryRun    bool     `json:"dry_run"`
	Files     []string `json:"files"`
	NextSteps []string `json:"next_steps"`
}

type findingRuleTemplateData struct {
	Definition findings.RuleDefinition
	Pack       string
	Names      findingRuleTemplateNames
	Files      findingRuleTemplateFiles
	Literals   findingRuleTemplateLiterals
	Fixture    findingRuleTemplateFixture
}

type findingRuleTemplateNames struct {
	RuleIDConst    string
	TitleConst     string
	SeverityConst  string
	StatusConst    string
	CheckIDConst   string
	CheckNameConst string
	ControlRefsVar string
	DefinitionVar  string
	KindMatcherVar string
	Constructor    string
	MatchFunc      string
	BuildFunc      string
	TestFunc       string
}

type findingRuleTemplateFiles struct {
	Rule    string
	Test    string
	Fixture string
}

type findingRuleTemplateLiterals struct {
	EventKinds         string
	Tags               string
	References         string
	FalsePositives     string
	RequiredAttributes string
	FingerprintFields  string
	ControlRefs        string
}

type findingRuleTemplateFixture struct {
	RequiredAttrs  map[string]string
	ExpectedAttrs  map[string]string
	FirstEventKind string
}

func runFindingRule(args []string) error {
	if len(args) == 0 {
		return usageError(fmt.Sprintf("%s\n%s", fmt.Sprintf(findingRuleNewUsage, os.Args[0]), fmt.Sprintf(findingRuleGraphEvaluateUsage, os.Args[0])))
	}
	switch args[0] {
	case "new":
		request, err := parseFindingRuleNewArgs(args[1:])
		if err != nil {
			return err
		}
		result, err := scaffoldFindingRule(request)
		if err != nil {
			return err
		}
		return printJSON(result)
	case "graph-evaluate":
		return runFindingRuleGraphEvaluate(args[1:])
	default:
		return usageError(fmt.Sprintf("%s\n%s", fmt.Sprintf(findingRuleNewUsage, os.Args[0]), fmt.Sprintf(findingRuleGraphEvaluateUsage, os.Args[0])))
	}
}

func parseFindingRuleNewArgs(args []string) (findingRuleScaffoldRequest, error) {
	if len(args) == 0 || strings.TrimSpace(args[0]) == "" {
		return findingRuleScaffoldRequest{}, usageError(fmt.Sprintf(findingRuleNewUsage, os.Args[0]))
	}
	ruleID := strings.TrimSpace(args[0])
	if err := validateScaffoldRuleID(ruleID); err != nil {
		return findingRuleScaffoldRequest{}, err
	}
	values := map[string]string{}
	for _, arg := range args[1:] {
		key, value, ok := strings.Cut(arg, "=")
		if !ok {
			return findingRuleScaffoldRequest{}, fmt.Errorf("invalid finding rule argument %q; want key=value", arg)
		}
		values[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	sourceID := values["source_id"]
	eventKinds := splitCSV(values["event_kinds"])
	if strings.TrimSpace(sourceID) == "" || len(eventKinds) == 0 {
		return findingRuleScaffoldRequest{}, usageError(fmt.Sprintf(findingRuleNewUsage, os.Args[0]))
	}
	outputKind := strings.TrimSpace(values["output_kind"])
	if outputKind == "" {
		outputKind = "finding." + snakeIdentifier(ruleID)
	}
	name := strings.TrimSpace(values["name"])
	if name == "" {
		name = titleFromID(ruleID)
	}
	description := strings.TrimSpace(values["description"])
	if description == "" {
		description = fmt.Sprintf("%s generated finding rule scaffold for %s source events. Review matcher logic and metadata before registration.", name, sourceID)
	}
	severity := firstNonEmptyCLI(values["severity"], "MEDIUM")
	status := firstNonEmptyCLI(values["status"], "open")
	maturity := firstNonEmptyCLI(values["maturity"], "test")
	tags := splitCSV(values["tags"])
	if len(tags) == 0 {
		tags = []string{sourceID, "generated"}
	}
	references := splitCSV(values["references"])
	if len(references) == 0 {
		references = []string{"Generated scaffold; replace with provider or control-plane reference before registration."}
	}
	falsePositives := splitCSV(values["false_positives"])
	if len(falsePositives) == 0 {
		falsePositives = []string{"The source event is expected or covered by an approved exception."}
	}
	runbook := strings.TrimSpace(values["runbook"])
	if runbook == "" {
		runbook = "Review the triggering source event, confirm the state is still risky, then remediate the provider state or document an approved exception."
	}
	fingerprintFields := splitCSV(values["fingerprint_fields"])
	if len(fingerprintFields) == 0 {
		fingerprintFields = []string{"event_id"}
	}
	controlRefs, err := parseScaffoldControlRefs(values["control_refs"])
	if err != nil {
		return findingRuleScaffoldRequest{}, err
	}
	pack := firstNonEmptyCLI(values["pack"], sourceID)
	outputDir := firstNonEmptyCLI(values["output_dir"], ".")
	dryRun, err := parseBoolValue(values["dry_run"])
	if err != nil {
		return findingRuleScaffoldRequest{}, fmt.Errorf("parse dry_run: %w", err)
	}
	force, err := parseBoolValue(values["force"])
	if err != nil {
		return findingRuleScaffoldRequest{}, fmt.Errorf("parse force: %w", err)
	}
	lifecycle, err := parseScaffoldLifecycle(values)
	if err != nil {
		return findingRuleScaffoldRequest{}, err
	}
	if lifecycle.Kind == findings.LifecycleDurableState && isDefaultEventIDFingerprint(fingerprintFields) {
		return findingRuleScaffoldRequest{}, errScaffoldDurableStateDefaultFingerprint
	}
	definition := findings.RuleDefinition{
		ID:                 ruleID,
		Name:               name,
		Description:        description,
		SourceID:           sourceID,
		EventKinds:         eventKinds,
		OutputKind:         outputKind,
		Severity:           severity,
		Status:             status,
		Maturity:           maturity,
		Tags:               tags,
		References:         references,
		FalsePositives:     falsePositives,
		Runbook:            runbook,
		RequiredAttributes: splitCSV(values["required_attributes"]),
		FingerprintFields:  fingerprintFields,
		ControlRefs:        controlRefs,
		Lifecycle:          lifecycle,
	}
	if err := definition.Validate(); err != nil {
		return findingRuleScaffoldRequest{}, err
	}
	return findingRuleScaffoldRequest{
		Definition: definition,
		Pack:       pack,
		OutputDir:  outputDir,
		DryRun:     dryRun,
		Force:      force,
	}, nil
}

func parseScaffoldLifecycle(values map[string]string) (findings.Lifecycle, error) {
	kind := findings.LifecycleKind(strings.TrimSpace(values["lifecycle_kind"]))
	if kind == "" {
		kind = findings.LifecycleAuditEvidence
	}
	anchor := findings.LifecycleAnchor(strings.TrimSpace(values["lifecycle_anchor"]))
	if anchor == "" {
		switch kind {
		case findings.LifecycleDurableState:
			anchor = findings.AnchorGraphAnchored
		default:
			anchor = findings.AnchorNone
		}
	}
	var ttl time.Duration
	if raw := strings.TrimSpace(values["lifecycle_ttl"]); raw != "" {
		parsed, err := time.ParseDuration(raw)
		if err != nil {
			return findings.Lifecycle{}, fmt.Errorf("parse lifecycle_ttl: %w", err)
		}
		ttl = parsed
	}
	return findings.Lifecycle{Kind: kind, Anchor: anchor, TTL: ttl}, nil
}

func scaffoldFindingRule(request findingRuleScaffoldRequest) (*findingRuleScaffoldResult, error) {
	data := newFindingRuleTemplateData(request)
	rulePath := filepath.Join(request.OutputDir, "internal", "findings", data.Files.Rule)
	testPath := filepath.Join(request.OutputDir, "internal", "findings", data.Files.Test)
	fixturePath := filepath.Join(request.OutputDir, "internal", "findings", "testdata", "rules", data.Files.Fixture)
	files := []string{rulePath, testPath, fixturePath}
	result := &findingRuleScaffoldResult{
		RuleID: request.Definition.ID,
		Pack:   request.Pack,
		DryRun: request.DryRun,
		Files:  files,
		NextSteps: []string{
			"Review generated matcher and finding builder.",
			"Register the constructor in the relevant builtin rule pack.",
			"Run: make finding-rule-test",
		},
	}
	if request.DryRun {
		return result, nil
	}
	ruleSource, err := format.Source([]byte(renderFindingRuleGo(data)))
	if err != nil {
		return nil, fmt.Errorf("format generated rule: %w", err)
	}
	testSource, err := format.Source([]byte(renderFindingRuleTestGo(data)))
	if err != nil {
		return nil, fmt.Errorf("format generated rule test: %w", err)
	}
	contents := map[string]string{
		rulePath:    string(ruleSource),
		testPath:    string(testSource),
		fixturePath: renderFindingRuleFixture(data),
	}
	for _, path := range files {
		if !request.Force {
			if _, err := os.Stat(path); err == nil {
				return nil, fmt.Errorf("%s already exists; pass force=true to overwrite", path)
			} else if !os.IsNotExist(err) {
				return nil, err
			}
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, []byte(contents[path]), 0o600); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func newFindingRuleTemplateData(request findingRuleScaffoldRequest) findingRuleTemplateData {
	definition := request.Definition
	snake := snakeIdentifier(definition.ID)
	camel := lowerCamelIdentifier(definition.ID)
	pascal := pascalIdentifier(definition.ID)
	requiredFixtureAttrs := map[string]string{}
	expectedAttrs := map[string]string{}
	for _, attr := range definition.RequiredAttributes {
		requiredFixtureAttrs[attr] = "fixture-" + snakeIdentifier(attr)
		expectedAttrs[attr] = "fixture-" + snakeIdentifier(attr)
	}
	return findingRuleTemplateData{
		Definition: definition,
		Pack:       request.Pack,
		Names: findingRuleTemplateNames{
			RuleIDConst:    camel + "RuleID",
			TitleConst:     camel + "Title",
			SeverityConst:  camel + "Severity",
			StatusConst:    camel + "Status",
			CheckIDConst:   camel + "CheckID",
			CheckNameConst: camel + "CheckName",
			ControlRefsVar: camel + "ControlRefs",
			DefinitionVar:  camel + "Definition",
			KindMatcherVar: camel + "KindMatcher",
			Constructor:    "new" + pascal + "Rule",
			MatchFunc:      "matches" + pascal,
			BuildFunc:      camel + "Finding",
			TestFunc:       "Test" + pascal + "Fixture",
		},
		Files: findingRuleTemplateFiles{
			Rule:    snake + "_rule.go",
			Test:    snake + "_rule_test.go",
			Fixture: definition.ID + ".json",
		},
		Literals: findingRuleTemplateLiterals{
			EventKinds:         goStringSlice(definition.EventKinds),
			Tags:               goStringSlice(definition.Tags),
			References:         goStringSlice(definition.References),
			FalsePositives:     goStringSlice(definition.FalsePositives),
			RequiredAttributes: goStringSlice(definition.RequiredAttributes),
			FingerprintFields:  goStringSlice(definition.FingerprintFields),
			ControlRefs:        goControlRefSlice(definition.ControlRefs),
		},
		Fixture: findingRuleTemplateFixture{
			RequiredAttrs:  requiredFixtureAttrs,
			ExpectedAttrs:  expectedAttrs,
			FirstEventKind: firstNonEmptyCLI(firstString(definition.EventKinds), definition.ID),
		},
	}
}

func renderFindingRuleGo(data findingRuleTemplateData) string {
	var b strings.Builder
	definition := data.Definition
	names := data.Names
	literals := data.Literals
	fmt.Fprintf(&b, "package findings\n\n")
	fmt.Fprintf(&b, "import (\n")
	fmt.Fprintf(&b, "\t\"context\"\n")
	fmt.Fprintf(&b, "\t\"strings\"\n")
	fmt.Fprintf(&b, "\t\"time\"\n\n")
	fmt.Fprintf(&b, "\tcerebrov1 \"github.com/writer/cerebro/gen/cerebro/v1\"\n")
	fmt.Fprintf(&b, "\t\"github.com/writer/cerebro/internal/ports\"\n")
	fmt.Fprintf(&b, ")\n\n")
	fmt.Fprintf(&b, "const (\n")
	fmt.Fprintf(&b, "\t%s = %s\n", names.RuleIDConst, strconv.Quote(definition.ID))
	fmt.Fprintf(&b, "\t%s = %s\n", names.TitleConst, strconv.Quote(definition.Name))
	fmt.Fprintf(&b, "\t%s = %s\n", names.SeverityConst, strconv.Quote(definition.Severity))
	fmt.Fprintf(&b, "\t%s = %s\n", names.StatusConst, strconv.Quote(definition.Status))
	fmt.Fprintf(&b, "\t%s = %s\n", names.CheckIDConst, strconv.Quote(definition.ID))
	fmt.Fprintf(&b, "\t%s = %s\n", names.CheckNameConst, strconv.Quote(definition.Name))
	fmt.Fprintf(&b, ")\n\n")
	fmt.Fprintf(&b, "var %s = []ports.FindingControlRef{%s}\n\n", names.ControlRefsVar, literals.ControlRefs)
	fmt.Fprintf(&b, "var %s = RuleDefinition{\n", names.DefinitionVar)
	fmt.Fprintf(&b, "\tID: %s,\n\tName: %s,\n\tDescription: %s,\n\tSourceID: %s,\n\tEventKinds: %s,\n\tOutputKind: %s,\n\tSeverity: %s,\n\tStatus: %s,\n\tMaturity: %s,\n\tTags: %s,\n\tReferences: %s,\n\tFalsePositives: %s,\n\tRequiredAttributes: %s,\n\tFingerprintFields: %s,\n\tControlRefs: %s,\n\tLifecycle: %s,\n",
		names.RuleIDConst, names.TitleConst, strconv.Quote(definition.Description), strconv.Quote(definition.SourceID), literals.EventKinds, strconv.Quote(definition.OutputKind), names.SeverityConst, names.StatusConst, strconv.Quote(definition.Maturity), literals.Tags, literals.References, literals.FalsePositives, literals.RequiredAttributes, literals.FingerprintFields, names.ControlRefsVar, renderLifecycleLiteral(definition.Lifecycle))
	fmt.Fprintf(&b, "}\n\n")
	fmt.Fprintf(&b, "var %s = eventKindMatcher(%s.EventKinds...)\n\n", names.KindMatcherVar, names.DefinitionVar)
	fmt.Fprintf(&b, "func %s() Rule {\n", names.Constructor)
	if definition.Lifecycle.Kind == findings.LifecycleRetired {
		fmt.Fprintf(&b, "\treturn newRetiredEventRule(%s)\n}\n\n", names.DefinitionVar)
	} else {
		fmt.Fprintf(&b, "\treturn newEventRule(eventRuleConfig{\n\t\tdefinition: %s,\n\t\tmatch: %s,\n\t\tbuild: func(ctx context.Context, runtime *cerebrov1.SourceRuntime, event *cerebrov1.EventEnvelope) (*ports.FindingRecord, error) {\n\t\t\treturn %s(ctx, event, runtime.GetId())\n\t\t},\n\t})\n}\n\n", names.DefinitionVar, names.MatchFunc, names.BuildFunc)
	}
	fmt.Fprintf(&b, "func %s(event *cerebrov1.EventEnvelope) bool {\n\treturn %s(event) && hasRequiredAttributes(event, %s...)\n}\n\n", names.MatchFunc, names.KindMatcherVar, names.DefinitionVar+".RequiredAttributes")
	fmt.Fprintf(&b, "func %s(_ context.Context, event *cerebrov1.EventEnvelope, runtimeID string) (*ports.FindingRecord, error) {\n", names.BuildFunc)
	fmt.Fprintf(&b, "\tfindingAttributes := map[string]string{\n\t\t\"event_id\": strings.TrimSpace(requiredAttributeValue(event, \"event_id\")),\n\t\t\"source_runtime_id\": strings.TrimSpace(requiredAttributeValue(event, ports.EventAttributeSourceRuntimeID)),\n\t}\n")
	fmt.Fprintf(&b, "\tfor _, key := range %s.RequiredAttributes {\n\t\tfindingAttributes[key] = strings.TrimSpace(requiredAttributeValue(event, key))\n\t}\n", names.DefinitionVar)
	fmt.Fprintf(&b, "\tfor key, value := range %s.AttributeMap() {\n\t\tfindingAttributes[\"rule_\"+key] = value\n\t}\n\ttrimEmptyAttributes(findingAttributes)\n", names.DefinitionVar)
	fmt.Fprintf(&b, "\tobservedAt := time.Time{}\n\tif timestamp := event.GetOccurredAt(); timestamp != nil {\n\t\tobservedAt = timestamp.AsTime().UTC()\n\t}\n")
	fmt.Fprintf(&b, "\tfingerprintParts := []string{%s}\n\tfor _, field := range %s.FingerprintFields {\n\t\tfingerprintParts = append(fingerprintParts, requiredAttributeValue(event, field))\n\t}\n\tfingerprint := hashFindingFingerprint(fingerprintParts...)\n", names.RuleIDConst, names.DefinitionVar)
	fmt.Fprintf(&b, "\treturn &ports.FindingRecord{\n\t\tID: fingerprint,\n\t\tFingerprint: fingerprint,\n\t\tTenantID: strings.TrimSpace(event.GetTenantId()),\n\t\tRuntimeID: strings.TrimSpace(runtimeID),\n\t\tRuleID: %s,\n\t\tTitle: %s,\n\t\tSeverity: normalizeFindingSeverity(%s),\n\t\tStatus: %s,\n\t\tSummary: %s,\n\t\tEventIDs: []string{strings.TrimSpace(event.GetId())},\n\t\tCheckID: %s,\n\t\tCheckName: %s,\n\t\tControlRefs: cloneFindingControlRefs(%s),\n\t\tAttributes: findingAttributes,\n\t\tFirstObservedAt: observedAt,\n\t\tLastObservedAt: observedAt,\n\t}, nil\n}\n",
		names.RuleIDConst, names.TitleConst, names.SeverityConst, names.StatusConst, names.TitleConst, names.CheckIDConst, names.CheckNameConst, names.ControlRefsVar)
	return b.String()
}

func renderLifecycleLiteral(lifecycle findings.Lifecycle) string {
	kind := lifecycleKindIdentifier(lifecycle.Kind)
	anchor := lifecycleAnchorIdentifier(lifecycle.Anchor)
	if lifecycle.TTL == 0 {
		return fmt.Sprintf("Lifecycle{Kind: %s, Anchor: %s}", kind, anchor)
	}
	return fmt.Sprintf("Lifecycle{Kind: %s, Anchor: %s, TTL: time.Duration(%d)}", kind, anchor, lifecycle.TTL.Nanoseconds())
}

func lifecycleKindIdentifier(kind findings.LifecycleKind) string {
	switch kind {
	case findings.LifecycleDurableState:
		return "LifecycleDurableState"
	case findings.LifecycleAuditEvidence:
		return "LifecycleAuditEvidence"
	case findings.LifecycleTTLEvidence:
		return "LifecycleTTLEvidence"
	case findings.LifecycleRetired:
		return "LifecycleRetired"
	default:
		return fmt.Sprintf("LifecycleKind(%s)", strconv.Quote(string(kind)))
	}
}

func lifecycleAnchorIdentifier(anchor findings.LifecycleAnchor) string {
	switch anchor {
	case findings.AnchorGraphAnchored:
		return "AnchorGraphAnchored"
	case findings.AnchorSourceState:
		return "AnchorSourceState"
	case findings.AnchorNone:
		return "AnchorNone"
	default:
		return fmt.Sprintf("LifecycleAnchor(%s)", strconv.Quote(string(anchor)))
	}
}

func renderFindingRuleTestGo(data findingRuleTemplateData) string {
	assertion := "assertRuleFixture"
	if data.Definition.Lifecycle.Kind == findings.LifecycleRetired {
		assertion = "assertRetiredEventRuleFixture"
	}
	return fmt.Sprintf("package findings\n\nimport \"testing\"\n\nfunc %s(t *testing.T) {\n\t%s(t, %s(), %s)\n}\n", data.Names.TestFunc, assertion, data.Names.Constructor, strconv.Quote("testdata/rules/"+data.Files.Fixture))
}

func renderFindingRuleFixture(data findingRuleTemplateData) string {
	attributes := map[string]string{
		"source_runtime_id": "fixture-runtime",
	}
	for key, value := range data.Fixture.RequiredAttrs {
		attributes[key] = value
	}
	expectedAttributes := map[string]string{}
	for key, value := range data.Fixture.ExpectedAttrs {
		expectedAttributes[key] = value
	}
	expectedFindings := []map[string]any{
		{
			"rule_id":    data.Definition.ID,
			"severity":   strings.ToUpper(data.Definition.Severity),
			"status":     data.Definition.Status,
			"summary":    data.Definition.Name,
			"event_ids":  []string{"fixture-event-1"},
			"attributes": expectedAttributes,
		},
	}
	if data.Definition.Lifecycle.Kind == findings.LifecycleRetired {
		expectedFindings = []map[string]any{}
	}
	events := []map[string]any{
		{
			"id":          "fixture-event-1",
			"tenant_id":   "fixture-tenant",
			"source_id":   data.Definition.SourceID,
			"kind":        data.Fixture.FirstEventKind,
			"occurred_at": "2026-04-27T00:00:00Z",
			"schema_ref":  data.Definition.SourceID + "/fixture/v1",
			"attributes":  attributes,
		},
	}
	expectedNoMatch := []map[string]string{}
	if data.Definition.Lifecycle.Kind != findings.LifecycleRetired {
		events = append(events, map[string]any{
			"id":          "fixture-event-unrelated-kind",
			"tenant_id":   "fixture-tenant",
			"source_id":   data.Definition.SourceID,
			"kind":        data.Definition.SourceID + ".unrelated",
			"occurred_at": "2026-04-27T00:01:00Z",
			"schema_ref":  data.Definition.SourceID + "/fixture/v1",
			"attributes":  attributes,
		})
		expectedNoMatch = append(expectedNoMatch, map[string]string{"event_id": "fixture-event-unrelated-kind", "reason": "unrelated event kind"})
		if len(data.Definition.RequiredAttributes) != 0 {
			missingRequiredAttributes := map[string]string{"source_runtime_id": "fixture-runtime"}
			events = append(events, map[string]any{
				"id":          "fixture-event-missing-required-attribute",
				"tenant_id":   "fixture-tenant",
				"source_id":   data.Definition.SourceID,
				"kind":        data.Fixture.FirstEventKind,
				"occurred_at": "2026-04-27T00:02:00Z",
				"schema_ref":  data.Definition.SourceID + "/fixture/v1",
				"attributes":  missingRequiredAttributes,
			})
			expectedNoMatch = append(expectedNoMatch, map[string]string{"event_id": "fixture-event-missing-required-attribute", "reason": "missing required attribute"})
		}
	}
	fixture := map[string]any{
		"rule_id": data.Definition.ID,
		"runtime": map[string]any{
			"id":        "fixture-runtime",
			"source_id": data.Definition.SourceID,
			"tenant_id": "fixture-tenant",
		},
		"events":            events,
		"expected_findings": expectedFindings,
	}
	if len(expectedNoMatch) != 0 {
		fixture["expected_no_match"] = expectedNoMatch
	}
	payload, _ := json.MarshalIndent(fixture, "", "  ")
	return string(append(payload, '\n'))
}

func parseScaffoldControlRefs(value string) ([]ports.FindingControlRef, error) {
	parts := splitCSV(value)
	refs := make([]ports.FindingControlRef, 0, len(parts))
	for _, part := range parts {
		index := strings.LastIndex(part, ":")
		if index <= 0 || index == len(part)-1 {
			return nil, fmt.Errorf("invalid control_ref %q; want framework:control", part)
		}
		ref := ports.FindingControlRef{
			FrameworkName: strings.TrimSpace(part[:index]),
			ControlID:     strings.TrimSpace(part[index+1:]),
		}
		if ref.FrameworkName == "" || ref.ControlID == "" {
			return nil, fmt.Errorf("invalid control_ref %q; framework and control are required", part)
		}
		refs = append(refs, ref)
	}
	return refs, nil
}

func splitCSV(value string) []string {
	parts := strings.Split(value, ",")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			values = append(values, trimmed)
		}
	}
	return values
}

func parseBoolValue(value string) (bool, error) {
	if strings.TrimSpace(value) == "" {
		return false, nil
	}
	return strconv.ParseBool(strings.TrimSpace(value))
}

func firstNonEmptyCLI(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func validateScaffoldRuleID(ruleID string) error {
	if strings.ContainsAny(ruleID, `/\`) || strings.Contains(ruleID, "..") {
		return fmt.Errorf("invalid rule id %q; use letters, numbers, dots, underscores, and hyphens", ruleID)
	}
	for _, r := range ruleID {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '.' && r != '_' && r != '-' {
			return fmt.Errorf("invalid rule id %q; use letters, numbers, dots, underscores, and hyphens", ruleID)
		}
	}
	return nil
}

var nonIdentifier = regexp.MustCompile(`[^a-zA-Z0-9]+`)

func snakeIdentifier(value string) string {
	normalized := strings.Trim(nonIdentifier.ReplaceAllString(strings.ToLower(strings.TrimSpace(value)), "_"), "_")
	if normalized == "" {
		return "rule"
	}
	if unicode.IsDigit([]rune(normalized)[0]) {
		return "rule_" + normalized
	}
	return normalized
}

func lowerCamelIdentifier(value string) string {
	pascal := pascalIdentifier(value)
	if pascal == "" {
		return "rule"
	}
	return strings.ToLower(pascal[:1]) + pascal[1:]
}

func pascalIdentifier(value string) string {
	parts := strings.Split(snakeIdentifier(value), "_")
	var b strings.Builder
	for _, part := range parts {
		if part == "" {
			continue
		}
		runes := []rune(part)
		runes[0] = unicode.ToUpper(runes[0])
		b.WriteString(string(runes))
	}
	if b.Len() == 0 {
		return "Rule"
	}
	return b.String()
}

func titleFromID(value string) string {
	parts := strings.Split(snakeIdentifier(value), "_")
	for index, part := range parts {
		if part == "" {
			continue
		}
		runes := []rune(part)
		runes[0] = unicode.ToUpper(runes[0])
		parts[index] = string(runes)
	}
	return strings.Join(parts, " ")
}

func goStringSlice(values []string) string {
	if len(values) == 0 {
		return "nil"
	}
	quoted := make([]string, 0, len(values))
	for _, value := range values {
		quoted = append(quoted, strconv.Quote(strings.TrimSpace(value)))
	}
	return "[]string{" + strings.Join(quoted, ", ") + "}"
}

func goControlRefSlice(values []ports.FindingControlRef) string {
	if len(values) == 0 {
		return ""
	}
	parts := make([]string, 0, len(values))
	for _, value := range values {
		framework := strings.TrimSpace(value.FrameworkName)
		control := strings.TrimSpace(value.ControlID)
		if framework == "" || control == "" {
			continue
		}
		parts = append(parts, fmt.Sprintf("{FrameworkName: %s, ControlID: %s}", strconv.Quote(framework), strconv.Quote(control)))
	}
	return strings.Join(parts, ", ")
}

func firstString(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func isDefaultEventIDFingerprint(fields []string) bool {
	return len(fields) == 1 && strings.EqualFold(strings.TrimSpace(fields[0]), "event_id")
}
