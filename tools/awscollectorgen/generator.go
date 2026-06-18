package main

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"text/template"
)

var (
	familyPattern   = regexp.MustCompile(`^[a-z][a-z0-9]*(_[a-z0-9]+)*$`)
	goIdentPattern  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	goTypePattern   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)?$`)
	goExprDenyChars = regexp.MustCompile(`[\r\n;]`)
)

const (
	sentinelFamilyConst     = "// awscollectorgen:family-const"
	sentinelFamilyRegister  = "// awscollectorgen:family-register"
	sentinelNormalize       = "// awscollectorgen:normalize-families"
	sentinelFixture         = "// awscollectorgen:fixture-families"
	sentinelProjector       = "// awscollectorgen:projector"
	sentinelEmittedKinds    = "# awscollectorgen:emitted-kinds"
	sentinelRuntimeFamilies = "# awscollectorgen:runtime-families"
	sentinelDimensions      = "# awscollectorgen:coverage-dimensions"
	sentinelDeployRuntimes  = "# awscollectorgen:deploy-runtimes"
)

type names struct {
	Family      string
	Pascal      string
	Dashed      string
	FamilyConst string
	RecordType  string
	ListFunc    string
	EventFunc   string
	Kind        string
	SchemaRef   string
	Label       string
	Title       string
	TitleYAML   string
	URNExpr     string
	CursorExpr  string
	Projector   string
}

func deriveNames(family, title, constName, recordType, listFunc, eventFunc, label, urnExpr, cursorExpr, projector string) (names, error) {
	family = strings.TrimSpace(family)
	if !familyPattern.MatchString(family) {
		return names{}, fmt.Errorf("family %q must be lower_snake_case matching %s", family, familyPattern.String())
	}
	pascal := pascalCase(family)
	if constName = strings.TrimSpace(constName); constName == "" {
		constName = "family" + pascal
	}
	if !goIdentPattern.MatchString(constName) {
		return names{}, fmt.Errorf("const name %q must be a Go identifier", constName)
	}
	if recordType = strings.TrimSpace(recordType); !goTypePattern.MatchString(recordType) {
		return names{}, fmt.Errorf("record type %q must be a Go identifier or selector", recordType)
	}
	if listFunc = strings.TrimSpace(listFunc); !goIdentPattern.MatchString(listFunc) {
		return names{}, fmt.Errorf("list func %q must be a Go identifier", listFunc)
	}
	if eventFunc = strings.TrimSpace(eventFunc); !goIdentPattern.MatchString(eventFunc) {
		return names{}, fmt.Errorf("event func %q must be a Go identifier", eventFunc)
	}
	if urnExpr = strings.TrimSpace(urnExpr); urnExpr == "" || goExprDenyChars.MatchString(urnExpr) {
		return names{}, fmt.Errorf("urn expr must be a non-empty single Go expression")
	}
	if cursorExpr = strings.TrimSpace(cursorExpr); cursorExpr == "" {
		cursorExpr = urnExpr
	}
	if goExprDenyChars.MatchString(cursorExpr) {
		return names{}, fmt.Errorf("cursor expr must be a single Go expression")
	}
	if projector = strings.TrimSpace(projector); projector == "" {
		projector = "awsCloudResourceProjections"
	}
	if !goIdentPattern.MatchString(projector) {
		return names{}, fmt.Errorf("projector %q must be a Go identifier", projector)
	}
	if label = strings.TrimSpace(label); label == "" {
		label = "aws " + strings.ReplaceAll(family, "_", " ")
	}
	if title = strings.TrimSpace(title); title == "" {
		title = "AWS " + strings.ReplaceAll(family, "_", " ")
	}
	if strings.ContainsAny(title, "\r\n") {
		return names{}, fmt.Errorf("title must be a single line")
	}
	return names{
		Family:      family,
		Pascal:      pascal,
		Dashed:      strings.ReplaceAll(family, "_", "-"),
		FamilyConst: constName,
		RecordType:  recordType,
		ListFunc:    listFunc,
		EventFunc:   eventFunc,
		Kind:        "aws." + family,
		SchemaRef:   "aws/" + family + "/v1",
		Label:       label,
		Title:       title,
		TitleYAML:   strconv.Quote(title),
		URNExpr:     urnExpr,
		CursorExpr:  cursorExpr,
		Projector:   projector,
	}, nil
}

func pascalCase(family string) string {
	var b strings.Builder
	for _, part := range strings.Split(family, "_") {
		b.WriteString(strings.ToUpper(part[:1]))
		b.WriteString(part[1:])
	}
	return b.String()
}

var registerTemplate = template.Must(template.New("register").Parse(`		awsFamily(s.clients, awsFamilyOptions[{{.RecordType}}]{
			Name:  {{.FamilyConst}},
			Label: {{printf "%q" .Label}},
			List:  {{.ListFunc}},
			Event: {{.EventFunc}},
			URN: func(settings settings, record {{.RecordType}}) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:{{.Family}}:%s", settings.accountID, {{.URNExpr}}), nil
			},
			CursorFallback: func(record {{.RecordType}}) string { return {{.CursorExpr}} },
		}),`))

var dimensionTemplate = template.Must(template.New("dimension").Parse(`    - id: {{.Family}}
      type: entity_family
      title: {{.TitleYAML}}
      families: [{{.Family}}]
      support: supported
      high_value: false`))

var deployTemplate = template.Must(template.New("deploy").Parse(`  - localId: {{.Dashed}}
    config:
      account_id: env:AWS_ACCOUNT_ID
      family: {{.Family}}
      per_page: "100"
      region: env:AWS_REGION
      role_arn: env:AWS_ROLE_ARN`))

func renderTemplate(tmpl *template.Template, n names) (string, error) {
	var b strings.Builder
	if err := tmpl.Execute(&b, n); err != nil {
		return "", err
	}
	return b.String(), nil
}

func insertBeforeLineSentinel(content, sentinel, snippet string) (string, error) {
	idx, err := singleSentinelIndex(content, sentinel)
	if err != nil {
		return "", err
	}
	lineStart := strings.LastIndex(content[:idx], "\n") + 1
	if !strings.HasSuffix(snippet, "\n") {
		snippet += "\n"
	}
	return content[:lineStart] + snippet + content[lineStart:], nil
}

func insertBeforeInlineTarget(content, sentinel, target, snippet string) (string, error) {
	idx, err := singleSentinelIndex(content, sentinel)
	if err != nil {
		return "", err
	}
	lineStart := strings.LastIndex(content[:idx], "\n") + 1
	lineEnd := strings.Index(content[idx:], "\n")
	if lineEnd < 0 {
		lineEnd = len(content)
	} else {
		lineEnd += idx
	}
	line := content[lineStart:lineEnd]
	targetOffset := strings.Index(line, target)
	if targetOffset < 0 {
		return "", fmt.Errorf("target %q not found on sentinel line %q", target, sentinel)
	}
	if lineStart+targetOffset > idx {
		return "", fmt.Errorf("target %q appears after sentinel %q", target, sentinel)
	}
	insertAt := lineStart + targetOffset
	return content[:insertAt] + snippet + content[insertAt:], nil
}

func singleSentinelIndex(content, sentinel string) (int, error) {
	idx := strings.Index(content, sentinel)
	if idx < 0 {
		return 0, fmt.Errorf("sentinel %q not found", sentinel)
	}
	if strings.Count(content, sentinel) > 1 {
		return 0, fmt.Errorf("sentinel %q appears more than once", sentinel)
	}
	return idx, nil
}
