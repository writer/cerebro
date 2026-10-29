package iac

import (
	"encoding/json"
	"fmt"

	"github.com/hashicorp/hcl/v2"
	"github.com/zclconf/go-cty/cty"

	ci "github.com/writer/cerebro/internal/cloudidentity"
)

// flexStrings unmarshals either a bare JSON string or a JSON array of
// strings into a []string, matching AWS's own policy-document leniency
// (Action/Resource/... accept either form). It marshals as a plain array.
type flexStrings []string

func (f *flexStrings) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		if single != "" {
			*f = []string{single}
		}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return err
	}
	*f = many
	return nil
}

// awsPolicyDoc/awsPolicyStatement mirror the canonical AWS IAM policy JSON
// shape. This package only ever constructs these (from HCL
// aws_iam_policy_document blocks) or decodes externally-referenced JSON
// (source_policy_documents/override_policy_documents); the resulting JSON
// text is always handed to the shared ci.ParseAWSPolicy for Grant conversion,
// so trust and identity statements go through one code path regardless of
// whether they originated as a literal jsonencode()/heredoc string or a
// declarative data source.
type awsPolicyDoc struct {
	Version   string               `json:"Version,omitempty"`
	ID        string               `json:"Id,omitempty"`
	Statement []awsPolicyStatement `json:"Statement"`
}

type awsPolicyStatement struct {
	Sid          string                            `json:"Sid,omitempty"`
	Effect       string                            `json:"Effect"`
	Action       flexStrings                       `json:"Action,omitempty"`
	NotAction    flexStrings                       `json:"NotAction,omitempty"`
	Resource     flexStrings                       `json:"Resource,omitempty"`
	NotResource  flexStrings                       `json:"NotResource,omitempty"`
	Principal    any                               `json:"Principal,omitempty"`
	NotPrincipal any                               `json:"NotPrincipal,omitempty"`
	Condition    map[string]map[string]flexStrings `json:"Condition,omitempty"`
}

func parseAWSPolicyDocJSON(raw string) (awsPolicyDoc, error) {
	var outer struct {
		Version   string          `json:"Version"`
		ID        string          `json:"Id"`
		Statement json.RawMessage `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(raw), &outer); err != nil {
		return awsPolicyDoc{}, err
	}
	var stmts []awsPolicyStatement
	if err := json.Unmarshal(outer.Statement, &stmts); err != nil {
		var one awsPolicyStatement
		if err2 := json.Unmarshal(outer.Statement, &one); err2 != nil {
			return awsPolicyDoc{}, err2
		}
		stmts = []awsPolicyStatement{one}
	}
	return awsPolicyDoc{Version: outer.Version, ID: outer.ID, Statement: stmts}, nil
}

// mergeStatements implements aws_iam_policy_document's
// source_policy_documents (prepend, isOverride=false) and
// override_policy_documents (replace-by-Sid-else-append, isOverride=true)
// semantics.
func mergeStatements(base, incoming []awsPolicyStatement, isOverride bool) []awsPolicyStatement {
	if !isOverride {
		out := make([]awsPolicyStatement, 0, len(base)+len(incoming))
		out = append(out, incoming...)
		out = append(out, base...)
		return out
	}
	bySid := map[string]int{}
	for i, s := range base {
		if s.Sid != "" {
			bySid[s.Sid] = i
		}
	}
	out := append([]awsPolicyStatement{}, base...)
	for _, s := range incoming {
		if s.Sid != "" {
			if idx, ok := bySid[s.Sid]; ok {
				out[idx] = s
				continue
			}
		}
		out = append(out, s)
	}
	return out
}

// passData was superseded by the unified dependency-ordered resolver in
// symbols.go (resolveValueSymbols); awsPolicyDocumentValue below is reused
// from there.

// awsPolicyDocumentValue renders one data.aws_iam_policy_document instance
// into canonical AWS policy JSON. Any gap recorded while extracting its
// statements/conditions/principals (including a dynamic block that failed
// to expand) marks both the resulting localPolicy and rn.incompleteDocs for
// this address incomplete, so a consumer evaluating a direct reference to
// this document's .json (see referencesIncompleteDocument) still marks its
// own declaration incomplete even though re-evaluating the already-rendered
// JSON string itself raises no new diagnostic.
func (rn *run) awsPolicyDocumentValue(addr string, declRange hcl.Range, body hcl.Body, ctx *hcl.EvalContext, mf moduleFiles, file *ci.SourceFile) cty.Value {
	scope := addr
	mark := rn.gapMark()
	doc := awsPolicyDoc{Version: "2012-10-17"}
	if expr, ok := rn.bodyAttr(mf, file, scope, body, "version"); ok {
		if v, ok2 := rn.evalString(expr, ctx, mf, file, scope); ok2 && v != "" {
			doc.Version = v
		}
	}
	if expr, ok := rn.bodyAttr(mf, file, scope, body, "policy_id"); ok {
		if v, ok2 := rn.evalString(expr, ctx, mf, file, scope); ok2 {
			doc.ID = v
		}
	}

	if expr, ok := rn.bodyAttr(mf, file, scope, body, "source_policy_documents"); ok {
		for _, raw := range rn.evalStringList(expr, ctx, mf, file, scope) {
			sub, err := parseAWSPolicyDocJSON(raw)
			if err != nil {
				rn.addGap(ci.Gap{Code: "iac.unsupported_expression", Scope: scope, Message: fmt.Sprintf("source_policy_documents entry is not parseable policy JSON: %s", err.Error()), References: []ci.Reference{rn.refFor(mf, file, expr.Range(), scope)}})
				continue
			}
			doc.Statement = mergeStatements(doc.Statement, sub.Statement, false)
		}
	}

	for _, stmtBlock := range rn.expandBlocks(mf, file, scope, body, ctx, "statement") {
		stmt := rn.awsPolicyStatement(scope, stmtBlock, ctx, mf, file)
		doc.Statement = append(doc.Statement, stmt)
	}

	if expr, ok := rn.bodyAttr(mf, file, scope, body, "override_policy_documents"); ok {
		for _, raw := range rn.evalStringList(expr, ctx, mf, file, scope) {
			sub, err := parseAWSPolicyDocJSON(raw)
			if err != nil {
				rn.addGap(ci.Gap{Code: "iac.unsupported_expression", Scope: scope, Message: fmt.Sprintf("override_policy_documents entry is not parseable policy JSON: %s", err.Error()), References: []ci.Reference{rn.refFor(mf, file, expr.Range(), scope)}})
				continue
			}
			doc.Statement = mergeStatements(doc.Statement, sub.Statement, true)
		}
	}

	jsonText := "{}"
	if b, err := json.Marshal(doc); err == nil {
		jsonText = string(b)
	}

	ref := rn.refFor(mf, file, declRange, scope)
	grants, err := ci.ParseAWSPolicy([]byte(jsonText), ref)
	if err != nil {
		rn.addGap(ci.Gap{Code: "iac.policy_parse_error", Scope: scope, Message: err.Error(), References: []ci.Reference{ref}})
	}
	incomplete := rn.gapsSince(mark)
	rn.policies[addr] = &localPolicy{grants: grants, refs: []ci.Reference{ref}, incomplete: incomplete}
	if incomplete {
		rn.incompleteDocs[addr] = true
	}

	return cty.ObjectVal(map[string]cty.Value{
		"json":     cty.StringVal(jsonText),
		"min_json": cty.StringVal(jsonText),
		"id":       cty.StringVal(doc.ID),
	})
}

// awsPolicyStatement extracts one `statement { ... }` block (already
// dynamic-block-expanded by the caller) into the canonical JSON shape.
func (rn *run) awsPolicyStatement(scope string, block *hcl.Block, ctx *hcl.EvalContext, mf moduleFiles, file *ci.SourceFile) awsPolicyStatement {
	body := block.Body
	stmtScope := scope + ".statement"
	stmt := awsPolicyStatement{Effect: "Allow"}

	if expr, ok := rn.bodyAttr(mf, file, stmtScope, body, "sid"); ok {
		if v, ok2 := rn.evalString(expr, ctx, mf, file, stmtScope); ok2 {
			stmt.Sid = v
		}
	}
	if expr, ok := rn.bodyAttr(mf, file, stmtScope, body, "effect"); ok {
		if v, ok2 := rn.evalString(expr, ctx, mf, file, stmtScope); ok2 && v != "" {
			stmt.Effect = v
		}
	}
	if expr, ok := rn.bodyAttr(mf, file, stmtScope, body, "actions"); ok {
		stmt.Action = rn.evalStringList(expr, ctx, mf, file, stmtScope)
	}
	if expr, ok := rn.bodyAttr(mf, file, stmtScope, body, "not_actions"); ok {
		stmt.NotAction = rn.evalStringList(expr, ctx, mf, file, stmtScope)
	}
	if expr, ok := rn.bodyAttr(mf, file, stmtScope, body, "resources"); ok {
		stmt.Resource = rn.evalStringList(expr, ctx, mf, file, stmtScope)
	}
	if expr, ok := rn.bodyAttr(mf, file, stmtScope, body, "not_resources"); ok {
		stmt.NotResource = rn.evalStringList(expr, ctx, mf, file, stmtScope)
	}

	principalMap := map[string][]string{}
	wildcard := false
	for _, pb := range rn.expandBlocks(mf, file, stmtScope, body, ctx, "principals") {
		t, ids := rn.awsPrincipalsBlock(stmtScope, pb, ctx, mf, file)
		if t == "AWS" && len(ids) == 1 && ids[0] == "*" {
			wildcard = true
			continue
		}
		if t != "" {
			principalMap[t] = append(principalMap[t], ids...)
		}
	}
	switch {
	case wildcard:
		stmt.Principal = "*"
	case len(principalMap) > 0:
		stmt.Principal = principalMap
	}

	notPrincipalMap := map[string][]string{}
	notWildcard := false
	for _, pb := range rn.expandBlocks(mf, file, stmtScope, body, ctx, "not_principals") {
		t, ids := rn.awsPrincipalsBlock(stmtScope, pb, ctx, mf, file)
		if t == "AWS" && len(ids) == 1 && ids[0] == "*" {
			notWildcard = true
			continue
		}
		if t != "" {
			notPrincipalMap[t] = append(notPrincipalMap[t], ids...)
		}
	}
	switch {
	case notWildcard:
		stmt.NotPrincipal = "*"
	case len(notPrincipalMap) > 0:
		stmt.NotPrincipal = notPrincipalMap
	}

	cond := map[string]map[string]flexStrings{}
	for _, cb := range rn.expandBlocks(mf, file, stmtScope, body, ctx, "condition") {
		attrs := rn.bodyAttrs(mf, file, stmtScope, cb.Body, "test", "variable", "values")
		testAttr, hasTest := attrs["test"]
		varAttr, hasVar := attrs["variable"]
		valuesAttr, hasValues := attrs["values"]
		if !hasTest || !hasVar || !hasValues {
			continue
		}
		test, ok1 := rn.evalString(testAttr.Expr, ctx, mf, file, stmtScope+".condition")
		variable, ok2 := rn.evalString(varAttr.Expr, ctx, mf, file, stmtScope+".condition")
		if !ok1 || !ok2 {
			continue
		}
		values := rn.evalStringList(valuesAttr.Expr, ctx, mf, file, stmtScope+".condition")
		if cond[test] == nil {
			cond[test] = map[string]flexStrings{}
		}
		cond[test][variable] = append(cond[test][variable], values...)
	}
	if len(cond) > 0 {
		stmt.Condition = cond
	}

	return stmt
}

func (rn *run) awsPrincipalsBlock(scope string, block *hcl.Block, ctx *hcl.EvalContext, mf moduleFiles, file *ci.SourceFile) (string, []string) {
	attrs := rn.bodyAttrs(mf, file, scope, block.Body, "type", "identifiers")
	typeAttr, hasType := attrs["type"]
	idsAttr, hasIds := attrs["identifiers"]
	if !hasType || !hasIds {
		return "", nil
	}
	t, ok := rn.evalString(typeAttr.Expr, ctx, mf, file, scope)
	if !ok {
		return "", nil
	}
	return t, rn.evalStringList(idsAttr.Expr, ctx, mf, file, scope)
}
