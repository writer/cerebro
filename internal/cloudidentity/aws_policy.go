package cloudidentity

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
)

type awsPolicyDocument struct {
	Version   string          `json:"Version"`
	Statement json.RawMessage `json:"Statement"`
}

type awsStatement struct {
	Sid          string                                `json:"Sid"`
	Effect       string                                `json:"Effect"`
	Action       json.RawMessage                       `json:"Action"`
	NotAction    json.RawMessage                       `json:"NotAction"`
	Resource     json.RawMessage                       `json:"Resource"`
	NotResource  json.RawMessage                       `json:"NotResource"`
	Principal    json.RawMessage                       `json:"Principal"`
	NotPrincipal json.RawMessage                       `json:"NotPrincipal"`
	Condition    map[string]map[string]json.RawMessage `json:"Condition"`
}

// ParseAWSPolicy decodes an AWS IAM policy document (identity, resource, or
// trust) into Grants. It preserves conditions, NotAction/NotResource and
// trust principals verbatim rather than flattening them, and it never widens
// a statement's effective scope: an identity-shaped statement (no Principal)
// that omits both Resource and NotResource keeps Resources empty rather than
// defaulting to "*" — ambiguity is surfaced downstream by Assess as an
// unknown-scope gap, never silently resolved to "allow everything".
//
// document must already be decoded JSON bytes (callers reading a
// URL-encoded PolicyDocument from an IAM API must url-decode first).
func ParseAWSPolicy(document []byte, reference Reference) ([]Grant, error) {
	var doc awsPolicyDocument
	if err := json.Unmarshal(document, &doc); err != nil {
		return nil, fmt.Errorf("cloudidentity: parse aws policy: %w", err)
	}
	statements, err := decodeAWSStatements(doc.Statement)
	if err != nil {
		return nil, err
	}
	if len(statements) == 0 {
		return nil, fmt.Errorf("cloudidentity: aws policy document has no statements")
	}

	grants := make([]Grant, 0, len(statements))
	for index, statement := range statements {
		grant, err := convertAWSStatement(index, statement, reference)
		if err != nil {
			return nil, err
		}
		grants = append(grants, grant)
	}
	return grants, nil
}

func decodeAWSStatements(raw json.RawMessage) ([]awsStatement, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, fmt.Errorf("cloudidentity: aws policy document missing Statement")
	}
	var list []awsStatement
	if err := json.Unmarshal(raw, &list); err == nil {
		return list, nil
	}
	var single awsStatement
	if err := json.Unmarshal(raw, &single); err != nil {
		return nil, fmt.Errorf("cloudidentity: aws policy Statement is neither an object nor an array: %w", err)
	}
	return []awsStatement{single}, nil
}

func convertAWSStatement(index int, statement awsStatement, reference Reference) (Grant, error) {
	effect := statement.Effect
	if effect != "Allow" && effect != "Deny" {
		return Grant{}, fmt.Errorf("cloudidentity: aws policy statement %d has unsupported Effect %q", index, effect)
	}

	id := statement.Sid
	if id == "" {
		id = fmt.Sprintf("statement-%d", index)
	}

	actions, err := decodeAWSStringSet(statement.Action)
	if err != nil {
		return Grant{}, fmt.Errorf("cloudidentity: aws policy statement %q Action: %w", id, err)
	}
	notActions, err := decodeAWSStringSet(statement.NotAction)
	if err != nil {
		return Grant{}, fmt.Errorf("cloudidentity: aws policy statement %q NotAction: %w", id, err)
	}
	if len(actions) == 0 && len(notActions) == 0 {
		return Grant{}, fmt.Errorf("cloudidentity: aws policy statement %q has neither Action nor NotAction", id)
	}

	resources, err := decodeAWSStringSet(statement.Resource)
	if err != nil {
		return Grant{}, fmt.Errorf("cloudidentity: aws policy statement %q Resource: %w", id, err)
	}
	notResources, err := decodeAWSStringSet(statement.NotResource)
	if err != nil {
		return Grant{}, fmt.Errorf("cloudidentity: aws policy statement %q NotResource: %w", id, err)
	}

	members, hasNotPrincipal := decodeAWSPrincipal(statement.Principal, statement.NotPrincipal)

	conditions, err := decodeAWSConditions(statement.Condition)
	if err != nil {
		return Grant{}, fmt.Errorf("cloudidentity: aws policy statement %q Condition: %w", id, err)
	}
	if hasNotPrincipal {
		// Grant has no NotMembers field: principal negation cannot be
		// represented positively. Recording it as an "Unsupported" condition
		// (rather than dropping it or folding it into Members) makes the
		// grant's applicability ambiguous to downstream matching instead of
		// silently granting or excluding the negated principals.
		conditions = append(conditions, Condition{
			Operator: "Unsupported",
			Key:      "aws:NotPrincipal",
			Values:   []string{"statement negates principals; applicability is unknown"},
		})
	}

	return Grant{
		ID:           id,
		Effect:       effect,
		Actions:      actions,
		NotActions:   notActions,
		Resources:    resources,
		NotResources: notResources,
		Conditions:   conditions,
		Members:      members,
		References:   []Reference{reference},
	}, nil
}

// decodeAWSStringSet normalizes an AWS policy field that may be absent, a
// single string, or an array of strings into a string slice. Absent fields
// return (nil, nil) — callers must not treat nil as "*".
func decodeAWSStringSet(raw json.RawMessage) ([]string, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return nil, nil
	}
	var single string
	if err := json.Unmarshal(trimmed, &single); err == nil {
		if single == "" {
			return nil, nil
		}
		return []string{single}, nil
	}
	var list []string
	if err := json.Unmarshal(trimmed, &list); err != nil {
		return nil, fmt.Errorf("expected string or array of strings: %w", err)
	}
	out := make([]string, 0, len(list))
	for _, v := range list {
		if v == "" {
			continue
		}
		out = append(out, v)
	}
	return out, nil
}

// decodeAWSPrincipal maps a Principal block ("*" or {"AWS":...,"Service":...,
// "Federated":...,"CanonicalUser":...}) into "Type:value" members, and
// reports whether a NotPrincipal block was present (which cannot be
// represented as members; see convertAWSStatement).
func decodeAWSPrincipal(principal, notPrincipal json.RawMessage) ([]string, bool) {
	var members []string
	if len(bytes.TrimSpace(principal)) > 0 && string(bytes.TrimSpace(principal)) != "null" {
		members = decodeAWSPrincipalValue(principal)
	}
	hasNotPrincipal := len(bytes.TrimSpace(notPrincipal)) > 0 && string(bytes.TrimSpace(notPrincipal)) != "null"
	return members, hasNotPrincipal
}

func decodeAWSPrincipalValue(raw json.RawMessage) []string {
	var wildcard string
	if err := json.Unmarshal(raw, &wildcard); err == nil {
		if wildcard == "" {
			return nil
		}
		return []string{wildcard}
	}
	var byType map[string]json.RawMessage
	if err := json.Unmarshal(raw, &byType); err != nil {
		return nil
	}
	types := make([]string, 0, len(byType))
	for t := range byType {
		types = append(types, t)
	}
	sort.Strings(types)
	var members []string
	for _, t := range types {
		values, err := decodeAWSStringSet(byType[t])
		if err != nil {
			continue
		}
		for _, v := range values {
			members = append(members, t+":"+v)
		}
	}
	return members
}

func decodeAWSConditions(raw map[string]map[string]json.RawMessage) ([]Condition, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	operators := make([]string, 0, len(raw))
	for op := range raw {
		operators = append(operators, op)
	}
	sort.Strings(operators)
	var conditions []Condition
	for _, op := range operators {
		keys := raw[op]
		keyNames := make([]string, 0, len(keys))
		for k := range keys {
			keyNames = append(keyNames, k)
		}
		sort.Strings(keyNames)
		for _, key := range keyNames {
			values, err := decodeAWSStringSet(keys[key])
			if err != nil {
				return nil, fmt.Errorf("condition %s.%s: %w", op, key, err)
			}
			conditions = append(conditions, Condition{Operator: op, Key: key, Values: values})
		}
	}
	return conditions, nil
}
