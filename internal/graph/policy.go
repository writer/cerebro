package graph

import (
	"encoding/json"
	"net/url"
	"strings"
)

// Statement represents a normalized IAM policy statement
type Statement struct {
	Effect     string
	Actions    []string
	Resources  []string
	Principals []string
	Conditions map[string]any
}

// policyDocument represents an IAM policy document structure
type policyDocument struct {
	Version   string            `json:"Version"`
	Statement []policyStatement `json:"Statement"`
}

// policyStatement represents a single IAM policy statement
type policyStatement struct {
	Sid       string         `json:"Sid,omitempty"`
	Effect    string         `json:"Effect"`
	Principal any            `json:"Principal,omitempty"`
	Action    any            `json:"Action"`
	Resource  any            `json:"Resource"`
	Condition map[string]any `json:"Condition,omitempty"`
}

// ParseAWSPolicy parses an AWS IAM policy document into normalized statements
func ParseAWSPolicy(document string) ([]Statement, error) {
	if document == "" {
		return nil, nil
	}

	// URL-decode if needed (Snowflake stores some policies URL-encoded)
	if strings.Contains(document, "%7B") || strings.Contains(document, "%22") {
		if decoded, err := url.QueryUnescape(document); err == nil {
			document = decoded
		}
	}
	// Strip surrounding quotes
	document = strings.TrimSpace(document)
	if len(document) >= 2 && document[0] == '"' && document[len(document)-1] == '"' {
		document = document[1 : len(document)-1]
	}

	var doc policyDocument
	if err := json.Unmarshal([]byte(document), &doc); err != nil {
		return nil, err
	}

	statements := make([]Statement, 0, len(doc.Statement))
	for _, stmt := range doc.Statement {
		s := Statement{
			Effect:     stmt.Effect,
			Actions:    toStringSlice(stmt.Action),
			Resources:  toStringSlice(stmt.Resource),
			Principals: extractPrincipalsFromAny(stmt.Principal),
			Conditions: stmt.Condition,
		}
		statements = append(statements, s)
	}

	return statements, nil
}

func extractPrincipalsFromAny(principal any) []string {
	if principal == nil {
		return nil
	}

	switch p := principal.(type) {
	case string:
		return []string{p}
	case map[string]any:
		var principals []string
		if aws, ok := p["AWS"]; ok {
			principals = append(principals, toStringSlice(aws)...)
		}
		if svc, ok := p["Service"]; ok {
			for _, s := range toStringSlice(svc) {
				principals = append(principals, "service:"+s)
			}
		}
		if fed, ok := p["Federated"]; ok {
			principals = append(principals, toStringSlice(fed)...)
		}
		return principals
	}
	return nil
}

// TrustPrincipal represents a principal extracted from a trust policy
type TrustPrincipal struct {
	ARN        string
	Type       string // AWS, Service, Federated
	IsPublic   bool
	Conditions map[string]any
}

// ParseTrustPolicy parses an AWS IAM trust policy and extracts principals
func ParseTrustPolicy(document string) ([]TrustPrincipal, error) {
	if document == "" {
		return nil, nil
	}

	// URL-decode if needed
	if strings.Contains(document, "%7B") || strings.Contains(document, "%22") {
		if decoded, err := url.QueryUnescape(document); err == nil {
			document = decoded
		}
	}
	document = strings.TrimSpace(document)
	if len(document) >= 2 && document[0] == '"' && document[len(document)-1] == '"' {
		document = document[1 : len(document)-1]
	}

	var policy struct {
		Statement []struct {
			Effect    string
			Principal any
			Action    any
			Condition map[string]any
		}
	}

	if err := json.Unmarshal([]byte(document), &policy); err != nil {
		return nil, err
	}

	var principals []TrustPrincipal

	for _, stmt := range policy.Statement {
		if stmt.Effect != "Allow" {
			continue
		}

		// Check if action includes assume role
		if !containsAssumeAction(stmt.Action) {
			continue
		}

		extracted := extractPrincipals(stmt.Principal)
		for i := range extracted {
			extracted[i].Conditions = stmt.Condition
		}
		principals = append(principals, extracted...)
	}

	return principals, nil
}

func containsAssumeAction(action any) bool {
	assumeActions := []string{
		"sts:AssumeRole",
		"sts:AssumeRoleWithSAML",
		"sts:AssumeRoleWithWebIdentity",
	}

	switch a := action.(type) {
	case string:
		for _, aa := range assumeActions {
			if strings.EqualFold(a, aa) {
				return true
			}
		}
	case []any:
		for _, item := range a {
			if s, ok := item.(string); ok {
				for _, aa := range assumeActions {
					if strings.EqualFold(s, aa) {
						return true
					}
				}
			}
		}
	}
	return false
}

func extractPrincipals(principal any) []TrustPrincipal {
	var results []TrustPrincipal

	switch p := principal.(type) {
	case string:
		if p == "*" {
			results = append(results, TrustPrincipal{
				ARN:      "internet",
				Type:     "Public",
				IsPublic: true,
			})
		}
	case map[string]any:
		// AWS principals
		if aws, ok := p["AWS"]; ok {
			for _, arn := range toStringSlice(aws) {
				if arn == "*" {
					results = append(results, TrustPrincipal{
						ARN:      "internet",
						Type:     "Public",
						IsPublic: true,
					})
				} else {
					results = append(results, TrustPrincipal{
						ARN:  arn,
						Type: "AWS",
					})
				}
			}
		}
		// Service principals
		if svc, ok := p["Service"]; ok {
			for _, s := range toStringSlice(svc) {
				results = append(results, TrustPrincipal{
					ARN:  "service:" + s,
					Type: "Service",
				})
			}
		}
		// Federated principals (OIDC, SAML)
		if fed, ok := p["Federated"]; ok {
			for _, f := range toStringSlice(fed) {
				results = append(results, TrustPrincipal{
					ARN:  f,
					Type: "Federated",
				})
			}
		}
	}

	return results
}

func toStringSlice(v any) []string {
	switch val := v.(type) {
	case string:
		return []string{val}
	case []any:
		var result []string
		for _, item := range val {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	case []string:
		return val
	}
	return nil
}

// ActionsToEdgeKind determines the edge kind from a list of IAM actions
func ActionsToEdgeKind(actions []string) EdgeKind {
	hasAdmin := false
	hasWrite := false
	hasDelete := false

	for _, action := range actions {
		actionLower := strings.ToLower(action)
		if action == "*" || strings.HasSuffix(actionLower, ":*") || strings.Contains(actionLower, "admin") {
			hasAdmin = true
		}
		if strings.Contains(actionLower, "put") || strings.Contains(actionLower, "create") ||
			strings.Contains(actionLower, "update") || strings.Contains(actionLower, "write") {
			hasWrite = true
		}
		if strings.Contains(actionLower, "delete") || strings.Contains(actionLower, "remove") {
			hasDelete = true
		}
	}

	if hasAdmin {
		return EdgeKindCanAdmin
	}
	if hasDelete {
		return EdgeKindCanDelete
	}
	if hasWrite {
		return EdgeKindCanWrite
	}
	return EdgeKindCanRead
}
