package findingdsl

import "encoding/json"

const PolicyRuleSchemaRelPath = "schemas/policy-finding-rule.schema.json"

func PolicyRuleJSONSchema() ([]byte, error) {
	schema := map[string]any{
		"$schema":              "https://json-schema.org/draft/2020-12/schema",
		"$id":                  "https://cerebro.writer.com/schemas/policy-finding-rule.schema.json",
		"title":                "Cerebro PolicyFindingRule",
		"description":          "Authoring schema for generated Cerebro policy finding rules.",
		"type":                 "object",
		"additionalProperties": false,
		"required":             []string{"apiVersion", "kind", "metadata", "spec"},
		"properties": map[string]any{
			"apiVersion": map[string]any{"const": APIVersion},
			"kind":       map[string]any{"const": KindPolicyFindingRule},
			"metadata":   metadataSchema(),
			"spec":       specSchema(),
		},
	}
	return json.MarshalIndent(schema, "", "  ")
}

func metadataSchema() map[string]any {
	return map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"required":             []string{"id", "name", "description"},
		"properties": map[string]any{
			"id": map[string]any{
				"type":        "string",
				"pattern":     "^[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*$",
				"description": "Stable policy and generated rule identifier.",
			},
			"name":         stringSchema("Human-readable policy name."),
			"description":  stringSchema("What the policy checks and why it matters."),
			"lastModified": stringSchema("Source policy timestamp for imported catalogs."),
			"tags":         stringArraySchema("Tags for categorization, routing, and catalog search."),
		},
	}
}

func specSchema() map[string]any {
	return map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"required":             []string{"severity", "match", "frameworks"},
		"properties": map[string]any{
			"severity": map[string]any{
				"type": "string",
				"enum": []string{"critical", "high", "medium", "low", "info", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"},
			},
			"category":       stringSchema("Optional generated policy category override."),
			"effect":         stringSchema("Policy effect, usually forbid for CEL-backed policies."),
			"principal":      stringSchema("Principal selector metadata for access-control-style policies."),
			"action":         stringSchema("Action selector metadata for access-control-style policies."),
			"resource":       stringSchema("Resource selector or resource family."),
			"resourceType":   stringSchema("Human-readable resource type."),
			"match":          matchSchema(),
			"remediation":    remediationSchema(),
			"riskCategories": stringArraySchema("Normalized risk category labels."),
			"frameworks": map[string]any{
				"type":     "array",
				"minItems": 1,
				"items":    frameworkSchema(),
			},
			"mitreAttack": map[string]any{
				"type":  "array",
				"items": mitreSchema(),
			},
			"enabled": map[string]any{"type": "boolean"},
		},
		"oneOf": []map[string]any{
			{"required": []string{"match"}},
		},
	}
}

func matchSchema() map[string]any {
	return map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"properties": map[string]any{
			"conditions": map[string]any{
				"type":     "array",
				"minItems": 1,
				"items":    stringSchema("CEL-style policy condition expression."),
			},
			"conditionFormat": map[string]any{"type": "string", "enum": []string{"cel"}},
			"query":           stringSchema("Query that returns failing rows for query-backed policies."),
		},
		"oneOf": []map[string]any{
			{"required": []string{"conditions"}},
			{"required": []string{"query"}},
		},
	}
}

func remediationSchema() map[string]any {
	return map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"properties": map[string]any{
			"summary": stringSchema("Short remediation intent."),
			"steps":   stringArraySchema("Ordered remediation steps."),
		},
	}
}

func frameworkSchema() map[string]any {
	return map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"required":             []string{"name", "controls"},
		"properties": map[string]any{
			"name": stringSchema("Compliance framework name."),
			"controls": map[string]any{
				"type":     "array",
				"minItems": 1,
				"items":    stringSchema("Framework control identifier."),
			},
		},
	}
}

func mitreSchema() map[string]any {
	return map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"properties": map[string]any{
			"tactic":    stringSchema("MITRE ATT&CK tactic."),
			"technique": stringSchema("MITRE ATT&CK technique."),
		},
	}
}

func stringArraySchema(description string) map[string]any {
	return map[string]any{
		"type":        "array",
		"description": description,
		"items":       stringSchema(""),
	}
}

func stringSchema(description string) map[string]any {
	schema := map[string]any{"type": "string"}
	if description != "" {
		schema["description"] = description
	}
	return schema
}
