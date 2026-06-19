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
			"references":   stringArraySchema("External or internal references for public detection catalog metadata."),
		},
	}
}

func specSchema() map[string]any {
	return map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"required":             []string{"severity", "frameworks"},
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
			"graph":          graphFindingSchema(),
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
			"input":        inputSchema(),
			"assert":       assertSchema(),
			"context":      contextSchema(),
			"evidence":     evidenceSchema(),
			"audit":        auditSchema(),
			"verification": verificationSchema(),
			"actions":      actionsSchema(),
			"enabled":      map[string]any{"type": "boolean"},
		},
		"oneOf": []map[string]any{
			{
				"required": []string{"graph"},
				"not": map[string]any{
					"anyOf": []map[string]any{
						{"required": []string{"match"}},
						{"required": []string{"assert"}},
					},
				},
			},
			{
				"anyOf": []map[string]any{
					{"required": []string{"match"}},
					{"required": []string{"assert"}},
				},
				"not": map[string]any{"required": []string{"graph"}},
			},
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

func graphFindingSchema() map[string]any {
	return map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"required":             []string{"query"},
		"properties": map[string]any{
			"query": stringSchema("Read-only Cypher query returning graph findings. Must return primary_urn."),
			"rowLimit": map[string]any{
				"type":        "integer",
				"minimum":     1,
				"maximum":     3000,
				"description": "Maximum graph rows to read for one rule evaluation.",
			},
			"params": map[string]any{
				"type":                 "object",
				"description":          "Static Cypher parameters added to tenant_id and row_limit.",
				"additionalProperties": map[string]any{"type": []string{"string", "number", "boolean", "null"}},
			},
			"requiredColumns": stringArraySchema("Additional returned aliases that the query must expose."),
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

func inputSchema() map[string]any {
	return map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"properties": map[string]any{
			"sourceKinds":    stringArraySchema("Source record kinds required to evaluate the policy."),
			"eventKinds":     stringArraySchema("Evidence or result event kinds accepted by the policy."),
			"requiredClaims": stringArraySchema("Normalized claims that must be present before evaluation."),
			"requiredFields": stringArraySchema("Fields required on every evaluated evidence record."),
			"requiredFieldsByKind": map[string]any{
				"type":                 "object",
				"additionalProperties": stringArraySchema("Fields required for this evidence kind."),
			},
			"freshnessSLA": stringSchema("Maximum acceptable evidence age, such as 24h or 14d."),
		},
	}
}

func assertSchema() map[string]any {
	assertions := map[string]any{
		"type":     "array",
		"minItems": 1,
		"items":    assertionSchema(),
	}
	return map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"properties": map[string]any{
			"all": assertions,
			"any": assertions,
		},
		"anyOf": []map[string]any{
			{"required": []string{"all"}},
			{"required": []string{"any"}},
		},
	}
}

func assertionSchema() map[string]any {
	return map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"required":             []string{"field", "op"},
		"properties": map[string]any{
			"field": stringSchema("Evidence field or normalized context path to evaluate."),
			"op": map[string]any{
				"type": "string",
				"enum": []string{"eq", "ne", "in", "not_in", "gt", "gte", "lt", "lte", "exists", "is_true", "is_false"},
			},
			"value": map[string]any{"description": "Expected comparison value for operators that need one."},
		},
	}
}

func contextSchema() map[string]any {
	return map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"properties": map[string]any{
			"graph": map[string]any{
				"type":                 "object",
				"additionalProperties": false,
				"properties": map[string]any{
					"anchors": stringArraySchema("Evidence fields that anchor graph lookup."),
					"enrich":  stringArraySchema("Graph-derived context to attach to the finding."),
				},
			},
			"severityAdjustments": map[string]any{
				"type":  "array",
				"items": severityAdjustmentSchema(),
			},
		},
	}
}

func severityAdjustmentSchema() map[string]any {
	return map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"required":             []string{"when"},
		"properties": map[string]any{
			"when": stringSchema("Expression over policy context that triggers the adjustment."),
			"set": map[string]any{
				"type": "string",
				"enum": []string{"critical", "high", "medium", "low", "info", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"},
			},
			"delta": stringSchema("Relative severity adjustment."),
		},
		"anyOf": []map[string]any{
			{"required": []string{"set"}},
			{"required": []string{"delta"}},
		},
	}
}

func evidenceSchema() map[string]any {
	return map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"properties": map[string]any{
			"type":              stringSchema("Normalized evidence type used for audit and routing."),
			"assessmentMethods": assessmentMethodsSchema(),
			"requiredForAudit":  map[string]any{"type": "boolean"},
			"freshnessSLA":      stringSchema("Maximum acceptable evidence age for this policy."),
			"acceptableSources": stringArraySchema("Authoritative systems accepted as evidence sources."),
			"requiredFields":    stringArraySchema("Fields required on collected evidence."),
			"fingerprintFields": stringArraySchema("Stable fields used to fingerprint repeated findings."),
		},
	}
}

func auditSchema() map[string]any {
	return map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"properties": map[string]any{
			"evidenceType":       stringSchema("Auditor-facing evidence type."),
			"assessmentMethods":  assessmentMethodsSchema(),
			"freshnessSLA":       stringSchema("Maximum acceptable age for auditor-facing evidence."),
			"auditorStatement":   stringSchema("Plain-language control statement for auditors."),
			"auditorGuidance":    stringSchema("Guidance for interpreting evidence and exceptions."),
			"riskStatement":      stringSchema("Risk addressed by the policy."),
			"remediationIntent":  stringSchema("Expected remediation outcome."),
			"acceptableEvidence": acceptableEvidenceSchema(),
			"exceptionPolicy":    exceptionPolicySchema(),
			"exceptionGuidance":  stringArraySchema("Accepted exception scenarios."),
			"falsePositives":     stringArraySchema("Common false-positive explanations."),
		},
	}
}

func acceptableEvidenceSchema() map[string]any {
	return map[string]any{
		"type": "array",
		"items": map[string]any{
			"type":                 "object",
			"additionalProperties": false,
			"required":             []string{"source"},
			"properties": map[string]any{
				"source": stringSchema("Authoritative evidence source."),
				"fields": stringArraySchema("Fields expected from this source."),
			},
		},
	}
}

func exceptionPolicySchema() map[string]any {
	return map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"properties": map[string]any{
			"maxAge":           stringSchema("Maximum exception age, such as 14d."),
			"requiresApproval": map[string]any{"type": "boolean"},
		},
	}
}

func verificationSchema() map[string]any {
	return map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"properties": map[string]any{
			"fixtures": map[string]any{
				"type":  "array",
				"items": verificationFixtureSchema(),
			},
			"mutationChecks":   stringArraySchema("Negative checks used to harden the policy."),
			"remediationCheck": remediationCheckSchema(),
		},
	}
}

func verificationFixtureSchema() map[string]any {
	return map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"required":             []string{"name", "expect"},
		"properties": map[string]any{
			"name":        stringSchema("Fixture identifier."),
			"expect":      map[string]any{"type": "string", "enum": []string{"finding", "pass"}},
			"description": stringSchema("What the fixture proves."),
		},
	}
}

func remediationCheckSchema() map[string]any {
	return map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"properties": map[string]any{
			"rerunAfter": stringSchema("Trigger after which the policy should be rerun."),
			"expectedStatus": map[string]any{
				"type": "string",
				"enum": []string{"pass", "finding", "closed", "open"},
			},
		},
	}
}

func actionsSchema() map[string]any {
	return map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"properties": map[string]any{
			"owner": map[string]any{
				"type":                 "object",
				"additionalProperties": false,
				"properties": map[string]any{
					"from":     stringSchema("Primary owner lookup path."),
					"fallback": stringSchema("Fallback owner lookup path."),
				},
			},
			"remediation": map[string]any{
				"type":                 "object",
				"additionalProperties": false,
				"properties": map[string]any{
					"type":  stringSchema("Remediation action type."),
					"steps": stringArraySchema("Ordered action steps."),
				},
			},
			"effort": map[string]any{"type": "string", "enum": []string{"low", "medium", "high"}},
			"blastRadius": map[string]any{
				"type":                 "object",
				"additionalProperties": false,
				"properties": map[string]any{
					"estimateFrom": stringSchema("Context path used to estimate blast radius."),
				},
			},
			"verification": map[string]any{
				"type":                 "object",
				"additionalProperties": false,
				"properties": map[string]any{
					"rerunPolicy": map[string]any{"type": "boolean"},
				},
			},
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

func assessmentMethodsSchema() map[string]any {
	return map[string]any{
		"type":        "array",
		"description": "Audit assessment methods.",
		"items": map[string]any{
			"type": "string",
			"enum": []string{"examine", "interview", "observe", "test"},
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
