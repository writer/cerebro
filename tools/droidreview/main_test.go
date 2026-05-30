package main

import "testing"

func TestSuspiciousCypherTokenIgnoresGuardrailGuidance(t *testing.T) {
	const guardrail = `Rules:
- Generate read-only Cypher only.
- Do not use CREATE, MERGE, DELETE, REMOVE, SET, DROP, FOREACH, LOAD CSV, USING PERIODIC, apoc.trigger, or apoc.periodic.
- Always include a numeric LIMIT <= 100.`

	if got := suspiciousCypherToken(guardrail); got != "" {
		t.Fatalf("suspiciousCypherToken() = %q, want no finding for guardrail prose", got)
	}
}

func TestSuspiciousCypherTokenFlagsWriteQueryLiterals(t *testing.T) {
	query := "MATCH (n) LOAD CSV FROM 'file:///tmp.csv' AS row RETURN row LIMIT 1"

	if got := suspiciousCypherToken(query); got != "LOAD CSV" {
		t.Fatalf("suspiciousCypherToken() = %q, want LOAD CSV", got)
	}
}
