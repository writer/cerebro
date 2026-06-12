package graphagent

import (
	"fmt"
	"strings"
)

type OntologyEntity struct {
	Type        string
	Description string
	Aliases     []string
	Properties  []string
	Examples    []string
}

type OntologyRelation struct {
	Relation    string
	Description string
	Aliases     []string
	FromTypes   []string
	ToTypes     []string
}

type GraphOntology struct {
	Label      string
	Entities   []OntologyEntity
	Relations  []OntologyRelation
	Properties []string
}

var canonicalGraphOntology = GraphOntology{
	Label:      "Entity",
	Properties: []string{"tenant_id", "urn", "source_id", "runtime_id", "entity_type", "label", "attributes_json"},
	Entities: []OntologyEntity{
		{
			Type:        "finding",
			Description: "Workflow finding anchors. Active findings are linked from affected resources via relation 'has_finding'.",
			Aliases:     []string{"Finding", "FINDING", "finding", "alert", "issue"},
			Properties:  []string{"urn", "label", "source_id", "runtime_id", "attributes_json"},
			Examples:    []string{"urn:cerebro:writer:finding:finding-1"},
		},
		{
			Type:        "github.code.repository",
			Description: "GitHub code repository resources emitted by code-repository events; repository metadata is stored in attributes_json.",
			Aliases:     []string{"repo", "repository", "github repo", "code repository"},
			Properties:  []string{"urn", "label", "source_id", "runtime_id", "attributes_json"},
			Examples:    []string{"urn:cerebro:writer:github_code_repository:1"},
		},
		{
			Type:        "identity.email",
			Description: "Canonical email identity anchors linked from concrete principals through represents_identity.",
			Aliases:     []string{"email identity", "canonical email", "identity email", "principal email"},
			Properties:  []string{"urn", "label", "source_id", "runtime_id", "attributes_json"},
			Examples:    []string{"urn:cerebro:writer:identity:email:alice@writer.com"},
		},
		{
			Type:        "identity.login",
			Description: "Canonical login identity anchors linked from concrete principals through represents_identity.",
			Aliases:     []string{"login identity", "canonical login", "identity login", "username identity"},
			Properties:  []string{"urn", "label", "source_id", "runtime_id", "attributes_json"},
			Examples:    []string{"urn:cerebro:writer:identity:login:alice"},
		},
		{
			Type:        "source",
			Description: "Projected source/integration nodes used for connector health. Freshness and health metadata are stored in attributes_json.",
			Aliases:     []string{"source", "source runtime", "runtime", "connector"},
			Properties:  []string{"urn", "label", "source_id", "runtime_id", "attributes_json"},
			Examples:    []string{"urn:cerebro:writer:source:github"},
		},
	},
	Relations: []OntologyRelation{
		{
			Relation:    "has_finding",
			Description: "Active edge from an affected resource Entity to a finding Entity.",
			Aliases:     []string{"HAS_FINDING", "finding", "has finding"},
			FromTypes:   []string{"*"},
			ToTypes:     []string{"finding"},
		},
		{
			Relation:    "belongs_to",
			Description: "Ownership/scope edge, such as repository to org, finding to scan, or runtime child to parent.",
			Aliases:     []string{"BELONGS_TO", "BELONGS_TO_SOURCE", "belongs to source", "source"},
			FromTypes:   []string{"*"},
			ToTypes:     []string{"*"},
		},
		{
			Relation:    "has_identifier",
			Description: "Edge from a concrete identity/resource node to a normalized identifier node.",
			Aliases:     []string{"HAS_IDENTIFIER", "identity_email", "email", "identifier"},
			FromTypes:   []string{"*"},
			ToTypes:     []string{"identifier"},
		},
		{
			Relation:    "represents_identity",
			Description: "Edge between concrete principals, identifier anchors, and canonical identity.email/identity.login nodes.",
			Aliases:     []string{"REPRESENTS_IDENTITY", "represents"},
			FromTypes:   []string{"*"},
			ToTypes:     []string{"identity.email", "identity.login"},
		},
	},
}

func (o GraphOntology) PromptHint() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Canonical Cerebro graph ontology:\n")
	fmt.Fprintf(&b, "- All graph nodes use label `%s`.\n", o.Label)
	fmt.Fprintf(&b, "- Node properties: %s.\n", strings.Join(o.Properties, ", "))
	fmt.Fprintf(&b, "- Entity types are stored in lowercase `entity_type`; never use labels like `:Finding`, `:repo`, or `:identity`.\n")
	fmt.Fprintf(&b, "- Relationships use label `RELATION` and lowercase `relation` property; never use relationship types like `:HAS_SOURCE`.\n")
	fmt.Fprintf(&b, "- Active finding shape: `(resource:Entity {tenant_id: $tenant_id})-[:RELATION {relation: 'has_finding'}]->(finding:Entity {tenant_id: $tenant_id, entity_type: 'finding'})`.\n")
	fmt.Fprintf(&b, "- Finding metadata such as `severity`, `effective_severity`, `status`, `risk_score`, `summary`, and `primary_resource_urn` is stored in `attributes_json`, not as top-level finding properties.\n")
	fmt.Fprintf(&b, "- GitHub repository metadata such as `owner_login`, `repository`, `visibility`, and `default_branch` is stored in `attributes_json`, not as top-level repository properties.\n")
	fmt.Fprintf(&b, "- Canonical identity anchors use `entity_type` values `identity.email` and `identity.login`; there is no generic `identity` entity_type or top-level `email` property. Match identity values through `urn`, `label`, or controlled `attributes_json` extraction.\n")
	fmt.Fprintf(&b, "- Connector/source health nodes use `entity_type: 'source'`; there is no `connector` entity_type and no top-level `status` or `last_sync_minutes` property. Read source health metadata from controlled `attributes_json` extraction.\n")
	fmt.Fprintf(&b, "- Finding source grouping should prefer controlled `attributes_json.source_family` string extraction, then fall back to `finding.source_id`.\n")
	for _, entity := range o.Entities {
		fmt.Fprintf(&b, "- Entity `%s`: %s Aliases: %s. Useful properties: %s.\n", entity.Type, entity.Description, strings.Join(entity.Aliases, ", "), strings.Join(entity.Properties, ", "))
		if len(entity.Examples) > 0 {
			fmt.Fprintf(&b, "  Examples: %s.\n", strings.Join(entity.Examples, ", "))
		}
	}
	for _, relation := range o.Relations {
		fmt.Fprintf(&b, "- Relation `%s`: %s Aliases: %s.\n", relation.Relation, relation.Description, strings.Join(relation.Aliases, ", "))
	}
	return strings.TrimSpace(b.String())
}

func canonicalEntityType(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	for _, entity := range canonicalGraphOntology.Entities {
		if normalized == strings.ToLower(entity.Type) {
			return entity.Type
		}
		for _, alias := range entity.Aliases {
			if normalized == strings.ToLower(alias) {
				return entity.Type
			}
		}
	}
	return normalized
}

func canonicalRelation(value string) (string, bool) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	for _, relation := range canonicalGraphOntology.Relations {
		if normalized == strings.ToLower(relation.Relation) {
			return relation.Relation, true
		}
		for _, alias := range relation.Aliases {
			if normalized == strings.ToLower(alias) {
				return relation.Relation, true
			}
		}
	}
	return normalized, false
}
