package graphagent

import (
	"fmt"
	"strings"

	"github.com/writer/cerebro/internal/fabriccontract"
	"github.com/writer/cerebro/internal/mitre"
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
			Type:        fabriccontract.EntityTypeFinding,
			Description: "Workflow finding anchors. Active findings are linked from affected resources via relation 'has_finding'.",
			Aliases:     []string{"Finding", "FINDING", "finding", "alert", "issue"},
			Properties:  []string{"urn", "label", "source_id", "runtime_id", "attributes_json"},
			Examples:    []string{"urn:cerebro:writer:finding:finding-1"},
		},
		{
			Type:        mitre.AttackTacticEntityType,
			Description: "MITRE ATT&CK tactic nodes linked from findings, controls, resources, and ATT&CK techniques.",
			Aliases:     []string{"attack tactic", "MITRE tactic", "ATT&CK tactic", "mitre attack tactic"},
			Properties:  []string{"urn", "label", "source_id", "attributes_json"},
			Examples:    []string{"urn:cerebro:writer:mitre_attack_tactic:TA0001"},
		},
		{
			Type:        mitre.AttackTechniqueEntityType,
			Description: "MITRE ATT&CK technique nodes linked from findings, controls, resources, coverage nodes, data components, and D3FEND techniques.",
			Aliases:     []string{"attack technique", "MITRE technique", "ATT&CK technique", "mitre attack technique"},
			Properties:  []string{"urn", "label", "source_id", "attributes_json"},
			Examples:    []string{"urn:cerebro:writer:mitre_attack_technique:T1190"},
		},
		{
			Type:        mitre.AttackCoverageEntityType,
			Description: "ATT&CK coverage nodes that connect a finding, control, tool, or resource to a technique and evidence data components.",
			Aliases:     []string{"attack coverage", "MITRE coverage", "ATT&CK coverage", "coverage gap"},
			Properties:  []string{"urn", "label", "source_id", "attributes_json"},
			Examples:    []string{"urn:cerebro:writer:mitre_attack_coverage:abc123"},
		},
		{
			Type:        mitre.AttackDataSourceEntityType,
			Description: "MITRE ATT&CK data source nodes such as Process, Application Log, or Network Traffic.",
			Aliases:     []string{"attack data source", "MITRE data source", "ATT&CK data source"},
			Properties:  []string{"urn", "label", "source_id", "attributes_json"},
			Examples:    []string{"urn:cerebro:writer:mitre_attack_data_source:DS0015"},
		},
		{
			Type:        mitre.AttackDataComponentEntityType,
			Description: "MITRE ATT&CK data component nodes that support detection or coverage for a technique.",
			Aliases:     []string{"attack data component", "MITRE data component", "ATT&CK data component", "detection data component"},
			Properties:  []string{"urn", "label", "source_id", "attributes_json"},
			Examples:    []string{"urn:cerebro:writer:mitre_attack_data_component:DS0015%3AApplication%20Log%20Content"},
		},
		{
			Type:        mitre.DefendTacticEntityType,
			Description: "MITRE D3FEND tactic nodes linked from findings or source facts when defensive tactic metadata is present.",
			Aliases:     []string{"d3fend tactic", "defend tactic", "MITRE D3FEND tactic"},
			Properties:  []string{"urn", "label", "source_id", "attributes_json"},
			Examples:    []string{"urn:cerebro:writer:mitre_defend_tactic:Harden"},
		},
		{
			Type:        mitre.DefendTechniqueEntityType,
			Description: "MITRE D3FEND technique nodes. These support ATT&CK techniques through defensive relationship edges.",
			Aliases:     []string{"d3fend technique", "defend technique", "MITRE D3FEND technique"},
			Properties:  []string{"urn", "label", "source_id", "attributes_json"},
			Examples:    []string{"urn:cerebro:writer:mitre_defend_technique:InboundTrafficFiltering"},
		},
		{
			Type:        mitre.DefendArtifactEntityType,
			Description: "MITRE D3FEND artifact nodes linked from D3FEND techniques or findings when defensive artifact metadata is present.",
			Aliases:     []string{"d3fend artifact", "defend artifact", "MITRE D3FEND artifact"},
			Properties:  []string{"urn", "label", "source_id", "attributes_json"},
			Examples:    []string{"urn:cerebro:writer:mitre_defend_artifact:WebServer"},
		},
		{
			Type:        fabriccontract.EntityTypeGithubCodeRepository,
			Description: "GitHub code repository resources emitted by code-repository events; repository metadata is stored in attributes_json.",
			Aliases:     []string{"repo", "repository", "github repo", "code repository"},
			Properties:  []string{"urn", "label", "source_id", "runtime_id", "attributes_json"},
			Examples:    []string{"urn:cerebro:writer:github_code_repository:1"},
		},
		{
			Type:        fabriccontract.EntityTypeIdentityEmail,
			Description: "Canonical email identity anchors linked from concrete principals through represents_identity.",
			Aliases:     []string{"email identity", "canonical email", "identity email", "principal email"},
			Properties:  []string{"urn", "label", "source_id", "runtime_id", "attributes_json"},
			Examples:    []string{"urn:cerebro:writer:identity:email:alice@writer.com"},
		},
		{
			Type:        fabriccontract.EntityTypeIdentityLogin,
			Description: "Canonical login identity anchors linked from concrete principals through represents_identity.",
			Aliases:     []string{"login identity", "canonical login", "identity login", "username identity"},
			Properties:  []string{"urn", "label", "source_id", "runtime_id", "attributes_json"},
			Examples:    []string{"urn:cerebro:writer:identity:login:alice"},
		},
		{
			Type:        "identifier.email",
			Description: "Email identifier evidence nodes linked from concrete principals and canonical identity.email anchors. Use them as join evidence, not as person records.",
			Aliases:     []string{"email identifier", "identifier email", "raw email"},
			Properties:  []string{"urn", "label", "source_id", "runtime_id", "attributes_json"},
			Examples:    []string{"urn:cerebro:writer:identifier:email:alice@writer.com"},
		},
		{
			Type:        "identifier.login",
			Description: "Login identifier evidence nodes linked from concrete principals and canonical identity.login anchors. Use them as join evidence, not as account records.",
			Aliases:     []string{"login identifier", "identifier login", "username identifier"},
			Properties:  []string{"urn", "label", "source_id", "runtime_id", "attributes_json"},
			Examples:    []string{"urn:cerebro:writer:identifier:login:alice"},
		},
		{
			Type:        "endpoint.identifier",
			Description: "Endpoint-scoped identifier evidence nodes such as serial numbers, hostnames, or device owner identifiers.",
			Aliases:     []string{"endpoint identifier", "device identifier", "host identifier"},
			Properties:  []string{"urn", "label", "source_id", "runtime_id", "attributes_json"},
			Examples:    []string{"urn:cerebro:writer:endpoint_identifier:serial_number:serial1"},
		},
		{
			Type:        fabriccontract.EntityTypeSource,
			Description: "Projected source/integration nodes used for connector health. Freshness and health metadata are stored in attributes_json.",
			Aliases:     []string{"source", "source runtime", "runtime", "connector"},
			Properties:  []string{"urn", "label", "source_id", "runtime_id", "attributes_json"},
			Examples:    []string{"urn:cerebro:writer:source:github"},
		},
		{
			Type:        "okta.user",
			Description: "Okta user principals. Lifecycle, MFA summary, employment/profile hints, source_event_id, and observed_at are stored in attributes_json; promoted booleans such as is_privileged_identity and mfa_disabled may exist as indexed node properties.",
			Aliases:     []string{"okta user", "Okta user", "Okta principal", "identity user"},
			Properties:  []string{"urn", "label", "source_id", "runtime_id", "attributes_json"},
			Examples:    []string{"urn:cerebro:writer:okta_user:00u1"},
		},
		{
			Type:        "okta.group",
			Description: "Okta groups linked from users by member_of and to Okta applications by assigned_to when group app assignments are projected.",
			Aliases:     []string{"okta group", "Okta group", "identity group"},
			Properties:  []string{"urn", "label", "source_id", "runtime_id", "attributes_json"},
			Examples:    []string{"urn:cerebro:writer:okta_group:grp-security"},
		},
		{
			Type:        "okta.application",
			Description: "Okta applications. Application metadata is in attributes_json; app-local permissions are available only when projected as okta.entitlement capability paths.",
			Aliases:     []string{"okta app", "Okta app", "Okta application", "application"},
			Properties:  []string{"urn", "label", "source_id", "runtime_id", "attributes_json"},
			Examples:    []string{"urn:cerebro:writer:okta_application:app-1"},
		},
		{
			Type:        "okta.role",
			Description: "Non-admin Okta role resources assigned to users or groups with assigned_to. Privileged administrator roles are represented as okta.admin_role and reached with can_admin.",
			Aliases:     []string{"okta role", "Okta role", "non-admin role"},
			Properties:  []string{"urn", "label", "source_id", "runtime_id", "attributes_json"},
			Examples:    []string{"urn:cerebro:writer:okta_role:role-1"},
		},
		{
			Type:        "okta.admin_role",
			Description: "Okta admin role assignments and role resources. Users link to these with can_admin for privileged administrator access.",
			Aliases:     []string{"okta admin role", "Okta admin role", "privileged role"},
			Properties:  []string{"urn", "label", "source_id", "runtime_id", "attributes_json"},
			Examples:    []string{"urn:cerebro:writer:okta_admin_role:SUPER_ADMIN"},
		},
		{
			Type:        "okta.entitlement",
			Description: "Projected Okta app or role entitlement nodes. These grant privileged.capability nodes; do not infer app-local entitlements beyond what this path exposes.",
			Aliases:     []string{"okta entitlement", "Okta entitlement", "app entitlement"},
			Properties:  []string{"urn", "label", "source_id", "runtime_id", "attributes_json"},
			Examples:    []string{"urn:cerebro:writer:okta_entitlement:app_assignment:app-1"},
		},
		{
			Type:        "privileged.capability",
			Description: "Normalized capability nodes conferred by source entitlements, such as app_access, identity_admin, or cloud_admin.",
			Aliases:     []string{"capability", "privileged capability", "access capability"},
			Properties:  []string{"urn", "label", "source_id", "runtime_id", "attributes_json"},
			Examples:    []string{"urn:cerebro:writer:privileged_capability:identity_admin"},
		},
		{
			Type:        "policy",
			Description: "GRC policy, control, and policy-document anchors. Control nodes use attributes_json.policy_type = 'control'.",
			Aliases:     []string{"control", "grc control", "policy", "policy document"},
			Properties:  []string{"urn", "label", "source_id", "runtime_id", "attributes_json"},
			Examples:    []string{"urn:cerebro:writer:policy:control:ac-1"},
		},
		{
			Type:        "runtime_evidence",
			Description: "Runtime evidence object linked from a source fact, policy, control, or assurance artifact through has_evidence.",
			Aliases:     []string{"runtime evidence", "evidence packet", "source evidence"},
			Properties:  []string{"urn", "label", "source_id", "runtime_id", "attributes_json"},
			Examples:    []string{"urn:cerebro:writer:runtime_evidence:evidence-1"},
		},
		{
			Type:        "evidence",
			Description: "Attached or imported evidence object linked from GRC artifacts, controls, source facts, and assurance documents through has_evidence.",
			Aliases:     []string{"evidence", "attached evidence", "uploaded evidence"},
			Properties:  []string{"urn", "label", "source_id", "runtime_id", "attributes_json"},
			Examples:    []string{"urn:cerebro:writer:evidence:evidence-1"},
		},
		{
			Type:        "security.questionnaire",
			Description: "GRC security questionnaire artifacts linked to controls, accounts, documents, and evidence through projected relations.",
			Aliases:     []string{"questionnaire", "security questionnaire"},
			Properties:  []string{"urn", "label", "source_id", "runtime_id", "attributes_json"},
			Examples:    []string{"urn:cerebro:writer:security_questionnaire:questionnaire-1"},
		},
		{
			Type:        "assurance.document",
			Description: "Assurance and policy document evidence used for questionnaire answers and control support.",
			Aliases:     []string{"assurance document", "policy doc", "document"},
			Properties:  []string{"urn", "label", "source_id", "runtime_id", "attributes_json"},
			Examples:    []string{"urn:cerebro:writer:assurance_document:soc2-report"},
		},
	},
	Relations: []OntologyRelation{
		{
			Relation:    fabriccontract.RelationHasFinding,
			Description: "Active edge from an affected resource Entity to a finding Entity.",
			Aliases:     []string{"HAS_FINDING", "finding", "has finding"},
			FromTypes:   []string{"*"},
			ToTypes:     []string{"finding"},
		},
		{
			Relation:    fabriccontract.RelationBelongsTo,
			Description: "Ownership/scope edge, such as repository to org, finding to scan, or runtime child to parent.",
			Aliases:     []string{"BELONGS_TO", "BELONGS_TO_SOURCE", "belongs to source", "source"},
			FromTypes:   []string{"*"},
			ToTypes:     []string{"*"},
		},
		{
			Relation:    fabriccontract.RelationHasContext,
			Description: "Context edge from a resource Entity to supporting repository, runtime, or library-note context.",
			Aliases:     []string{"HAS_CONTEXT", "repository context", "library context"},
			FromTypes:   []string{"*"},
			ToTypes:     []string{"*"},
		},
		{
			Relation:    fabriccontract.RelationHasIdentifier,
			Description: "Edge from a concrete identity/resource node to a normalized identifier node.",
			Aliases:     []string{"HAS_IDENTIFIER", "identity_email", "email", "identifier"},
			FromTypes:   []string{"*"},
			ToTypes:     []string{"identifier.email", "identifier.login", "endpoint.identifier"},
		},
		{
			Relation:    fabriccontract.RelationRepresentsIdentity,
			Description: "Edge between concrete principals, identifier anchors, and canonical identity.email/identity.login nodes.",
			Aliases:     []string{"REPRESENTS_IDENTITY", "represents"},
			FromTypes:   []string{"*"},
			ToTypes:     []string{"identity.email", "identity.login"},
		},
		{
			Relation:    fabriccontract.RelationMemberOf,
			Description: "Membership edge from an identity principal to a group; edge attributes carry event/source provenance.",
			Aliases:     []string{"MEMBER_OF", "group membership", "member of"},
			FromTypes:   []string{"okta.user"},
			ToTypes:     []string{"okta.group"},
		},
		{
			Relation:    fabriccontract.RelationAssignedTo,
			Description: "Assignment edge from a user or group to an application, or from a principal to a non-admin role; edge attributes carry event/source provenance.",
			Aliases:     []string{"ASSIGNED_TO", "app assignment", "assigned to"},
			FromTypes:   []string{"okta.user", "okta.group"},
			ToTypes:     []string{"okta.application", "okta.role"},
		},
		{
			Relation:    fabriccontract.RelationCanAdmin,
			Description: "Privileged admin assignment edge from a user to an admin role; edge attributes carry event/source provenance.",
			Aliases:     []string{"CAN_ADMIN", "admin role assignment", "administrator"},
			FromTypes:   []string{"okta.user"},
			ToTypes:     []string{"okta.admin_role"},
		},
		{
			Relation:    fabriccontract.RelationGrantsEntitlement,
			Description: "Edge from an application or role to a projected entitlement. Use this before claiming an access capability.",
			Aliases:     []string{"GRANTS_ENTITLEMENT", "grants entitlement"},
			FromTypes:   []string{"okta.application", "okta.admin_role"},
			ToTypes:     []string{"okta.entitlement"},
		},
		{
			Relation:    fabriccontract.RelationConfersCapability,
			Description: "Edge from a projected entitlement to a normalized capability. Capabilities are source-backed, not inferred app-local permissions.",
			Aliases:     []string{"CONFERS_CAPABILITY", "confers capability"},
			FromTypes:   []string{"okta.entitlement"},
			ToTypes:     []string{"privileged.capability"},
		},
		{
			Relation:    fabriccontract.RelationSupports,
			Description: "Evidence, policy, questionnaire, source-fact, ATT&CK data component, coverage, or D3FEND edge to the control or object it supports.",
			Aliases:     []string{"SUPPORTS", "control support", "mapped control", "defends against", "detects attack technique"},
			FromTypes:   []string{"*"},
			ToTypes:     []string{"policy", mitre.AttackTechniqueEntityType},
		},
		{
			Relation:    fabriccontract.RelationHasEvidence,
			Description: "Resource, GRC artifact, or ATT&CK coverage edge to runtime evidence, attached evidence, or ATT&CK data components.",
			Aliases:     []string{"HAS_EVIDENCE", "evidence", "source evidence", "coverage evidence"},
			FromTypes:   []string{"*"},
			ToTypes:     []string{"runtime_evidence", "evidence", mitre.AttackDataComponentEntityType},
		},
		{
			Relation:    fabriccontract.RelationAssociatedWith,
			Description: "Association edge between GRC artifacts, findings, accounts, and related source objects.",
			Aliases:     []string{"ASSOCIATED_WITH", "associated", "related"},
			FromTypes:   []string{"*"},
			ToTypes:     []string{"*"},
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
	fmt.Fprintf(&b, "- MITRE ATT&CK/D3FEND graph context uses `mitre.attack.*` and `mitre.defend.*` entity types. Findings, controls, tools, and resources link to explicit ATT&CK/D3FEND context with `has_context`; ATT&CK coverage nodes link to techniques with `supports` and to data components with `has_evidence`; D3FEND techniques link to ATT&CK techniques with `supports` when the relationship attribute is `defends_against`.\n")
	fmt.Fprintf(&b, "- Okta access-review evidence is graph-shaped: use `okta.user` -> `okta.group` via `member_of`, user/group -> `okta.application` via `assigned_to`, user -> `okta.admin_role` via `can_admin`, and application/admin-role -> `okta.entitlement` -> `privileged.capability` before claiming app, admin, or privileged capability access.\n")
	fmt.Fprintf(&b, "- Okta lifecycle and MFA fields such as `status`, `last_login_at`, `mfa_enrolled`, `mfa_factor_count`, `mfa_factor_types`, `mfa_phishing_resistant`, `source_event_id`, and `observed_at` live in `attributes_json`; do not treat missing factor detail as proof of weak MFA or infer contractor approval from Okta profile hints alone.\n")
	fmt.Fprintf(&b, "- Questionnaire answers must start from bounded graph evidence: controls are `policy` nodes with `attributes_json.policy_type = 'control'`, support links use relation `supports`, evidence links use relation `has_evidence`, and policy/source freshness metadata lives in `attributes_json`.\n")
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
