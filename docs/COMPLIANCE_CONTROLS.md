# Compliance Controls

Cerebro stores compliance controls as YAML control packs. The built-in pack lives at `internal/compliance/control_families.yaml`; custom packs should use the same schema and can be merged with the built-in pack before validation.

The control pack is intentionally richer than a tag list. A control can describe what it is meant to prove, what evidence is acceptable, how fresh that evidence should be, and which other controls it maps to. Findings and generated policy rules still carry `ControlRefs`; the compliance package resolves those refs into selected controls and coverage.

## Control Pack Shape

```yaml
version: "2026-06-17"
frameworks:
  - id: customer-audit-2026
    name: Customer Audit 2026
    framework_version: "2026"
    tags: [customer_audit]
    families:
      - id: IAM
        name: Identity Controls
        tags: [identity]
        controls:
          - id: IAM-1
            title: Privileged access requires MFA
            objective: Privileged users authenticate with phishing-resistant MFA.
            intent: Reduce account takeover risk for administrative access.
            applicability: [production, privileged_access]
            assessment_methods: [examine, test]
            owner_domain: identity
            automatable: true
            manual_evidence_allowed: true
            freshness_sla: 30d
            tags: [mfa, privileged_access]
            evidence_expectations:
              - id: privileged-mfa-state
                type: identity_configuration
                description: MFA posture for privileged users.
                required: true
                assessment_methods: [examine]
                freshness_sla: 30d
                accepted_from: [okta, github]
            maps_to:
              - framework_name: SOC 2
                control_id: CC6.1
```

Required fields are intentionally small for compatibility: catalog `version`, framework `name`, family `id` and `name`, and control `id`. Rich controls should add `title`, `objective`, `intent`, `assessment_methods`, `evidence_expectations`, and `maps_to` as soon as they are known.

Assessment methods are limited to `examine`, `interview`, and `test`. Evidence expectations require `id` and `type` when present. `maps_to` entries must reference controls that exist in the merged catalog.

## Custom Frameworks

Custom frameworks should be separate YAML packs with stable framework IDs. Load and merge them with the built-in pack before building the catalog index:

```go
catalog, err := compliance.LoadControlCatalogFiles(
	"internal/compliance/control_families.yaml",
	"customer/control_pack.yaml",
)
index, issues := compliance.BuildCatalogIndex(catalog)
```

Use `maps_to` to connect custom controls to controls already covered by generated policy rules. Rule coverage resolution credits the selected custom control when a rule maps to any equivalent control in `maps_to`.

## Control Selections

A control selection is a named scope for a report, audit request, customer questionnaire, internal review, or compliance program view.

```yaml
id: customer-audit-security
name: Customer Audit Security Scope
frameworks:
  - name: Customer Audit 2026
    controls: [IAM-1]
include_tags: [identity]
include_owner_domains: [identity]
include_evidence_types: [identity_configuration]
exclude_controls:
  - framework_name: SOC 2
    control_id: CC6.2
```

Selections can include whole frameworks, families, explicit controls, tags, owner domains, and evidence types. Exclusions are applied last. An empty selection resolves to the full merged catalog, which is useful for completeness checks.

## Coverage Resolution

Coverage is resolved in two steps:

1. Resolve a `ControlSelection` into concrete controls from the catalog index.
2. Compare selected controls and their `maps_to` aliases with rule `ControlRefs`.

The result reports selected control count, mapped rule IDs, controls without rule coverage, rules by control, and controls by rule. This is the foundation for later control posture and auditor evidence packets.

## Validation

`go run ./tools/catalogcheck` validates the built-in control pack and policy mappings. The shared compliance package also exposes:

- `LoadControlCatalog` and `LoadControlCatalogFiles`
- `MergeControlCatalogs`
- `BuildCatalogIndex`
- `LoadControlSelection`
- `ResolveControlSelection`
- `ResolveRuleCoverage`

Run focused checks after changing control authoring code:

```bash
go test ./internal/compliance ./tools/catalogcheck
go run ./tools/catalogcheck -summary=false
```
