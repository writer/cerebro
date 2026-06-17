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
            implementation_guidance:
              - Require privileged identities to enroll MFA before production access is granted.
            audit_procedure:
              - Compare privileged account inventory with current MFA enrollment evidence.
            failure_modes:
              - Privileged user has active production access without enrolled MFA.
            remediation_guidance:
              - Remove privileged access until MFA enrollment is complete.
            exception_guidance: Time-bound exceptions require compensating monitoring and approval.
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

Required fields are intentionally small for compatibility: catalog `version`, framework `name`, family `id` and `name`, and control `id`. Rich controls should add `title`, `objective`, `intent`, `assessment_methods`, `implementation_guidance`, `audit_procedure`, `failure_modes`, `remediation_guidance`, `evidence_expectations`, and `maps_to` as soon as they are known.

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

## Control Extension Packs

Control extension packs are YAML manifests that package custom catalog and profile files together. This gives custom framework work a single generated-coverage entrypoint while keeping the actual control catalog YAML separate and reviewable.

```yaml
version: "2026-06-17"
id: customer-controls
name: Customer Controls
description: Custom framework and reusable audit selections.
catalogs:
  - controls.yaml
profiles:
  - profiles.yaml
```

Manifest paths are resolved relative to the manifest file. Use an extension pack when a customer, business unit, or product surface needs its own control IDs and profile selections:

```bash
go run ./tools/controlindex \
  --extension customer-controls/extension.yaml \
  --profile customer-security-audit \
  --output customer-controls/coverage.yaml \
  --write
```

The generator merges extension catalogs with the built-in catalog, merges extension profile sets with the built-in profiles, validates all `maps_to` references, and emits a coverage index for every selected profile. Repeat `--profile` to generate a packet for only the requested profile IDs. Included profiles remain available for `include_profiles` composition, but only explicitly requested profile IDs are emitted. Filtered profile output requires an explicit `--output` so the built-in canonical coverage index remains a complete all-profile index.

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
include_applicability: [production]
include_assessment_methods: [examine, test]
automatable: true
manual_evidence_allowed: true
exclude_controls:
  - framework_name: SOC 2
    control_id: CC6.2
```

Selections can include whole frameworks, families, explicit controls, tags, owner domains, evidence types, applicability labels, assessment methods, automatable controls, and controls that allow or disallow manual evidence. Assessment method filters match both control-level methods and expectation-level methods. Exclusions are applied last. An empty selection resolves to the full merged catalog, which is useful for completeness checks.

## Control Profiles

Control profiles are reusable YAML selections. The built-in profile set lives at `internal/compliance/control_profiles.yaml`; each profile uses the same fields as a `ControlSelection`.

```yaml
version: "2026-06-17"
profiles:
  - id: customer-production-access
    name: Customer Production Access
    description: Production identity and privileged-access scope for customer audit evidence.
    include_profiles: [soc2-security-core]
    frameworks:
      - name: Customer Audit 2026
        controls: [IAM-1]
    include_applicability: [production]
    include_assessment_methods: [examine, test]
```

Use profiles for common auditor views, control subsets, custom framework launches, or product-packaged compliance views. Custom frameworks can ship their own profile YAML beside their control pack and use the same resolver APIs.

Profiles can compose other profiles with `include_profiles`. Included profiles are resolved independently and unioned with the including profile, so each reusable selection keeps its own framework, tag, owner, evidence, applicability, and assessment-method semantics. The including profile's `exclude_controls` and `exclude_tags` are applied after the union, which lets teams build broad audit packets and then remove customer-irrelevant controls without copying the source profile definitions.

```yaml
version: "2026-06-17"
profiles:
  - id: customer-security-audit
    name: Customer Security Audit
    include_profiles:
      - soc2-security-core
      - cloud-security-benchmarks
    frameworks:
      - name: Customer Audit 2026
        controls: [IAM-1]
    exclude_controls:
      - framework_name: SOC 2
        control_id: CC6.2
```

Use composition for customer audit packets, internal control programs, product-specific compliance views, or custom framework launches that need to combine several built-in control groups with customer-specific controls.

## Coverage Resolution

Coverage is resolved in two steps:

1. Resolve a `ControlSelection` into concrete controls from the catalog index.
2. Compare selected controls and their `maps_to` aliases with rule `ControlRefs`.

The result reports selected control count, mapped rule IDs, controls without rule coverage, rules by control, and controls by rule. This is the foundation for later control posture and auditor evidence packets.

`BuildControlCoverageIndex` applies this process to a full profile set. The checked-in `internal/compliance/control_coverage_index.yaml` is generated from the built-in profiles and builtin rule metadata. It gives reviewers a stable YAML view of selected controls, coverage status, rule counts, mapped rules, mapped equivalent controls, evidence expectations, unmapped controls, and per-profile coverage summaries.

Regenerate and verify the index with:

```bash
make control-index-generate
make control-index-check
```

## Control Posture

Control posture turns a selected control scope into an auditor-facing operating status. It combines:

- selected controls from `ResolveControlSelection`
- rule coverage from `ResolveRuleCoverage`
- open finding signals
- evidence signals
- assessment overrides for exceptions, manual review, and not-applicable scope decisions

`EvaluateControlPosture` returns one `ControlPosture` per selected control. Evidence and findings can attach directly to the selected control, to a mapped control reference, or to a mapped rule ID. This lets custom framework controls receive posture credit from existing generated rules while preserving the customer-facing control ID in the output.

Statuses are intentionally ordered for audit review:

| Status | Meaning |
| --- | --- |
| `not_applicable` | An active scope override says the control does not apply to this assessment. |
| `exception` | An active exception or compensating-control approval covers the selected control. |
| `failing` | One or more open findings map to the selected control. |
| `missing_evidence` | Required evidence expectations are not present. |
| `stale_evidence` | Evidence exists but is older than the control or evidence freshness window. |
| `manual_review` | Evidence exists, but interview/manual assessment is still required before reliance. |
| `passing` | Required evidence is present and no open findings are mapped to the control. |

The posture output keeps control identity, finding IDs, evidence IDs, freshness data, and exception/not-applicable IDs in separate nested blocks. It includes mapped rule IDs, open finding IDs, evidence IDs, missing or stale evidence expectation IDs, exception/not-applicable IDs, freshness SLA, latest evidence time, and evidence due date. `SummarizeControlPosture` aggregates the posture list into counts by status for dashboard and report headers.

## Evidence Packets

`BuildControlEvidencePacket` turns the same posture input into an auditor-facing packet. The packet includes a generated timestamp, posture summary, one entry per selected control, full open-finding details, usable evidence items, expectation-level status, mapped rules, and active exception or not-applicable overrides.

Expectation status makes evidence gaps explicit:

| Status | Meaning |
| --- | --- |
| `satisfied` | Matching evidence exists and is inside the freshness window. |
| `missing` | Required evidence is not present. |
| `stale` | Matching evidence exists but is expired or outside the freshness window. |
| `optional` | The expectation is not required and no matching evidence was supplied. |

The packet builder uses the same matching rules as posture evaluation. Evidence and findings can be connected by selected control ref, mapped control ref, or mapped rule ID, so custom framework controls can keep their own IDs while still collecting evidence generated by existing rules.

## Validation

`go run ./tools/catalogcheck` validates the built-in control pack and policy mappings. The shared compliance package also exposes:

- `LoadControlCatalog` and `LoadControlCatalogFiles`
- `MergeControlCatalogs`
- `BuildCatalogIndex`
- `LoadControlSelection`
- `ResolveControlSelection`
- `ResolveRuleCoverage`
- `LoadControlProfileSet`
- `LoadControlExtensionPack`
- `ValidateControlExtensionPack`
- `MergeControlProfileSets`
- `ResolveControlProfiles`
- `BuildControlCoverageIndex`
- `EvaluateControlPosture`
- `SummarizeControlPosture`
- `BuildControlEvidencePacket`

Run focused checks after changing control authoring code:

```bash
go test ./internal/compliance ./tools/catalogcheck
go run ./tools/catalogcheck -summary=false
go run ./tools/controlindex --check
```
