# Cerebro Policy Finding DSL

## Overview

The `policies/` tree is the checked-in authoring catalog for generated policy findings. Policy findings are authored as validated `PolicyFindingRule` YAML DSL documents. The only JSON file that remains under `policies/` is the non-finding control mapping at `policies/cerebro/control-mapping.json`.

Policies are generated into Go rule definitions in `internal/findings/policy_rule_catalog_gen.go` with `make policy-rule-generate`. The generated policy rules register in the built-in `policy` rule pack, publish auditor-facing control refs in `internal/findings/public_detection_catalog.json`, and evaluate either dedicated `policy.evidence` / `policy.result` events that identify a failed `policy_id`, `check_id`, or `rule_id`, or bounded graph queries that emit graph-anchored policy findings.

Generated rule copy, evidence type, assessment methods, false-positive guidance, and auditor notes are enriched from `internal/compliance/policy_rule_extensions.yaml`; see `docs/domains/policy-rule-extensions.md`. Control pack authoring, custom frameworks, and selected control coverage are documented in `docs/domains/compliance-controls.md`.

Editor integrations can use the generated JSON Schema at `schemas/policy-finding-rule.schema.json`.

## Basic Policy

```yaml
apiVersion: cerebro.writer.com/v1alpha1
kind: PolicyFindingRule
metadata:
  id: aws-s3-bucket-no-public-access
  name: S3 Bucket Public Access Block
  description: S3 buckets should have public access blocked at the bucket level.
  tags: [aws, s3, data-protection]
spec:
  severity: critical
  effect: forbid
  resource: aws::s3::bucket
  match:
    conditionFormat: cel
    conditions:
      - cmp_eq(path(resource, "block_public_acls"), false)
  remediation:
    summary: Enable S3 public access block settings at the account and bucket level.
  riskCategories:
    - EXTERNAL_EXPOSURE
    - UNPROTECTED_DATA
  frameworks:
    - name: SOC 2
      controls: [CC6]
```

## Fields

| Field | Required | Description |
|-------|----------|-------------|
| `apiVersion` | Yes | Must be `cerebro.writer.com/v1alpha1`. |
| `kind` | Yes | Must be `PolicyFindingRule`. |
| `metadata.id` | Yes | Stable kebab-case policy and generated finding rule identifier. |
| `metadata.name` | Yes | Human-readable policy name. |
| `metadata.description` | Yes | What the policy checks and why it matters. |
| `metadata.lastModified` | No | Source policy timestamp when imported from an upstream catalog. |
| `metadata.tags` | No | Tags for categorization, routing, and catalog search. |
| `metadata.references` | No | External or internal references surfaced in public detection catalog metadata. |
| `spec.severity` | Yes | One of `critical`, `high`, `medium`, `low`, or `info`. |
| `spec.category` | No | Optional category override. Defaults to the policy directory domain. |
| `spec.effect` | Conditional | Required for CEL-backed policies; usually `forbid`. |
| `spec.principal` | No | Principal selector metadata for access-control-style policies. |
| `spec.action` | No | Action selector metadata for access-control-style policies. |
| `spec.resource` | No | Resource selector or resource family, such as `aws::ec2::instance`. |
| `spec.resourceType` | No | Human-oriented resource type when it differs from `spec.resource`. |
| `spec.match.conditions` | Conditional | CEL condition expressions for resource-state policies. |
| `spec.match.conditionFormat` | Conditional | Must be `cel` when present. |
| `spec.match.query` | Conditional | SQL/evidence query for query-backed policy rules. |
| `spec.graph.query` | Conditional | Read-only Cypher query for graph-backed policy rules. Must return `primary_urn`. |
| `spec.graph.rowLimit` | No | Optional row cap from 1 to 3000. Required when the query does not include `LIMIT`. |
| `spec.graph.params` | No | Static scalar Cypher params merged with runtime `tenant_id` and `row_limit`. |
| `spec.graph.requiredColumns` | No | Return aliases the validator must find in `spec.graph.query`. |
| `spec.input` | No | Evidence input contract: source kinds, event kinds, required claims, required fields, and freshness SLA. |
| `spec.assert` | Conditional | Structured evidence assertions for policies that evaluate normalized evidence records instead of CEL or SQL. |
| `spec.context` | No | Graph anchors, graph enrichment, and severity adjustment metadata used to explain and prioritize findings. |
| `spec.evidence` | No | Evidence type, audit requirement, accepted sources, required fields, fingerprint fields, and freshness metadata. |
| `spec.audit` | No | Auditor-facing evidence, assessment, exception, risk, remediation, and false-positive guidance. |
| `spec.verification` | No | Fixture expectations, mutation checks, and remediation rerun expectations for policy validation. |
| `spec.actions` | No | Owner resolution, remediation steps, effort, blast-radius, and policy-rerun guidance. |
| `spec.remediation.summary` | No | Remediation intent used in generated runbooks and finding attributes. |
| `spec.remediation.steps` | No | Optional ordered remediation steps. |
| `spec.riskCategories` | No | Normalized risk category labels. |
| `spec.frameworks` | Yes | Compliance framework/control mappings. Framework names and control IDs must exist in `internal/compliance/control_families.yaml`. |
| `spec.mitreAttack` | No | MITRE tactic and technique mappings. |
| `spec.enabled` | No | Set to `false` to keep a policy in the catalog while disabling generated rule support. |

Every policy must define `spec.graph` or at least one non-graph evaluation mode: `spec.match.conditions`, `spec.match.query`, or `spec.assert`. `spec.graph` is mutually exclusive with `spec.match` and `spec.assert`; `spec.match.conditions` and `spec.match.query` are mutually exclusive.

## Assertion Policies

Use `spec.assert` for normalized evidence records where the policy can be stated as field-level expectations. Assertions are useful for auditor-facing controls because they pair cleanly with input, evidence, audit, verification, and action metadata.

```yaml
spec:
  severity: high
  frameworks:
    - name: SOC 2
      controls: [CC6]
  input:
    sourceKinds: [okta.user]
    requiredFields: [tenant_id, resource_urn, privilege_level, mfa_enrolled, observed_at]
    freshnessSLA: 24h
  assert:
    all:
      - field: privilege_level
        op: in
        value: [admin, super_admin]
      - field: mfa_enrolled
        op: eq
        value: false
  evidence:
    type: identity_configuration
    assessmentMethods: [examine, test]
    requiredForAudit: true
  audit:
    auditorStatement: Privileged users are required to have MFA before administrative SaaS access.
    falsePositives:
      - The account is disabled or outside the privileged population.
```

## CEL Policies

Use `spec.match.conditions` for resource-state or event-state checks. Conditions are stored as strings because the policy runtime owns CEL evaluation. The DSL validator parse-checks the supported predicate envelope, including helpers such as `path`, `exists_path`, `cmp_eq`, `cmp_ne`, `cmp_gt`, `cmp_lt`, `cmp_ge`, `cmp_le`, `in_list`, `contains_value`, `matches_value`, `ends_with_value`, and `list_value(...).exists(...)`.

```yaml
spec:
  effect: forbid
  match:
    conditionFormat: cel
    conditions:
      - cmp_ne(path(resource, "public_ip_address"), null)
      - cmp_eq(path(resource, "internet_exposed"), true)
```

Multiple conditions are retained in order. A failed policy evidence or result event opens a policy finding through the generated `policy` rule adapter.

## Query Policies

Use `spec.match.query` for evidence queries that return failing rows:

```yaml
spec:
  severity: high
  match:
    query: SELECT id, owner FROM resources WHERE encryption_enabled = false
  frameworks:
    - name: SOC 2
      controls: [CC6]
```

The generated finding rule records `policy_query_present=true` and treats each failed evidence event as a policy finding candidate keyed by policy and resource identifiers.

## Graph Policies

Use `spec.graph` when the finding is derived from the projected graph rather than a replayed policy event. Graph policies compile into `GraphRule` implementations with a durable graph-anchored lifecycle.

```yaml
spec:
  severity: low
  category: graph
  resourceType: graph entity
  graph:
    query: |
      MATCH (entity:Entity {tenant_id: $tenant_id})
      WHERE entity.entity_type <> 'finding'
      RETURN entity.urn AS primary_urn,
             entity.urn AS fingerprint_key,
             'Graph entity requires review' AS summary
      LIMIT $row_limit
    rowLimit: 500
    requiredColumns:
      - primary_urn
      - fingerprint_key
      - summary
  input:
    sourceKinds: [graph]
  frameworks:
    - name: SOC 2
      controls: [CC7.1]
```

The graph validator enforces read-only Cypher, a bounded query, scalar params, and returned aliases. Standard aliases consumed by the runtime are `primary_urn`, `primary_label`, `primary_type`, `fingerprint_key`, `severity`, `summary`, `action`, `resource_urns`, and `evidence`.

## Authoring Commands

Create a policy scaffold:

```bash
go run ./tools/findingdsl new \
  --write \
  --domain aws \
  --id aws-s3-bucket-no-public-access \
  --name "S3 Bucket Public Access Block" \
  --description "S3 buckets should have public access blocked." \
  --severity critical \
  --resource aws::s3::bucket \
  --condition 'cmp_eq(path(resource, "block_public_acls"), false)' \
  --framework "SOC 2:CC6" \
  --reference "https://www.cisecurity.org/benchmark/amazon_web_services" \
  --tag aws \
  --risk-category EXTERNAL_EXPOSURE \
  --remediation "Enable S3 public access block settings."
```

Without `--write`, `new` prints the YAML to stdout. When `--out` is omitted, the file path is `policies/<domain>/<id>.yaml`.

Create a graph-backed policy scaffold:

```bash
go run ./tools/findingdsl new \
  --write \
  --domain graph \
  --id graph-orphan-nonfinding-node \
  --name "Graph Orphan Non-Finding Node" \
  --description "Detect non-finding graph nodes with no relationships." \
  --severity low \
  --graph-query 'MATCH (entity:Entity {tenant_id: $tenant_id}) RETURN entity.urn AS primary_urn, entity.urn AS fingerprint_key LIMIT $row_limit' \
  --graph-row-limit 500 \
  --graph-required-column primary_urn \
  --graph-required-column fingerprint_key \
  --framework "SOC 2:CC7.1" \
  --reference "https://www.iso.org/standard/27001" \
  --tag graph
```

Format one file or the full catalog:

```bash
go run ./tools/findingdsl fmt --write policies/aws/aws-s3-public.yaml
go run ./tools/findingdsl fmt --check
```

Generate or verify the editor schema:

```bash
make finding-dsl-schema-generate
make finding-dsl-schema-check
```

The legacy flag interface remains available for automation:

```bash
go run ./tools/findingdsl --check
go run ./tools/findingdsl --migrate-policies --write
```

## Fixture Tests

Policy behavior can be covered with `PolicyFindingRuleTest` files next to the policy. A suite named `policies/aws/aws-s3-public.test.yaml` defaults to testing `policies/aws/aws-s3-public.yaml`.

```yaml
apiVersion: cerebro.writer.com/v1alpha1
kind: PolicyFindingRuleTest
cases:
  - name: bucket without public access block fails
    resource:
      block_public_acls: false
    wantFinding: true
  - name: bucket with public access block passes
    resource:
      block_public_acls: true
    wantFinding: false
```

For query-backed policies, use `queryRows`; any returned row means the policy should produce a finding. For graph-backed policies, `queryRows` should model returned Cypher rows and include `primary_urn` for rows that should emit findings:

```yaml
apiVersion: cerebro.writer.com/v1alpha1
kind: PolicyFindingRuleTest
policy: policies/identity/example-query-policy.yaml
cases:
  - name: returned row fails
    queryRows:
      - primary_urn: urn:cerebro:writer:identity:user-1
    wantFinding: true
  - name: empty result passes
    resource:
      placeholder: true
    wantFinding: false
```

Run suites with:

```bash
go run ./tools/findingdsl test
```

## Validation And Generation

Run focused checks after editing policy DSL files:

```bash
make finding-dsl-check
make policy-rule-generate
make detection-catalog-generate
```

Before opening a PR, run:

```bash
make catalog-check
make policy-rule-check
make detection-catalog-check
```

`make finding-dsl-check` verifies the JSON Schema, runs policy fixture suites, rejects unknown YAML fields, rejects legacy JSON policy files, checks condition/query mode correctness, parse-checks condition expressions, and validates required DSL metadata. `make policy-rule-check` depends on `finding-dsl-check`, so stale generated rule output and invalid DSL files fail together.

## Migration

Legacy JSON policy files can be converted with:

```bash
make finding-dsl-migrate
```

The migration command converts `policies/**/*.json` files to `PolicyFindingRule` YAML and intentionally skips `policies/cerebro/control-mapping.json`.

## Organization

Policy files remain grouped by domain:

```text
policies/
├── aws/
│   ├── aws-s3-bucket-encryption.yaml
│   └── aws-ec2-internet-facing-iam.yaml
├── identity/
│   └── identity-okta-admin-mfa.yaml
├── kubernetes/
│   └── k8s-rbac-high-risk-binding.yaml
└── vulnerability/
    └── vuln-known-exploited.yaml
```

The directory name becomes the default generated policy category when `spec.category` is omitted.
