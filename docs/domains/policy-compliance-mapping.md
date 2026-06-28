# Policy Compliance Mapping

Policy compliance mapping is YAML-first. The checked-in CSV files under `docs/reference/policy-compliance-mapping/` are generated review tables for auditors, control owners, and policy authors.

Do not edit the CSV rows by hand. Update the YAML inputs, regenerate the mapping, and review the diff.

## Source Files

| Source | Owns |
|--------|------|
| `policies/**.yaml` | Policy IDs, names, domains, severities, resources, remediation, control refs, metadata tags, risk categories, and MITRE refs. |
| `internal/findings/public_detection_catalog.json` | Public detection IDs, packs, sources, evaluation modes, runtime tags, control refs, audit depth, and source coverage refs for every public finding type. |
| `internal/compliance/control_families.yaml` | Framework names, control IDs, and control family labels. |
| `internal/compliance/policy_rule_extensions.yaml` | Shared audit language by defaults, evidence mode, domain, policy override, finding-domain alias, and finding override. |
| `internal/compliance/framework_review_areas.yaml` | Framework-level review queues that group direct control refs without changing evidence status. |
| `internal/compliance/control_relationships.yaml` | Alias, child requirement, sibling scope, evidence dependency, and follow-up hints between controls. |
| `internal/compliance/evidence_capabilities.yaml` | Source and dimension capability declarations for source-backed evidence review. |
| `tools/policymappingexport` | Generated CSV tables for spreadsheet review. |

## Merge Order

Audit language is merged in this order:

1. `defaults`
2. `evidence_modes.<mode>`
3. `domains.<policy-directory>`
4. `policies.<policy-id>`
5. Policy YAML fields

Specific string fields replace earlier values. Assessment methods replace earlier values. False-positive guidance is accumulated and de-duplicated.

All-finding audit language uses the same YAML file:

1. `defaults`
2. `evidence_modes.<evaluation-mode>`
3. `domains.<resolved-domain>`
4. `findings.<finding-id>`
5. Public detection catalog fields

Finding domains resolve from `finding_domains` by finding ID, pack, source, then tag. Direct catalog fields win when they are present. `audit_language_source` reports the final source of the emitted audit fields.

## Generated Tables

| File | Use |
|------|-----|
| `overview.csv` | Counts by policy, control row, tag row, domain, framework, and evidence mode. |
| `policy_map.csv` | One row per policy finding rule with controls, tags, evidence, risk, and audit language. |
| `control_map.csv` | One row per policy-control mapping for framework coverage review. |
| `tag_map.csv` | One row per tag-policy mapping for routing and search cleanup. |
| `finding_map.csv` | One row per public detection with pack, source, evaluation mode, controls, runtime catalog tags, compliance review tags, audit depth, and source coverage summary. |
| `finding_control_map.csv` | One row per public detection-control mapping across policy and non-policy findings. |
| `finding_tag_map.csv` | One row per public detection tag, including catalog tags and control-derived compliance review tags. |
| `source_coverage_map.csv` | One row per public detection source coverage ref for evidence-source review. |
| `finding_compliance_review_map.csv` | One row per public detection with resolved audit domain, audit language source, source-backed control counts, and review flags. |
| `finding_domain_aliases.csv` | One row per YAML finding-domain alias used to resolve non-policy findings into audit domains. |
| `framework_review_areas.csv` | One row per YAML framework review area with its control refs and purpose. |
| `control_relationships.csv` | One row per YAML control relationship, including alias, child requirement, sibling scope, and evidence dependency hints. |
| `finding_review_area_map.csv` | One row per public detection matched into a YAML framework review area through direct control refs. |
| `finding_control_relationship_map.csv` | One row per public detection-control relationship hint through direct control refs. |
| `evidence_capabilities.csv` | One row per YAML source/dimension capability with declared source-backed control refs. |
| `source_capability_review_map.csv` | One row per source/dimension comparing YAML capability refs with observed public catalog source coverage refs. |
| `framework_control_enrichment_map.csv` | One row per framework control showing direct findings, source-backed findings, source capabilities, review areas, and relationships. |
| `yaml_layers.csv` | One row per extension layer so inherited audit language can be reviewed. |
| `logic.csv` | The generation contract in spreadsheet form. |

`finding_map.csv` keeps its original columns in place and appends new enrichment columns after `review_flags`. Read generated CSVs by header name when possible; positional readers should treat appended columns as additive fields.

## Tags

Metadata tags come from `metadata.tags` in policy YAML. Derived tags are added from stable rule properties:

- `policy`
- evidence mode: `cel`, `query`, `graph`, or `manual`
- policy domain
- `evidence:<type>` when an evidence type is known
- `assessment:<method>` for assessment methods
- `spec.category` when present

The export keeps metadata and derived tags separate, then emits `all_tags` for the runtime-equivalent view.

The all-finding tables add `compliance_review_tags` from `control_refs`:

- `framework:<framework>`
- `control:<framework>:<control>`
- `control-family:<family>`

These tags are for spreadsheet filtering and cleanup. They do not replace `control_refs`, and they are not added to the runtime finding tag set.

## Source-Backed Controls

The all-finding export compares detection `control_refs` with source coverage `matched_control_refs`:

- `source_backed`: every direct finding control has a matching source coverage control.
- `partial_source_backed`: at least one direct finding control has source coverage, and at least one does not.
- `control_only`: the finding has control refs but no matching source coverage control refs.

Use `control_refs_without_source_match` as a review queue. It does not mean the control is invalid; it means the spreadsheet cannot point to a matched source coverage lane for that direct control ref yet.

## Review Context

`framework_review_areas.yaml` groups related controls into reviewer queues such as access authorization, technical safeguards, privacy incident response, payment-card authentication, and AI management planning. A finding enters `finding_review_area_map.csv` when one of its direct control refs is in the YAML area.

`control_relationships.yaml` adds explicit links such as aliases, child requirements, sibling scope, evidence dependencies, and corrective-action follow-up. A finding enters `finding_control_relationship_map.csv` when it has the direct control ref. These rows are review hints only; they do not change `source_backed`, `partial_source_backed`, or `control_only` status.

`evidence_capabilities.yaml` declares what a source/dimension can support when source coverage is available. `source_capability_review_map.csv` compares those YAML declarations with the public detection catalog so capability gaps are visible without treating review context as evidence.

`framework_control_enrichment_map.csv` is the control-centric view. It answers the reverse question for each framework control: which findings map directly, which findings are source-backed, which source capabilities can support it, which review areas use it, and which related controls should be inspected with it.

## Commands

```bash
make detection-catalog-generate
make policy-mapping-export
make policy-mapping-check
```

Run `make policy-mapping-export` after changing policy YAML, public detection metadata, control families, or policy rule extensions. The target regenerates the policy rule catalog and public detection catalog first so all-finding CSVs use the latest checked-in catalogs. Run `make policy-mapping-check` before opening a PR.
