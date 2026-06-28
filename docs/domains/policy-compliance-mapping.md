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
| `internal/findings/builtin_rule_audit_extensions.yaml` | Layered audit-depth fields (assessment method, evidence type, frequency, false-positive guidance) for non-policy public detections, by defaults, anchors, sources, and per-rule override. |
| `internal/findings/coverage_control_domain_refs.yaml` | Curated `control_domains` to framework control refs, used to enrich a detection's source coverage refs only for the matched coverage source. |
| `tools/policymappingexport` | Generated CSV tables for spreadsheet review. |

## Merge Order

Audit language is merged in this order:

1. `defaults`
2. `evidence_modes.<mode>`
3. `domains.<policy-directory>`
4. `policies.<policy-id>`
5. Policy YAML fields

Specific string fields replace earlier values. Assessment methods replace earlier values. False-positive guidance is accumulated and de-duplicated.

## Non-Policy Audit and Coverage Overlays

Policy findings inherit audit language from `policy_rule_extensions.yaml`. Non-policy public detections (for example correlation and source-native rules) inherit audit depth from `builtin_rule_audit_extensions.yaml`, merged in this order:

1. `defaults`
2. `anchors.<anchor>`
3. `sources.<source-id>`
4. `rules.<detection-id>`

Rule-level values win. Policy-sourced detections are skipped so policy YAML stays authoritative. `detection-catalog-generate` validates that every public detection ends up with complete audit depth.

Source coverage refs come from the source coverage contracts. When a contract declares only coarse `control_domains`, `coverage_control_domain_refs.yaml` maps selected domains to defensible framework controls. Derived refs are added only when the detection matches the coverage source and the coverage dimension or evidence type also matches, so coverage stays source-bounded and avoids broad same-source over-claiming. Domains that do not directly evidence framework controls, such as `source_operations`, are explicitly exempted by tests instead of being silently ignored.

## All-Finding Audit Language

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
| `yaml_layers.csv` | One row per extension layer so inherited audit language can be reviewed. |
| `logic.csv` | The generation contract in spreadsheet form. |

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

## Commands

```bash
make detection-catalog-generate
make policy-mapping-export
make policy-mapping-check
```

Run `make policy-mapping-export` after changing policy YAML, public detection metadata, control families, or policy rule extensions. The target regenerates the policy rule catalog and public detection catalog first so all-finding CSVs use the latest checked-in catalogs. Run `make policy-mapping-check` before opening a PR.
