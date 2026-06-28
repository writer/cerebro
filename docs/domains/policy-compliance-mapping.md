# Policy Compliance Mapping

Policy compliance mapping is YAML-first. The checked-in CSV files under `docs/reference/policy-compliance-mapping/` are generated review tables for auditors, control owners, and policy authors.

Do not edit the CSV rows by hand. Update the YAML inputs, regenerate the mapping, and review the diff.

## Source Files

| Source | Owns |
|--------|------|
| `policies/**.yaml` | Policy IDs, names, domains, severities, resources, remediation, control refs, metadata tags, risk categories, and MITRE refs. |
| `internal/compliance/control_families.yaml` | Framework names, control IDs, and control family labels. |
| `internal/compliance/policy_rule_extensions.yaml` | Shared audit language by defaults, evidence mode, domain, and policy override. |
| `tools/policymappingexport` | Generated CSV tables for spreadsheet review. |

## Merge Order

Audit language is merged in this order:

1. `defaults`
2. `evidence_modes.<mode>`
3. `domains.<policy-directory>`
4. `policies.<policy-id>`
5. Policy YAML fields

Specific string fields replace earlier values. Assessment methods replace earlier values. False-positive guidance is accumulated and de-duplicated.

## Generated Tables

| File | Use |
|------|-----|
| `overview.csv` | Counts by policy, control row, tag row, domain, framework, and evidence mode. |
| `policy_map.csv` | One row per policy finding rule with controls, tags, evidence, risk, and audit language. |
| `control_map.csv` | One row per policy-control mapping for framework coverage review. |
| `tag_map.csv` | One row per tag-policy mapping for routing and search cleanup. |
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

## Commands

```bash
make policy-mapping-export
make policy-mapping-check
```

Run `make policy-mapping-export` after changing policy YAML, control families, or policy rule extensions. Run `make policy-mapping-check` before opening a PR.
