# Policy Rule Extensions

`policies/` remains the policy authoring catalog. `internal/compliance/policy_rule_extensions.yaml` is the enrichment layer used by `tools/policyrulegen` to turn those policies into clearer, auditor-facing Go finding rules.

The extension file lets us improve generated rule copy and evidence semantics without hand-editing `internal/findings/policy_rule_catalog_gen.go`.

## Merge Model

Extensions are applied in this order:

1. `defaults`
2. `evidence_modes.<mode>`
3. `domains.<policy-directory>`
4. `policies.<policy-id>`

More specific string fields replace earlier values. `assessment_methods` replace earlier values so query, manual, and domain-specific evidence can use the right assessment posture. `false_positives` are accumulated and de-duplicated.

## Generated Fields

The generator uses extensions to populate:

- rule descriptions with clearer failed-evidence language and risk statements
- rule runbooks with evidence review, owner/scope confirmation, remediation, and re-test language
- false-positive guidance for exceptions, stale evidence, compensating controls, and scope issues
- tags such as `assessment:examine` and `evidence:cloud_configuration`
- policy finding attributes including `policy_evidence_type`, `policy_assessment_methods`, `policy_auditor_guidance`, `policy_risk_statement`, `policy_remediation`, `policy_exception_guidance`, and `policy_control_families`

## Authoring Guidance

Use domain-level extensions for broad control families such as cloud configuration, identity governance, runtime threat signals, third-party risk, and procedural compliance. Use policy-level extensions only when one check needs materially different audit language, evidence classification, or exception handling.

After changing policies or extensions, run:

```bash
make policy-rule-generate
make detection-catalog-generate
```
