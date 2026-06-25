# Connector Definition Catalog

This directory contains built-in connector definitions for integrations that
are available to users before they are promoted into hand-written Source CDK
packages. Each YAML file groups entries by stable product domain:

- `identity-access-secrets.yaml`
- `collaboration-productivity.yaml`
- `devops-ci-cd.yaml`
- `security-posture-vulnerability.yaml`
- `observability-soar-threat-intel.yaml`
- `business-data-grc.yaml`

Keep entries sorted by `source_id` within each file. Add a new integration to
the smallest matching domain file, and create a new domain file only when the
existing groups would make the catalog harder to review.

Every entry must include a committed `classifier_output` and a normalized
`connectordefinitions.Definition` with:

- auth model and reference-only credential fields
- verification endpoint
- 2-4 high-value resource families
- projection templates
- coverage dimensions with evidence types and control domains for supported or partial high-value dimensions

`make catalog-check` is the broad catalog proof gate. It normalizes and
classifies every definition, rejects contradictory supported/missing feature
IDs, requires high-value coverage, and dry-runs sourcegen for entries classified
as supported. Use `make sourcegen-check` when the change should prove that every
built-in connector definition remains sourcegen-ready. The checker prints the
catalog status summary that should be used in PR notes.

Generateable entries can be promoted one integration at a time from the catalog:

```sh
go run ./cmd/cerebro source-runtime sdk new <source_id> catalog=true dry_run=true
```

Drop `dry_run=true` when the generated files are ready to review, then wire the
new source loader and projection registry entries called out in the generator
receipt.

External open-source catalogs can inform naming and resource-family choices only
when their licenses are permissive enough for this repository. Useful references
found during the initial pass:

- APIs.guru/openapi-directory: CC0 OpenAPI definitions.
- turbot/steampipe-plugin-* repositories: Apache-2.0 source table taxonomy.
- apache/camel: Apache-2.0 integration taxonomy.

Do not import source-available connector manifests into this catalog.
