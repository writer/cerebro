# Connector Definition Catalog

This directory contains built-in connector definitions for integrations that
are available to users before they are promoted into hand-written Source CDK
packages. Catalog entries are split one source per file under stable product
domain directories:

- `identity-access-secrets/<source_id>.yaml`
- `collaboration-productivity/<source_id>.yaml`
- `devops-ci-cd/<source_id>.yaml`
- `security-posture-vulnerability/<source_id>.yaml`
- `observability-soar-threat-intel/<source_id>.yaml`
- `business-data-grc/<source_id>.yaml`

Keep each file scoped to one `source_id`. Add a new integration to the smallest
matching domain directory, and create a new domain directory only when the
existing groups would make the catalog harder to review.

Every entry must include a committed `classifier_output` and a normalized
`connectordefinitions.Definition` with:

- auth model and reference-only credential fields
- verification endpoint
- 2-12 high-value resource families
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

Do not import source-available connector manifests into this catalog. Keep any
new broad catalog wave limited to source-level enterprise SaaS products, and
reject public data feeds, government datasets, consumer media APIs, local
self-hosted endpoints, and provider API surface shards.
