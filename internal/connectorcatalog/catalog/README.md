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
- `ai-governance/<source_id>.yaml`

Keep each file scoped to one `source_id`. Add a new integration to the smallest
matching domain directory, and create a new domain directory only when the
existing groups would make the catalog harder to review.

Every entry must include a committed `classifier_output` and a normalized
`connectordefinitions.Definition` with:

- auth model and reference-only credential fields
- verification endpoint
- at least 2 resource families and at most 12 high-value resource families
- projection templates
- coverage dimensions with evidence types and control domains for supported or partial high-value dimensions

`make catalog-check` is the broad catalog proof gate. It normalizes and
classifies every definition, rejects contradictory supported/missing feature
IDs, requires high-value coverage, and dry-runs sourcegen for entries classified
as supported. Use `make sourcegen-check` when the change should prove that every
built-in connector definition remains sourcegen-ready. The checker prints the
catalog status summary that should be used in PR notes.

Use `make connector-catalog-maintenance` before promoting or cleaning catalog
entries. It runs the catalog proof gates and writes:

- `tmp/connector-catalog-review.md`
- `tmp/connector-catalog-review.json`
- `tmp/connector-catalog-fidelity.json`

The report is the review queue for this catalog. It lists sourcegen promotion
candidates, graph projection coverage, cleanup findings such as duplicate
provider roots, and review Q&A for each source. Treat cleanup findings as
actionable before adding another broad connector wave. Treat Q&A as the
operator checklist for creation and usage: graph targets, coverage value,
auth scope, and promotion state should be answerable from the catalog entry or
the linked Source CDK runtime.

Run `make connector-catalog-fidelity-generate` after importing or editing a
connector wave. It materializes deterministic Source CDK fields that are safe to
derive from the committed definition: event URN kinds, required payload fields,
short descriptions, and graph projection field maps for shallow families. The
maintenance job runs `connector-catalog-fidelity-check`, so any source that
drifts from those deterministic contracts must be regenerated or reviewed before
merge.

The repository also runs connector catalog maintenance on catalog PRs, on
`main`, and every six hours. The scheduled job publishes the Markdown and JSON
review artifacts so catalog drift, promotion backlog, and cleanup candidates
stay visible even when no connector PR is open.

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
