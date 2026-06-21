# Source CDK Extraction Plan

New source packages must stay at or below 300 nonblank Go LOC and must not own
direct store writes, direct process environment reads, background contexts, or
provider-specific retry/pagination frameworks. Shared behavior belongs in the
Source CDK, not in one source.

Legacy sources above the 300 LOC budget are grandfathered with exact no-growth ceilings in `tools/archtests/source_packages_test.go`. If one shrinks, lower the budget in the same PR. If one needs new shared behavior, extract the behavior into `internal/sourcecdk` or another shared source-support package before growing the source.

## Extraction Themes

- Move provider client construction, retry policy, and pagination loops into
  shared Source CDK helpers.
- Keep normalization, graph projection, persistence, and finding logic outside
  `sources/*`.
- Prefer small resource-family readers that emit typed records over one large
  source-level orchestration file.
- Add replay fixtures before changing legacy source behavior so extraction does
  not silently change emitted events.

## Grandfathered Sources

| Source | Current LOC Budget | Extraction Pressure |
| --- | ---: | --- |
| `aurelius` | 653 | Split source orchestration from record mapping and shared request plumbing. |
| `aws` | 19121 | Extract common AWS client/session, pagination, ARN parsing, and resource-family traversal helpers. |
| `azure` | 2856 | Extract subscription traversal, client factories, and paginated resource readers. |
| `cosmo` | 1104 | Move shared API pagination and response normalization into reusable source helpers. |
| `gcp` | 2095 | Extract project traversal, service clients, and resource-family pagination helpers. |
| `github` | 2102 | Split audit/event readers from repository/user normalization and shared pagination. |
| `googleworkspace` | 827 | Extract API client setup and paginated directory readers. |
| `grc` | 1378 | Keep control/evidence shaping out of source orchestration and push common mapping into shared helpers. |
| `okta` | 2361 | Extract client, pagination, and identity/group/application readers into smaller units. |
| `panopticon` | 820 | Separate request plumbing from emitted record construction. |
| `sentinelone` | 2181 | Extract API paging, agent/application readers, and shared response normalization. |
| `vulnview` | 1064 | Split feed/client access from vulnerability record normalization. |
