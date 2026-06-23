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
| `aurelius` | 600 | Split source orchestration from record mapping and shared request plumbing. |
| `aws` | 19078 | Extract common AWS client/session, pagination, ARN parsing, and resource-family traversal helpers. |
| `azure` | 2859 | Extract subscription traversal, client factories, and paginated resource readers. |
| `cosmo` | 975 | Move shared API pagination and response normalization into reusable source helpers. |
| `gcp` | 2083 | Extract project traversal, service clients, and resource-family pagination helpers. |
| `github` | 2011 | Split audit/event readers from repository/user normalization and shared pagination. |
| `googleworkspace` | 798 | Extract API client setup and paginated directory readers. |
| `grc` | 1302 | Keep control/evidence shaping out of source orchestration and push common mapping into shared helpers. |
| `okta` | 2234 | Extract client, pagination, and identity/group/application readers into smaller units. |
| `panopticon` | 758 | Separate request plumbing from emitted record construction. |
| `sentinelone` | 2054 | Extract API paging, agent/application readers, and shared response normalization. |
| `vulnview` | 960 | Split feed/client access from vulnerability record normalization. |

## Cross-Source Duplication Guardrail

`tools/archtests/source_helper_duplication_test.go` fails when the same function
body (structurally identical, ignoring the function name) of meaningful size
appears in two or more source packages. Duplication across sources is the signal
that provider-agnostic behavior should live in `internal/sourcecdk` instead of
being copy-pasted per source. The fingerprint ignores the function name, so
renamed copies are still detected.

Known, pre-existing duplication is captured in an allowlist that acts as a
ratchet: a new copy-paste fails the build, and each entry is removed when its
shared logic is lifted into the Source CDK. The current extraction backlog is:

| Shared behavior | Sources | Disposition |
| --- | --- | --- |
| provider URN parsing | `aws`, `azure` | Consolidate cautiously (provider-specific identifiers) |
| provider URN construction | `okta`, `sentinelone` | Consolidate into Source CDK URN helper |
| `New` constructor scaffold | `azure`, `gcp`, `googleworkspace` | Needs a generic CDK builder to deduplicate |
| `New` constructor scaffold | `archetype`, `sdk`, `trustedendpoint` | Structural boilerplate for sample/fixture sources |
