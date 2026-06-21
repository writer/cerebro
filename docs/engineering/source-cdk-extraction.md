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
| `aurelius` | 623 | Split source orchestration from record mapping and shared request plumbing. |
| `aws` | 19070 | Extract common AWS client/session, pagination, ARN parsing, and resource-family traversal helpers. |
| `azure` | 2842 | Extract subscription traversal, client factories, and paginated resource readers. |
| `cosmo` | 1011 | Move shared API pagination and response normalization into reusable source helpers. |
| `gcp` | 2095 | Extract project traversal, service clients, and resource-family pagination helpers. |
| `github` | 2028 | Split audit/event readers from repository/user normalization and shared pagination. |
| `googleworkspace` | 815 | Extract API client setup and paginated directory readers. |
| `grc` | 1343 | Keep control/evidence shaping out of source orchestration and push common mapping into shared helpers. |
| `okta` | 2269 | Extract client, pagination, and identity/group/application readers into smaller units. |
| `panopticon` | 781 | Separate request plumbing from emitted record construction. |
| `sentinelone` | 2089 | Extract API paging, agent/application readers, and shared response normalization. |
| `vulnview` | 1042 | Split feed/client access from vulnerability record normalization. |

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
| `runtimeConfig` accessor | `akeyless`, `doppler`, `hashicorp_vault` | Extract into Source CDK config helper |
| `pullFromRecords` paging loop | `grc`, `vulnview` | Extract into Source CDK record pull |
| `checkpointCursor` encode/decode | `okta`, `sentinelone` | Extract into Source CDK cursor |
| `watermarkString` formatting | `aurelius`, `panopticon` | Extract into Source CDK watermark helper |
| `valueString` JSON scalar formatting | `cosmo`, `vulnview` | Fold into Source CDK JSON value helpers |
| provider URN parsing | `aws`, `azure` | Consolidate cautiously (provider-specific identifiers) |
| provider URN construction | `okta`, `sentinelone` | Consolidate into Source CDK URN helper |
| `New` constructor scaffold | `azure`, `gcp`, `googleworkspace` | Needs a generic CDK builder to deduplicate |
| `New` constructor scaffold | `archetype`, `sdk`, `trustedendpoint` | Structural boilerplate for sample/fixture sources |
