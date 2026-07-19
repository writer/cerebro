# Source API Fixture Verification: 2026-07-18

## Scope

This pass examined all 820 source catalogs and then ran a second GitHub corpus
sweep without creating provider accounts.
The repository contained 799 runtime sources, and the existing fidelity scan
identified 3,548 synthetic normalized read fixtures across 743 sources before
the pass.

The verification used four access paths:

- anonymous HTTPS GET requests to provider endpoints declared by source
  catalogs;
- documented public routes that require a stable public path parameter;
- an existing authenticated GitHub CLI session for read-only GitHub API calls;
- pinned record/replay artifacts in public GitHub repositories, accepted only
  when the recording harness, license, request method, and endpoint matched an
  existing production source family.

No provider signup, trial, mutation request, or new credential was used. Local
Google Cloud and Kubernetes credentials could not be refreshed without an
interactive login, so they were not used.

## Catalog endpoint audit

The catalog audit considered every declared GET family whose base URL and path
formed a fixed HTTPS URL without `${config.*}` values or `{path_parameters}`.
It issued a bounded request with `Accept: application/json`, a 12-second
timeout, a 1 MiB inspection limit, and same-host redirects only.

| Result | Endpoints |
| --- | ---: |
| Genuine non-empty JSON response | 4 |
| HTTP 401 | 264 |
| HTTP 403 | 29 |
| HTTP 404 | 17 |
| HTTP 406 | 11 |
| HTTP 400 | 2 |
| HTTP 422 | 1 |
| HTTP 503 | 4 |
| Network failure | 8 |
| Provider error envelope returned with 2xx | 8 |
| Non-JSON response returned with 2xx | 3 |
| Empty JSON response returned with 2xx | 1 |
| Total fixed endpoints | 352 |

Successful HTTP status alone did not qualify a response. Slack `not_authed`,
API2Cart error envelopes, HTML login pages, and empty collection responses were
rejected. The Fivetran public connector-type response was retained after its
production decoder was corrected from `data.items` to the observed `data`
array.

## Captures accepted

| Source | Runtime family | Capture cases | Access | Production replay result |
| --- | --- | --- | --- | --- |
| Appwrite | `continent` | `continents` | Anonymous | 7 continent records |
| Avaza | `currency` | `currencies` | Anonymous | 158 currency records |
| Docker Hub | `repositories` | `ubuntu_repository` | Anonymous | Official namespace repository record |
| Fivetran | `public_connector_types` | `connector_types` | Anonymous | 803 connector metadata records |
| GitHub | `org_inventory` | `members` | Existing `gh` session | Organization member record |
| GitHub | `pull_request` | `pull_requests` | Existing `gh` session | Pull request record |
| GitHub | `repository` | `repository`, `org_repositories`, `user_repositories` | Existing `gh` session | Direct, organization-list, and user-list response shapes |
| GitLab | `repositories` | `projects` | Anonymous | Public project record |
| GitLab | `users` | `users` | Anonymous | Public user record |
| Have I Been Pwned | `breaches` | `adobe` | Anonymous | Public breach record |
| Hugging Face | `repositories` | `models` | Anonymous | Public model repository record |
| Datadog | `audit_events`, `dashboards`, `incidents`, `monitors`, `roles`, `slos`, `teams`, `users` | 8 list cases | Pinned upstream VCR recordings | All 8 runtime families replayed |
| GitHub | `audit`, `dependabot_alert`, `secret_scanning_alert` | 3 restricted list cases | Pinned Octokit and PyGithub recordings | All remaining GitHub runtime families replayed |
| Okta | 19 runtime families except `audit` | 21 list, configuration, policy, and MFA cases | Pinned upstream VCR recordings | 19 production families replayed, including the user MFA enrichment path |
| Auth0 | `client_grants`, `clients`, `guardian_factors`, `organization_members`, `roles`, `user_roles`, `users` | 7 list cases | Pinned upstream VCR recordings | All 7 captured runtime families replayed |
| Zendesk | `audit_events`, `tickets`, `users` | 3 list cases | Pinned upstream Betamax recordings | All 3 runtime families replayed through corrected v2 collection paths |
| Tenable.io | `assets`, `vulnerabilities` | 2 list cases | Pinned upstream VCR recordings | 13 assets and 2 vulnerability aggregates replayed; evidence remains historical |
| GitGuardian | `audit_events`, `incidents`, `members` | 3 list cases | Pinned upstream VCR recordings | All 3 runtime families replayed with provider Link pagination |
| GitGuardian Secrets | `audit_events`, `sources` | 2 list cases | Pinned upstream VCR recordings | Both captured runtime families replayed; the unsupported `secrets` scaffold remains blocked |

The repository now contains 62 validated proof bundles across 15 sources and
58 runtime families. This second sweep added 17 bundles and completed genuine
replay coverage for Zendesk and GitGuardian. Datadog has genuine replay
coverage for all 8 runtime families, GitHub for all 6, Okta for 19 of 20,
Zendesk for all 3, and GitGuardian for all 3. Each accepted response is replayed
through the production decoder, and its normalized read and discovery fixtures
are derived from that replay.

Every upstream artifact is pinned by full commit, repository-relative path,
artifact digest, declared license, recording tool, harness path, and interaction
index. A capture is marked `current` only where current-contract compatibility
was established; other compatible evidence is marked `historical` and does not
claim current provider validation.

## Public GitHub corpus audit

The GitHub pass examined high-volume record/replay corpora before selecting the
imports above:

- the maintained Datadog client contains 2,235 cassettes and supplied an exact
  GET response for every active Datadog family;
- the maintained Okta client contains 444 cassettes and supplied exact GET
  responses for 19 of 20 active Okta families; no successful non-empty System
  Log capture was present for `audit`;
- the maintained Auth0 provider contains 240 recordings and supplied exact,
  non-empty GET responses for 7 active families; connection responses were
  rejected because their full option payloads contained credential subtrees,
  and the remaining families had no matching recordings;
- the maintained Zendesk client contains 269 Betamax recordings and supplied
  exact responses for users, tickets, and ticket audits;
- the maintained Tenable client contains 528 VCR recordings and supplied exact
  historical responses for assets and aggregate vulnerabilities; available
  findings search captures use POST and were not relabeled as GET fixtures;
- two maintained GitGuardian clients contain 43 and 180 VCR recordings. They
  supplied exact member, incident, audit-log, and source responses. The current
  corpus records response redaction in its VCR harness, and `sourcefixture`
  applies a second sanitization pass before the response enters the repository;
- the maintained Cortex Xpanse client contains 41 VCR cassettes, including 31
  API response cases. None matches the current `cortex_xdr`, `cortex_xsoar`, or
  `prisma_cloud` request contracts, so no Xpanse response was relabeled as a
  different Palo Alto product;
- Azure SDK test-proxy assets, Google Cloud replay files, Xero VCR files, and
  Twilio and Slack test fixtures were also checked. The available artifacts
  either lacked the collection request required by the production family,
  targeted a different endpoint, or were authored mocks rather than recorded
  network responses.

## Runtime corrections found by replay

The captures exposed contract errors that synthetic records had not exercised:

- public families were incorrectly requiring provider credentials;
- the Docker Hub repository path used a non-provider route instead of the
  documented namespace route;
- the Fivetran public connector endpoint returns an unpaginated `data` array;
- Appwrite continents and Avaza currencies use provider-specific code and name
  fields;
- GitLab pagination and query parameters had not been tested against public
  project and user payloads;
- Have I Been Pwned uses `hibp-api-key` for protected families while the breach
  catalog remains public;
- normalized IDs and URNs were based on generated values instead of provider
  record identity.
- Datadog audit attributes are nested under `attributes.attributes` in genuine
  responses, not only under the synthetic shape previously tested;
- GitHub Dependabot discovery does not need an unrelated repository refetch
  after the alerts endpoint has already validated access;
- Okta ThreatInsight uses both RFC3339 and legacy space-separated timestamps;
- fixture replay tests must accept the real provider page cardinality instead
  of assuming one generated record.
- Auth0 organization members and user-role collections use `members` and
  `roles` response envelopes rather than the scaffold's generic list shape;
- Zendesk uses `/api/v2/users.json`, `/api/v2/tickets.json`, and
  `/api/v2/ticket_audits.json` with `page[after]` cursor pagination;
- Tenable.io uses the `X-ApiKeys` header, `/assets`, and
  `/workbenches/vulnerabilities`; aggregate vulnerabilities are identified by
  `plugin_id` rather than a generated `id`;
- GitGuardian collection responses are top-level arrays paged by the `Link`
  header, and audit actors use `member_id`, `member_email`, and `member_name`;
- GitGuardian source records use `full_name` and `type`, while their collection
  page size parameter is `per_page` rather than the generated `limit`.

## Remaining boundary

`tools/sourcefidelity` still reports 742 sources with at least one normalized
fixture matching synthetic markers. The final scan reports 62 genuine bundles,
58 genuine families, 15 sources with genuine evidence, and 43 high-fidelity
sources. The remaining families require provider tenant identifiers,
credentials, non-public account data, a corrected documented route, or a
matching public recording. They were not replaced with documentation examples,
auth-error envelopes, empty collections, or invented JSON. The long-term
migration gate remains `needs_real_fixtures=0` after genuine captures become
available.
