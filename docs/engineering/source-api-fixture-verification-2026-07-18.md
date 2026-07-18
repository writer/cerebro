# Source API Fixture Verification: 2026-07-18

## Scope

This pass examined all 820 source catalogs without creating provider accounts.
The repository contained 799 runtime sources, and the existing fidelity scan
identified 3,548 synthetic normalized read fixtures across 743 sources before
the pass.

The verification used three access paths:

- anonymous HTTPS GET requests to provider endpoints declared by source
  catalogs;
- documented public routes that require a stable public path parameter;
- an existing authenticated GitHub CLI session for read-only GitHub API calls.

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

The repository now contains 13 validated proof bundles across 8 sources and 11
runtime families. Each accepted response is replayed through the production
decoder, and its normalized read and discovery fixtures are derived from that
replay.

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

## Remaining boundary

`tools/sourcefidelity` still reports 743 sources with at least one normalized
fixture matching synthetic markers. Those families require provider tenant
identifiers, credentials, non-public account data, or a corrected documented
route. They were not replaced with documentation examples or invented JSON.
The long-term migration gate remains `needs_real_fixtures=0` after genuine
captures become available.
