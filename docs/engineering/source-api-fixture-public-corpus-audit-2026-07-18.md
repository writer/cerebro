# Public Source API Recording Corpus Audit: 2026-07-18

## Decision boundary

This audit exhausted the public, redistributable recording corpus that could be
identified without creating a provider account. A response qualified only when
the pinned artifact contained a successful, non-empty, read-only provider
interaction; the repository included a network recording harness and
redistribution terms; and the method, path, API version, and response semantics
matched a Cerebro runtime family.

Provider documentation, generated SDK examples, mocks, schemas, error
responses, and empty responses were rejected. A recorder dependency or a
repository name was treated as a discovery signal, not response evidence.

The baseline was 799 runtime sources, 93 genuine bundles, 20 sources with
genuine evidence, 82 genuine families, and 740 sources still carrying at least
one synthetic normalized fixture.

## Search coverage

All searches used the authenticated GitHub CLI and public repository APIs.
GitHub code search returned the following bounded result sets:

| Discovery query | Results inspected | Unique repositories |
| --- | ---: | ---: |
| VCR cassette paths | 1,000, result cap reached | 193 |
| `recorded_with` in `.yml` | 1,000, result cap reached | 248 |
| `recorded_with` in `.yaml` | 117 | 36 |
| go-vcr imports and artifacts | 731 | 595 |
| Betamax manifests | 141 | 128 |
| vcrpy, pytest-recording, and pytest-vcr manifests | 400 | 341 |
| Polly.JS, Nock Back, node-replay, and MSW recorder manifests | 270 | 254 |

The combined discovery sets represented 1,738 unique repositories. Candidate
repository trees, licenses, harnesses, and response artifacts were then read at
pinned commits through the GitHub API. Exact provider-host searches were also
run for CrowdStrike, Snyk, JumpCloud, PagerDuty, New Relic, Linear, Gong,
Vanta, Drata, and SentinelOne cassette paths; all ten returned zero results.
The same host search against generic fixture paths returned only an authored
dependency-remediation study, a sample PagerDuty webhook, and curl-conversion
test inputs. None was a recorded provider response. A final open-web search
found no additional response corpus outside the GitHub results.

The pass included the official Palo Alto Networks repositories for Prisma
Cloud Python and Go clients, the Prisma Cloud Terraform provider, Cortex Data
Lake, AutoFocus, and public integration examples. Those repositories expose
SDKs, documentation, Postman collections, or authored tests, but no committed
successful response recording compatible with the current Cerebro contracts.

## Accepted artifacts

Sixteen exact interactions from ten pinned recorder corpora were imported.
All are historical evidence unless the individual provenance file says
otherwise.

| Source | Families | Pinned origin | Artifact paths | License |
| --- | --- | --- | --- | --- |
| BambooHR | `users` | `thebugcatcher/bamboohr_api@e45a54e32cc6231b12de2bb42cd6569fcb7d4858` | `fixture/vcr_cassettes/employee/list/valid.json` | MIT |
| Bugsnag | `projects`, `errors` | `bugsnag/bugsnag-api-ruby@a743f527b7ca123954924a94eeb544acea13ca38` | organization project list; project error list under `spec/cassettes` | MIT |
| Contentful | `documents` | `JuulLabs-OSS/contentful_lite@9e1210adbe01d3c3537fd040228ea339db24f091` | `fixtures/vcr_cassettes/client/entries.yml` | MIT |
| HackerOne | `findings` | `github/hackerone-client@232a746dd4d1d7a718a3b9465038dfe1f4cbed75` | `fixtures/vcr_cassettes/report_list.yml` | MIT |
| Mailchimp | `lists`, `members` | `duartejc/mailchimp@a11991323c81cafeccd529cbf5e44fe914bfa57b` | `account.lists.json`, `list.members.json` | MIT |
| Postmark | `domains` | `Stranger6667/postmarker@a060d4955e8b41a322a90c8e261765aa5e57d028` | `test/cassettes/domains.json` | MIT |
| Replicate | `models`, `collections` | `replicate/replicate-python@d2956ff9c3e26ef434bc839cc5c87a50c49dfe20` | `tests/cassettes/models-list.yaml`, `collections-list.yaml` | Apache-2.0 |
| Retool | `users` | `tryretool/terraform-provider-retool@cd9bed3672a48b8efc1c526c577d6f8af6653b46` | `test/data/recordings/TestAccUsersDataSource.yaml` | MIT |
| Trello | `users`, `groups`, `workspaces`, `documents` | `yammine/ex_trello@a252cb34a2c08500ba62ad2f86f9d55ca609170f` | four matching ExVCR artifacts under `fixtures/vcr_cassettes` | MIT |
| Trello | `audit_events` | `jeremytregunna/ruby-trello@ddea4c71606c29e7cf5f09268d5c1d82a0539398` | `spec/cassettes/can_get_actions_of_members.yml` | MIT |

Each proof bundle records the complete repository-relative artifact path,
artifact digest, interaction index, recording tool, harness path, capture time,
sanitizer changes, and replay test. Original recordings containing credentials
or tenant data were streamed through `sourcefixture`; only the sanitized
response and provenance were retained.

## Rejected candidates

| Candidate corpus | Decision |
| --- | --- |
| Palo Alto Networks official clients and providers | No committed successful response recording; the separate Cortex Xpanse VCR corpus targets a different product and contract. |
| Linode Go client | Recorded requests use `/v4beta`; Cerebro supports `/v4`. Historical revisions checked in 2022 and 2024 retained the beta path. |
| Looker Terraform provider | Recordings cover detail reads and filtered searches, not the list contracts used by the current families. |
| Zuora Ruby client | Successful GET recordings are account-detail requests under `/rest/v1/accounts/{id}` and do not match any current Zuora family. |
| Rollbar clients and provider | Recorded projects, teams, and users do not match Cerebro's alerts, incidents, monitors, or dashboards semantics and paths. |
| Iterable client | The large VCR corpus does not match the generated paths or semantics of the current families. |
| Postmark clients | Domains matched and were accepted; the remaining recording is singular `/server` with a server token, not the account-level `/servers` collection. |
| CircleCI clients | Available recordings target v1.1 or other paths rather than the current v2 contracts. |
| HackerOne client | Reports matched `findings` and were accepted; no matching successful recording exists for the other generated families. |
| Zscaler clients and providers | No response recorder artifacts were committed. |
| SGNL adapters | Provider-shaped objects are authored mocks and smoke-test inputs, not captured HTTP responses. |
| Atlan clients | Recorder coverage exercises httpbin harness traffic, not Atlan API responses. |
| Hyperproof, Frontegg, Splunk, and Klaviyo candidates | Recorder dependencies or test scaffolds were present, but no qualifying provider response artifact was committed. |
| Documentation and Postman collections across remaining candidates | Request descriptions and example bodies do not establish a genuine response and were rejected by policy. |

## Result

The repository now has 109 verified bundles across 29 sources and 98 runtime
families. Production replay exposed and corrected the provider routes,
authentication, envelopes, identifiers, timestamps, and pagination behavior
used by these interactions. `tools/sourcefidelity` reports 739 sources still
carrying at least one synthetic normalized fixture.

This is a bounded exhaustion result, not a claim that private provider traffic
does not exist. The remaining migration work requires an existing provider
tenant or credential, a newly published licensed recording, a local official
implementation, or a corrected production contract. Those families remain
explicitly unverified rather than being filled with generated data.
