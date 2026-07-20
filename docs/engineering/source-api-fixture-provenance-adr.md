# ADR: Genuine Source API Fixtures

- **Status:** Accepted
- **Date:** 2026-07-18
- **Amended:** 2026-07-18
- **Related boundaries:** [`source-cdk-extraction.md`](source-cdk-extraction.md), [`rust-source-runtime-adr.md`](rust-source-runtime-adr.md), [`development.md`](development.md)

## Decision

Cerebro source tests will replay sanitized responses captured from genuine
provider API requests. A qualifying response may come from a request made by
the operator, a maintainer-published record/replay corpus, a licensed public
HTTP archive, or a locally run official provider implementation pinned by
version and digest. Generated objects, hand-authored provider-shaped JSON, and
examples copied from provider documentation are not source API fixtures.

Every active runtime family must carry one proof bundle containing:

- the HTTP method and provider path used by the source;
- the response status, headers that affect decoding or pagination, and body;
- the UTC capture time and provider API version when the provider exposes one;
- the capture origin and immutable coordinates for any upstream artifact or
  official implementation used;
- a SHA-256 digest of the sanitized response;
- the sanitizer version and the fields it changed or removed;
- a test that replays the response through the production decoder and asserts
  the resulting Cerebro event contract.

The checked-in response is sanitized, but it remains a capture. Sanitization
may replace credentials, tenant identifiers, account identifiers, personal
data, free-form content, and provider hostnames. It must preserve object shape,
field presence, JSON types, pagination structure, and values that select a
decoder branch. Repeated provider identifiers must resolve to the same example
value in request paths, direct fields, embedded strings, and cross-record
references. A proof bundle is rejected when sanitization changes the response
into a smaller schema example.

Pagination cursors are provider navigation state rather than authentication
credentials. Known cursor fields such as `next_token` and `pagination_token`
must retain a non-empty value so replay tests exercise the next-page branch.
When an upstream harness records against a local provider instance, the import
may replace its scheme and host with an HTTPS `.example.test` host, but it must
preserve the recorded provider path exactly.

Existing `testdata/read_*.json` files are normalized Cerebro events. They remain
useful replay outputs, but they do not prove that the source can decode a
provider response and do not satisfy this decision by themselves.

## Current state

At the decision date, `tools/sourcefidelity` reports 799 runtime sources. It
classifies 3,548 normalized read fixtures across 743 sources as synthetic. The
generated source tests commonly serve hand-authored provider records from an
`httptest` handler. Some source catalogs also record that their generated paths
do not exist in the provider reference.

Changing names and IDs in those files would make the payloads look realistic
without establishing API compatibility. This decision closes that path.

## Repository contract

A source proof bundle lives under the source package:

```text
sources/<source>/testdata/api/<family>/<case>/
  response.json
  provenance.yaml
```

`provenance.yaml` uses this contract:

```yaml
schema_version: cerebro.source-api-fixture.v1
source_id: example
family: users
case: first_page
request:
  method: GET
  url: https://api.example.test/v1/users
response:
  status: 200
  content_type: application/json
  captured_at: 2026-07-18T00:00:00Z
  sha256: <digest of response.json>
sanitization:
  tool: sourcefixture
  version: 1
  changed_fields: [items.*.id, items.*.email]
  removed_fields: []
origin:
  type: upstream_recording
  repository: https://github.com/example/provider-sdk
  commit: 0123456789abcdef0123456789abcdef01234567
  path: test/recordings/list-users.yaml
  artifact_sha256: <digest of the original recording file>
  license: Apache-2.0
  recording_tool: vcr
  interaction_index: 0
  freshness: current
```

`origin.type` is one of:

- `operator_request`: a public request made by `sourcefixture`, or an
  authenticated response piped from a provider CLI already available to the
  operator;
- `upstream_recording`: an interaction extracted from a provider-maintained or
  SDK-maintainer record/replay corpus whose harness demonstrates that the
  response was recorded from network traffic;
- `public_archive`: a response recovered from a public HTTP archive with a
  stable artifact locator and terms that permit redistribution;
- `official_implementation`: a response served by a pinned official image or
  release after its state was created through the implementation's public API.

An upstream origin records its repository, full commit, artifact path, artifact
digest, declared license, recording tool, and interaction index. An archive
origin records its stable locator, capture timestamp, artifact digest, and
redistribution basis. An official implementation origin records its release or
image digest and the repeatable seed and request commands. Every imported
response is re-sanitized by `sourcefixture`; the original artifact is not
checked in when it contains credentials, personal data, or unrelated
interactions.

Freshness is `current` when the captured request version and response shape are
compatible with the source's supported provider contract. Older but compatible
evidence is `historical` and cannot by itself promote a family to current
provider validation. A recording is rejected when its request host, method,
path, or API version does not match the production source contract.

`make source-fixture-check` validates every proof bundle present in the
repository. It fails when:

- a response digest does not match the checked-in payload;
- provenance uses a source ID or family not declared by the source catalog;
- the response is empty or is not valid for its declared content type;
- a proof bundle contains credential fields or non-example personal email addresses;
- a request is not a read-only HTTPS GET;
- canonical response JSON or provenance is invalid.
- an imported response lacks immutable origin coordinates or an artifact
  digest;
- a repository fixture has no record/replay harness establishing a genuine
  network capture;
- origin terms do not permit the sanitized response to be redistributed;
- a supposedly current recording predates an incompatible provider contract.

`tools/sourcefidelity` separately reports how many sources and families carry
validated proof bundles and how many normalized fixtures still match synthetic
markers. Missing bundles remain a migration finding until all runtime families
are covered.

Discovery fixtures and normalized read fixtures must be regenerated by replaying
the captured response through production source code. They must not be authored
independently.

## Capture workflow

`sourcefixture capture` sends one read-only public provider request, bounds the
response size, rejects cross-host redirects, canonicalizes JSON, scans the
result for credentials and personal data, and writes the proof bundle.
Authenticated captures are piped from an existing provider CLI with `-stdin`,
so the tool never receives or persists the credential. `sourcefixture import`
extracts one successful GET interaction from a pinned upstream artifact and
records the artifact coordinates and digest. The operator declares every
sanitized or removed field in provenance.

Capture and import are denied for mutation methods, non-HTTPS URLs, provider
error responses, empty responses, and non-JSON responses. Provider errors do
not replace a successful family fixture. SDK model snapshots, mocked responses,
documentation examples, screenshots, generated schemas, and test payloads with
no recording harness remain synthetic regardless of how realistic they look.

The importer may normalize recorder-specific envelopes, including VCR YAML or
JSON, pytest-recording `response.content`, ExVCR interaction arrays, and go-vcr
status fields. Supporting an envelope does not qualify its payload: the pinned
artifact, recording harness, successful read-only interaction, license, and
exact production method/path check remain mandatory.

## Migration

The migration is complete when every active runtime family passes the proof
bundle validator, its source test replays the checked-in response, and
`tools/sourcefidelity` reports `needs_real_fixtures=0`.

A source without safe provider access, a documented path, or a response capture
cannot be completed by generating data. Its runtime status must remain blocked
until a genuine capture is available. A catalog whose provider path has been
invalidated must be corrected before capture.

Migration commits should be grouped by provider so the capture provenance,
decoder change, normalized output, and projection assertions remain reviewable
together.

An online-corpus pass is complete only when its search frameworks, result caps,
pinned candidate repositories, accepted interactions, and exact reasons for
rejection are recorded. Dependency declarations and repository names are
discovery signals, not response evidence.

The first no-signup verification pass and its access boundaries are recorded in
[`source-api-fixture-verification-2026-07-18.md`](source-api-fixture-verification-2026-07-18.md).

## Consequences

- Fixture updates become evidence-bearing source changes rather than cosmetic
  test-data edits.
- Provider response drift is visible as a replay diff against a dated capture.
- Generated source scaffolds cannot claim runtime fidelity from generated data.
- Some sources will remain blocked until a genuine response with acceptable
  provenance and redistribution terms is available.
- Checked-in fixtures remain deterministic and safe for public repository use.
