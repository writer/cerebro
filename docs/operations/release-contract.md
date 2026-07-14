# Release Contract

This guide explains Cerebro's public release artifacts and the runtime deploy contract. It is for OSS users who want to consume releases, verify artifacts, or wire their own deployment automation.

Use it with:

- [`README.md`](../../README.md) "Release and deploy artifacts".
- [`docs/operations/hosting.md`](hosting.md) for how to run the image.
- [`docs/operations/runtime-profiles.md`](runtime-profiles.md) for profile-specific dependencies, config, and checks.
- [`docs/operations/deployment-readiness.md`](deployment-readiness.md) for rollout gates and preflight receipts.
- [`docs/domains/source-runtime-guide.md`](../domains/source-runtime-guide.md) for source runtime manifests.
- [`tools/sourcedeploy`](../../tools/sourcedeploy) for contract rendering code.

## Release channels

Every commit merged to `main` produces a candidate. A candidate is identified by its full commit and image digest:

```text
candidate-<40-character-commit>
ghcr.io/writer/cerebro@sha256:<digest>
```

The Candidate Build workflow waits for CI, builds the binary archives and multi-architecture image once, writes checksums and a dependency inventory, attaches provenance, signs the image and runtime contracts, and stores a `cerebro.release-candidate/v1` receipt. Candidate builds do not create Git tags, GitHub releases, stable semantic-version image tags, `latest`, or deployment requests.

Stable releases are promoted from a successful Candidate Build run through the `stable-release` GitHub environment. The operator supplies the candidate run ID, stable tag, completed release notes, and a successful smoke receipt URL. The workflow verifies the candidate bundle checksums, commit, run ID, image digest, and image signature before it assigns stable tags.

Stable release tags use:

```text
vMAJOR.MINOR.PATCH
```

Examples:

```text
v1.2.3
```

`latest` is updated only by the Stable Release workflow. Deployment automation receives requests only after the stable GitHub release is published. Candidate testing must pin the candidate digest; it does not use the stable deployment dispatch.

Use [`release-notes-template.md`](release-notes-template.md) for the required compatibility, migration, configuration, content-pack, rollback, runtime-contract, smoke-evidence, and supported-version record.

## Public artifacts

A release can include:

- CLI archives,
- Linux runtime binaries,
- multi-arch runtime image,
- image provenance and signatures,
- target-specific runtime contracts, named `cerebro-runtime-contract-<target>.json`,
- matching runtime contract signatures,
- matching runtime contract certificates.

Runtime image:

```text
ghcr.io/writer/cerebro:<tag>
```

Run:

```bash
docker run --rm ghcr.io/writer/cerebro:<tag> version
```

## Release verification

The release workflow runs the same broad validation families used in CI:

- build,
- tests,
- SDK tests,
- lint,
- proto checks,
- OpenAPI checks,
- catalog checks,
- README checks,
- OSS audit,
- release smoke,
- Docker smoke,
- structural and architecture checks.

For local preflight before release-oriented changes:

```bash
make verify
make release-smoke
make docker-smoke
```

For public docs and config changes:

```bash
make readme-check docs-drift-check oss-audit
```

## Runtime deploy contract

The runtime deploy contract is a JSON handoff from this public repo to deployment automation.

Schema version:

```text
cerebro.runtime-deploy-contract/v1
```

Render locally:

```bash
go run ./cmd/sourcedeploy \
  -env <environment> \
  -tenant <tenant-id> \
  -format contract-json \
  -image-tag vX.Y.Z \
  -out .dist/cerebro-runtime-contract.json
```

Use placeholder environment and tenant values for local experiments. Real values belong in your deployment system.

## Contract fields

Top-level shape:

```json
{
  "schema_version": "cerebro.runtime-deploy-contract/v1",
  "image_tag": "vX.Y.Z",
  "environment": "<environment>",
  "tenant_id": "<tenant-id>",
  "required_secrets": ["PROVIDER_API_TOKEN"],
  "runtime_profiles": [],
  "required_env_vars": [],
  "required_backing_services": [],
  "optional_capabilities": [],
  "post_deploy_health_checks": [],
  "compatibility_notes": [],
  "sources": []
}
```

Top-level fields:

| Field | Meaning |
| --- | --- |
| `schema_version` | contract schema identifier |
| `image_tag` | release image tag used by deployment automation |
| `environment` | caller-supplied environment label |
| `tenant_id` | caller-supplied tenant identifier |
| `required_secrets` | union of source runtime secret env vars needed by rendered manifests |
| `runtime_profiles` | portable profiles and their backing-service requirements |
| `required_env_vars` | conditional environment variable names needed by hosted deployments |
| `required_backing_services` | Postgres, JetStream, Neo4j/Aura, or other services required by runtime capabilities |
| `optional_capabilities` | config gates, dependencies, and health checks for optional surfaces |
| `post_deploy_health_checks` | public-safe commands or probes deployment automation should run after rollout |
| `compatibility_notes` | deployment compatibility and source-of-truth notes for contract consumers |
| `sources` | per-source capability and runtime metadata |

Environment variable entries:

| Field | Meaning |
| --- | --- |
| `name` | environment variable name |
| `required_for` | profile or capability that needs the variable |
| `secret` | whether the value must stay in a secret manager or orchestrator secret |

Backing-service entries:

| Field | Meaning |
| --- | --- |
| `name` | service identifier such as `postgres`, `nats-jetstream`, or `neo4j` |
| `required_for` | runtime behavior that depends on the service |
| `config_vars` | environment variable names that wire the service |

Per-source fields:

| Field | Meaning |
| --- | --- |
| `source_id` | source catalog ID |
| `emitted_kinds` | event kinds declared by the source catalog |
| `supported_families` | runtime families inferred from catalog and manifests |
| `required_secrets` | source-level secret env var names |
| `role_assumption_config_keys` | config keys that may contain role assumption targets |
| `source_health_receipt` | optional source health receipt JSON |
| `runtimes` | rendered runtime definitions for this source |

Per-runtime fields:

| Field | Meaning |
| --- | --- |
| `id` | fully qualified runtime ID |
| `source_id` | source integration ID |
| `tenant_id` | tenant identifier embedded in the runtime |
| `family` | optional runtime family |
| `required_secrets` | env vars referenced by runtime config |
| `role_assumptions` | role assumption metadata derived from config |
| `config` | runtime config with `env:` references preserved |

## Source deploy manifests

Sources can declare deploy metadata in:

```text
sources/<source-id>/deploy.yaml
```

Manifest shape:

```yaml
sourceId: example
secretKeys:
  - EXAMPLE_API_TOKEN
runtimes:
  - localId: default
    config:
      api_token: env:EXAMPLE_API_TOKEN
      family: default
```

Rules enforced by the renderer:

- `sourceId` must match the source catalog ID.
- `sourceId` uses lowercase kebab or snake case.
- `localId` uses lowercase kebab case.
- secret keys use `SCREAMING_SNAKE_CASE`.
- sensitive config values must use `env:VAR`.
- `env:VAR` references must be declared in `secretKeys`.
- duplicate runtime local IDs and duplicate secret keys are rejected.

## What the contract is for

Use the contract to:

- know which source runtimes a release declares,
- know which secret env vars must exist before deployment,
- know which source event kinds and runtime families are expected,
- pair an image tag with source runtime config,
- drive your own deployment automation without scraping docs.

## What the contract is not for

The contract intentionally does not define:

- cloud accounts,
- DNS names,
- private network topology,
- secret manager paths,
- concrete secret values,
- rollout approvals,
- deployment schedules,
- source sync cadence,
- customer assignments,
- alert thresholds.

Keep those in your deployment system.

## Signature artifacts

Releases can upload one signed contract per deployment target:

```text
cerebro-runtime-contract-<target>.json
cerebro-runtime-contract-<target>.json.sig
cerebro-runtime-contract-<target>.json.pem
```

Use the signature and certificate with your preferred Sigstore verification workflow. Verification policy is environment-specific, but the contract content is public and should not contain live secrets.

## Consuming a release

Suggested flow:

1. Select an immutable release tag.
2. Pull or pin `ghcr.io/writer/cerebro:<tag>`.
3. Download the contract whose suffix matches your deployment target, such as `cerebro-runtime-contract-<target>.json`.
4. Verify the contract signature if your deployment process requires it.
5. Check `required_secrets` against your secret manager.
6. Check source runtimes against your intended tenants and schedules.
7. Deploy the image with matching config.
8. Run `/livez`, `/health`, source runtime health, and graph health checks.

## Stable release procedure

1. Select a green Candidate Build run for a commit on `main`.
2. Deploy `ghcr.io/writer/cerebro@sha256:<candidate-digest>` to the canary environment.
3. Run readiness, graph, source, and version checks and save the smoke receipt at a durable URL.
4. Complete every section in the release notes template. Name migration order, downgrade limits, configuration changes, and the rollback digest.
5. Start the Stable Release workflow with the candidate run ID, `vMAJOR.MINOR.PATCH` tag, completed notes, and smoke receipt URL.
6. Approve the `stable-release` environment after checking the candidate receipt, smoke receipt, and release notes.
7. Confirm the GitHub release, semantic-version image tag, `latest` tag, signed runtime contracts, and deployment requests all use the candidate commit and digest.

Stable release windows are scheduled by the release operator. A schedule controls when the operator starts and approves the workflow; it does not create an unattended tag.

## Emergency release

Use the same candidate and stable workflows for an emergency release. Do not build or tag an unverified working tree.

1. Merge the narrow fix to `main` and wait for CI and Candidate Build to finish.
2. Pin the candidate image digest in a canary or isolated production slice.
3. Capture a smoke receipt covering the failing path plus readiness, graph health, source health, and `version`.
4. Complete the release notes. State the incident scope, compatibility result, migration requirement, configuration change, and rollback digest.
5. Start Stable Release and request the configured emergency approver for the `stable-release` environment.
6. After promotion, confirm the deployment request selected the stable channel and the promoted digest.

Emergency handling may shorten the release window. It does not bypass CI, candidate verification, checksums, signatures, provenance, runtime contracts, release-note checks, or environment approval.

## Rollback

Before promotion, record the previous stable image digest, semantic-version tag, configuration revision, and any reverse-migration limit in the release notes.

For a stateless rollback:

1. Stop the rollout.
2. Restore the previous image by digest and the matching configuration revision.
3. Run readiness, graph, source, and version checks.
4. Save the rollback smoke receipt with the incident or release record.

For a release with storage or event changes, follow the release-specific rollback order. Do not restore an older binary until the notes confirm that its storage and event readers accept the current state. If downgrade is unsafe, roll forward with a new candidate.

Test the rollback path during a release window by deploying the candidate digest to a canary, restoring the previous stable digest and configuration, checking health, and then redeploying the candidate. The Stable Release workflow requires this result in the `Rollback` and `Smoke evidence` sections when the candidate changes storage, events, or required configuration.

## Local contract inspection

Render and inspect:

```bash
mkdir -p .dist
go run ./cmd/sourcedeploy \
  -env local \
  -tenant example \
  -format contract-json \
  -image-tag v0.0.0-local \
  -out .dist/cerebro-runtime-contract.json

python3 -m json.tool .dist/cerebro-runtime-contract.json
```

List required secrets:

```bash
python3 - <<'PY'
import json
from pathlib import Path
contract = json.loads(Path(".dist/cerebro-runtime-contract.json").read_text())
for key in contract.get("required_secrets", []):
    print(key)
PY
```

## Compatibility expectations

Consumers should treat `schema_version` as the compatibility boundary. If the schema version changes, update contract consumers before using the new release contract.

Within the current schema:

- unknown fields should be ignored by tolerant consumers,
- required known fields should be validated,
- `env:` references should be resolved only by the deployment system,
- concrete secret values should never be expected in the contract.
