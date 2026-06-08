# EvidenceCAS references for source evidence

Cerebro does not currently implement an EvidenceCAS client in this repository.
This repository is the deployment and operator surface for Cerebro, so the
EvidenceCAS guidance here is an integration contract for source runtimes and
operators: when an upstream source produces durable evidence blobs, Cerebro
should ingest and preserve EvidenceCAS references as evidence pointers rather
than materializing payload bytes.

EvidenceCAS is the content-addressed storage plane for evidence bytes. Cerebro
remains the graph, finding, source-runtime, and operator workflow system. Store
the pointer and verification fields in graph evidence; fetch bytes from
EvidenceCAS only in an explicitly authorized operator workflow.

## Where EvidenceCAS fits

Use EvidenceCAS references in Cerebro for source evidence that is:

- too large to place in a claim or finding payload,
- sensitive enough that only a pointer should enter the graph,
- needed for byte-level custody or reconstruction,
- produced by another WriterInternal system such as Panopticon or Trusted
  Endpoint.

Examples:

- case evidence registered by Panopticon as `evidencecas://cases/...`
- Trusted Endpoint metadata evidence bundles or transparency proof bundles
- source-runtime S3 artifacts that should be represented by digest and URI
- closeout or GRC evidence attachments that need durable verification

This repo should not add direct payload ingestion paths for EvidenceCAS blobs.
The default posture is pointer-only graph evidence.

## Evidence pointer shape

Source runtimes and connector payloads should carry EvidenceCAS references in a
stable object shape:

```json
{
  "ref_type": "evidencecas.manifest.v1",
  "uri": "evidencecas://<bucket>/<key>",
  "bucket": "<bucket>",
  "key": "<key>",
  "digest": "<whole-object digest>",
  "size": 12345,
  "content_type": "application/json",
  "manifest_version": 1,
  "chunking": {"type": "fastcdc"},
  "merkle_root": "<manifest merkle root>",
  "commit_id": "<EvidenceCAS commit id>",
  "blocks_count": 4
}
```

Cerebro consumers should treat these as custody-critical fields:

- `uri`: dereferenceable EvidenceCAS pointer, not an HTTP URL
- `digest`: whole-object digest for equality and deduplication
- `merkle_root`: manifest root for reconstruction verification
- `commit_id`: EvidenceCAS provenance/audit commit identifier
- `content_type`: expected media type for safe rendering or export decisions

For graph claims, keep references under an evidence/supporting-material field
and keep findings focused on the risky state, affected asset, control, or graph
path. Do not promote a raw CAS object into a finding unless it supports a
current actionable condition.

## Bucket and key conventions

Use source-owned buckets and non-sensitive keys. Recommended patterns:

```text
Panopticon case evidence:
  bucket: cases
  key: <case_id>/evidence/<case_received_file_uuid>

Trusted Endpoint evidence:
  bucket: trusted-endpoint
  key: <tenant>/<agent_id>/<artifact_family>/<artifact_id>.<ext>

Generic source-runtime evidence:
  bucket: cerebro-source-evidence
  key: <tenant>/<runtime_id>/<source_event_id_or_artifact_id>.<ext>
```

Do not include plaintext credentials, user names, hostnames, account ids,
sensitive ARNs, prompts, command lines, diffs, workflow contents, or raw file
paths in keys, metadata, stack config, logs, or graph properties.

## Source onboarding guidance

When onboarding a source that emits EvidenceCAS references:

1. Confirm the runtime emits pointer fields only; it should not inline blob
   payloads into claims or findings.
2. Confirm each reference includes at least `uri`, `digest`, `merkle_root`, and
   `commit_id`.
3. Keep `cerebro:sourceRuntimes` config limited to non-secret runtime settings
   and `env:<NAME>` references.
4. If the runtime also reads an S3 source, keep `cerebro:s3Sources`
   least-privilege and separate from EvidenceCAS authorization.
5. Validate graph health after deploy and confirm evidence pointers appear as
   supporting evidence, not as expanded payloads.

EvidenceCAS service credentials should not be added to this repository unless a
runtime image explicitly supports and requires them. If such a runtime exists,
wire credentials through `cerebro:sourceSecretKeys` and the approved external
secret prefix, never as plaintext stack config.

## Auth and operator expectations

Cerebro operators should expect EvidenceCAS reads to require scoped bearer
tokens issued for the requested action, bucket, and key. This repository should
only carry secret references needed by a deployed runtime; it must not contain
token values.

Operational expectations:

- Keep EvidenceCAS service access internal unless external exposure has been
  explicitly reviewed.
- Require production EvidenceCAS posture before depending on it for production
  evidence: durable content storage, durable object-store JSONL audit, readiness
  checks, request limits, and redacted logs.
- Treat missing or unverifiable references as evidence-quality degradation, not
  as permission to ingest the payload through another channel.
- Preserve least-privilege IAM for `cerebro:s3Sources`; S3 source permissions do
  not imply EvidenceCAS permissions.

## Failure and troubleshooting

Common failure modes:

- Reference is absent: the source has not implemented EvidenceCAS or the CAS
  write failed upstream.
- Reference is present but cannot be verified: check token scope, service
  readiness, digest mismatch, object key, or audit/storage health.
- Payload appears inline: reject the source/runtime change and keep the graph
  pointer-only.

Troubleshooting checklist:

1. Check the upstream source logs for CAS write or verification failures.
2. Check EvidenceCAS `/readyz`, `/metrics`, and audit sink health.
3. Verify the object with the EvidenceCAS CLI:

   ```bash
   evidence-cas manifest <bucket> <key>
   evidence-cas verify <bucket> <key>
   ```

4. Confirm Cerebro graph evidence contains the `evidencecas://` URI, digest,
   Merkle root, and commit id.
5. Run the relevant repository validation for docs/config changes:

   ```bash
   git diff --check docs/EVIDENCE_CAS_REFERENCES.md README.md docs/SOURCE_ONBOARDING.md
   ```

## Production safety notes

- EvidenceCAS is not a graph database or source runtime cursor store.
- Cerebro should store evidence references, not scan CAS buckets as an
  authoritative source of events.
- Findings should remain current-state and graph-anchored; EvidenceCAS objects
  are supporting evidence.
- Keep references immutable. If the evidence bytes change, write a new object
  and ingest a new digest.
