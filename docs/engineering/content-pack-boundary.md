# Runtime Kernel And Content Pack Boundary

Status: accepted for the signed content-pack pilot.

## Decision

Cerebro keeps runtime behavior and trust enforcement in the kernel. Versioned content packs carry bounded declarative data. A pack is not executable code and cannot register a Go implementation, open a network connection, write a store, add a route, or change an authorization decision.

The kernel owns:

- tenant identity, authentication, authorization, and operator configuration;
- Source CDK execution, provider clients, retries, pagination, and event emission;
- append log, state store, graph projection, replay, and rebuild behavior;
- finding evaluation, evidence processing, action approval, and workflow state;
- HTTP, Connect, MCP, SDK, metrics, health, and operational controls; and
- pack compatibility, signature, allowlist, digest, size, ordering, conflict, and fallback enforcement.

A content pack may own:

- generated connector definitions and source catalog metadata;
- provider schemas and projection metadata already accepted by a kernel-owned parser;
- policy and finding-rule YAML;
- control catalogs, evidence mappings, and detection catalogs; and
- certification and compatibility metadata for those files.

The pilot packages two exact repository assets without removing their embedded defaults:

- `connector.deepseek.generated` contains the generated DeepSeek source catalog; and
- `policy-control.ai.generated` contains the AI agent tool-allowlist policy rule.

Keeping the original assets embedded is intentional. It proves artifact integrity, release independence, invalid-pack handling, and rollback before changing runtime selection.

## Trust Contract

Each pack has an immutable `manifest.json` and detached `manifest.sig`.

The manifest declares:

- schema, pack ID, semantic version, and pack kind;
- a manifest digest computed with the digest field empty;
- the signing-key ID;
- an inclusive minimum and exclusive maximum kernel version;
- deterministic load order;
- sorted logical content IDs, clean relative paths, media types, byte counts, and SHA-256 digests; and
- owner, certification state, source path, and rollback boundary.

An operator allowlist grants one tenant exact pack IDs, versions, manifest digests, and signing-key IDs. Verification fails closed when any grant, signature, digest, compatibility range, file type, path, or size check fails. A manifest cannot select executable media: only JSON and YAML are accepted.

Private signing keys are not committed. `tools/contentpackkeygen` creates a new owner-readable key, and `tools/contentpackbuild` finalizes and signs a release candidate. Production keys belong in the release system's signing boundary.

## Ordering, Conflicts, And Failure Behavior

Candidate directories are discovered in lexical order and verified independently. Verified candidates are ordered by `load_order`, pack ID, version, and digest. Earlier content wins. A later pack with the same pack ID or the same logical content ID is rejected with a diagnostic; it cannot shadow an embedded or previously selected asset.

External candidate count, file count, individual file size, total content size, and manifest size are bounded. Symlinks and non-regular files are rejected.

An invalid external candidate does not stop kernel startup. The resolver reports the rejection and retains the embedded defaults. Invalid embedded defaults remain a build error; the kernel must not silently replace one capability implementation with another. This distinction preserves the repository's no-hidden-capability-fallback rule while giving operators a bounded rollback path for data-only releases.

## Compatibility And Rollout

Kernel compatibility uses canonical `major.minor.patch` versions. A pack is accepted only when:

`min_inclusive <= kernel_version < max_exclusive`

A pack release does not widen its own compatibility after signing. Supporting another kernel line requires a new signed manifest and digest. Changing any payload byte also requires a new manifest digest, signature, and allowlist entry.

The pilot does not change runtime registration. A later activation change must name the kernel parser for each pack kind, retain the embedded default until rollback evidence is complete, expose selection metrics, and run source and policy contract checks against the selected bytes.

## Repository Boundary

This decision does not create a binary plugin system or a connector marketplace. Source implementations remain in-process Go packages under the Source CDK boundary. Packs contain declarative inputs for kernel-owned parsers and cannot bypass source, storage, graph, finding, or action contracts.
