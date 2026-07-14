# Content Pack Release And Rollback

Use this runbook for data-only content-pack releases. Kernel releases continue to use the existing release contract.

## Prepare A Candidate

1. Copy the approved generated asset into a new versioned pack directory.
2. Update `pack_id`, `version`, kernel compatibility, content IDs, owner, certification state, and source path in `manifest.json`.
3. Generate or retrieve the release signing key outside the repository. For a local test key:

   ```sh
   go run ./tools/contentpackkeygen -private-key-out /secure/path/content-pack.key
   ```

4. Finalize content digests and sign the manifest:

   ```sh
   go run ./tools/contentpackbuild \
     -dir contentpacks/pilot/connector-deepseek \
     -private-key /secure/path/content-pack.key
   ```

5. Add the public key and exact pack ID, version, manifest digest, and signing-key ID to the tenant's operator allowlist.
6. Validate the artifact independently:

   ```sh
   make content-pack-check
   ```

Do not commit a private key. Do not reuse a manifest signature after changing the manifest or content.

## Release A Pack

1. Publish the immutable directory under its pack ID, version, and manifest digest.
2. Mount the pack root and allowlist, then set `CEREBRO_CONTENT_PACK_ROOT`, `CEREBRO_CONTENT_PACK_ALLOWLIST_PATH`, `CEREBRO_CONTENT_PACK_TENANT_ID`, and the target `CEREBRO_CONTENT_PACK_KERNEL_VERSION`.
3. Confirm the target kernel version is inside the signed compatibility range.
4. Update the tenant allowlist to the new exact version and digest.
5. Restart one instance and inspect the `content packs:` startup records plus `cerebro.content_pack.selections` accepted, rejected, and embedded-fallback states.
6. Expand the allowlist only after the staged tenant loads the intended content IDs and contract validation passes.

Pack release approval does not approve a kernel release. Kernel release approval does not approve a new pack digest.

## Roll Back A Pack

1. Remove the new digest from the tenant allowlist or restore the prior exact version and digest.
2. Reload pack selection.
3. Confirm the selected content IDs resolve to the prior pack or embedded defaults.
4. Confirm the rejected candidate reports the removed digest and the kernel remains available.
5. Keep the failed artifact immutable for investigation. Publish a new version for any correction.

Rollback does not require reverting or rebuilding the kernel. If embedded defaults cannot load, treat that as a kernel release failure and use the kernel rollback procedure.

## Rotate A Signing Key

1. Add the new public key to the operator allowlist.
2. Sign a new manifest version with the new key ID.
3. Grant the new version, digest, and key ID together.
4. Remove the old key only after no active allowlist entry references it.

The verifier rejects unknown, malformed, or ungranted keys.
