# Compliance Import Operations

## Default state

Imports are validation-only until an authorized actor accepts the staged change
plan with the expected staging version. Parsing or validating a package must not
write canonical programs, evidence claims, assessments, work, or audit records.

## Validation order

1. Enforce request, file, and archive limits.
2. Normalize relative paths and reject traversal, symlinks, duplicates, and case
   collisions.
3. Parse the manifest and identify its declared version.
4. Validate schema and references.
5. Validate tenant and disclosure policy.
6. Verify every file digest and the package digest.
7. Verify the detached signature with the configured tenant trust resolver.
8. Compare the round-trip canonical records.
9. Persist validation issues and the proposed change plan.

The validator never follows a remote key URL. Add trusted keys through the
configured resolver before retrying a signature failure.

## Failed validation

- Keep the validation result and bounded issue codes.
- Do not persist package attachments into a new blob store.
- Do not copy evidence contents into logs, metrics, events, or validation errors.
- A digest mismatch requires a new package; it is not repairable through metadata.
- A tenant mismatch is terminal for the staged import.
- An unsupported mandatory record type requires a supported exchange adapter.

## Staged commit

Before commit, verify:

- the staging version still matches the operator request
- every referenced canonical revision still exists
- the signer remains trusted for this tenant and purpose
- the change plan contains no unresolved error
- the actor has the mutation scopes required by every planned operation

Commit appends canonical domain events. If projection fails after append, replay
the events; do not rebuild the change plan against newer inputs under the same
staging ID.
