# Final repository archive contract

Repository archive automation must validate a final lock and a fresh runtime receipt before it can
perform an archive mutation. These artifacts use logical repository IDs only:

- `slack_companion`
- `web_public`
- `web_private`

Raw repository names, account identifiers, deployment topology, endpoints, and environment
configuration are outside the contract. A runtime adapter owns the mapping from a logical ID to an
allowlisted repository. Any other ID or an additional repository field fails validation.

## Artifacts

`final-archive-lock.schema.json` defines the stable source and authority boundary. The lock binds:

- the exact source `main` commit, source tree, and sorted path-inventory digest;
- the exact public and private target commits;
- the ledger adapter, byte digest, row count, disposition counts, and terminal-row count;
- content-addressed cutover and rollback receipt references and byte digests;
- expected freeze and archive-capability contract digests;
- a maximum age of 15 minutes or less for runtime observations.

`final-archive-receipt.schema.json` defines the live observation and postcondition boundary. A receipt
binds the canonical lock digest, the same source and target commits, zero open pull requests and
issues, an active default-branch freeze with no bypass actors, absence of candidate-status authority,
and a capability proof that can read evidence and freeze state and can apply repository
administration changes.

A `dry-run` receipt must end in `verified` with no archive postcondition. An `apply` receipt is valid
only after the archive postcondition was checked, the repository is archived, and the exact source
commit and tree remain unchanged. The schema does not authorize an archive operation by itself.

## Terminal dispositions

Slack source evidence accepts only these terminal dispositions:

- `obsolete_or_generated`
- `obsolete_or_replaced`
- `represented_public`

The web representation adapter additionally accepts:

- `covered_by_new_public_slice`
- `private_host_ops`

Every other disposition is nonterminal. The adapter-specific set is fixed by schema and must match
the source authority. A final lock requires zero nonterminal rows, and the validator derives that
result from ledger bytes instead of trusting a claimed count.

## Current-shape adapters

The validator accepts the existing Slack ledger lock shape through `slack_legacy_v1`. It accepts the
existing public or private web representation proof plus its matching inventory receipt through
`web_representation_v1`. Both adapters must prove the same source commit, tree, path inventory,
targets, row count, disposition counts, and ledger digest as the normalized lock.

Web representation evidence must declare archive readiness, contain no blockers, contain zero
nonterminal rows for the selected ledger, and record zero open pull requests and issues. Missing or
stale adapter authority fails closed.

## Validation

The validator needs the normalized lock and receipt, the current-shape authority artifacts, the
ledger and content-addressed cutover and rollback receipts, exact live commit and tree observations,
and the current authority epoch:

```bash
bash infra/scripts/validate_final_archive_contract.sh \
  --lock final-lock.json \
  --receipt final-receipt.json \
  --ledger source-disposition.tsv \
  --source-authority source-authority.json \
  --cutover-receipt cutover.receipt \
  --rollback-receipt rollback.receipt \
  --live-source-main 0000000000000000000000000000000000000000 \
  --live-source-tree 1111111111111111111111111111111111111111 \
  --live-public-target 2222222222222222222222222222222222222222 \
  --live-private-target 3333333333333333333333333333333333333333 \
  --authority-now-epoch 1
```

Add `--inventory-receipt` for a web ledger. The validator prints only a bounded result or reason code.

## Web dry-run producer

`infra/scripts/produce_web_final_archive_dry_run.sh` creates normalized lock and receipt artifacts for
the two logical web source IDs. The private adapter maps those IDs to its fixed repository allowlist;
the command does not accept repository names.

The producer reads the current source commit and tree, verifies that the ledger covers every source
blob, checks that open pull-request and issue counts are zero, and requires the active migration
freeze ruleset and required check with no bypass actors. It also reads current public and private
target commits and confirms that the caller has administration capability without changing any
repository setting. GitHub calls are read-only.

The supplied cutover and rollback receipts are bound by byte digest. Their contents remain upstream
authority inputs and must come from the reviewed cutover and rollback workflows. The producer invokes
the final archive validator before writing either output artifact. It emits a `dry-run` receipt only;
it has no apply or archive mode.

```bash
bash infra/scripts/produce_web_final_archive_dry_run.sh \
  --source-id web_public \
  --ledger public-source-disposition.tsv \
  --inventory-receipt public-source-inventory.json \
  --representation-proof representation-proof.json \
  --cutover-receipt cutover.receipt \
  --rollback-receipt rollback.receipt \
  --output-directory final-archive-output
```

The output files contain logical repository IDs and contract evidence only. Command output is limited
to a bounded success result or failure reason.
