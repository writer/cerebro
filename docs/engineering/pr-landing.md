# PR landing

This repo treats deterministic CI and protected GitHub rules as the merge
gate. A PR should not be merged while a required check is failing or an
active review thread remains unresolved.

Use the landing helper when merging from a local checkout:

```sh
make land-pr PR=<number>
```

For administrator merges:

```sh
make land-pr PR=<number> LAND_PR_ADMIN=true
```

The helper enforces this order:

1. Wait for `tenant-data leak check` to pass.
2. Confirm there are no active review threads.
3. Merge with the original PR head SHA pinned through `--match-head-commit`.
4. Delete the same-repository PR branch only after the merge succeeds.

The post-merge health workflow audits the merged commit's main-branch
workflows and release-tag position. Release tag lag is informational unless
the release workflows themselves are failing.
