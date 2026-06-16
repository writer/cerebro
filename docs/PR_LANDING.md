# PR landing

This repo treats Droid review completion as a merge gate, not as an advisory
comment. A PR should not be merged while the latest Droid bot comment is an
error or an in-progress placeholder.

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
2. Wait for the latest Droid bot comment to be a finished review.
3. Merge with the original PR head SHA pinned through `--match-head-commit`.
4. Delete the same-repository PR branch only after the merge succeeds.

Do not use `gh pr merge --delete-branch` directly before Droid has posted a
finished review. The Droid action checks out the PR by head branch during its
review phase, so deleting the branch early can turn the review into a prepare
error instead of a code review.

The post-merge health workflow audits the merged commit's associated PR. It
fails in strict mode when the PR has an unsuperseded Droid error comment, a
stale in-progress Droid comment, or no finished Droid review comment.
