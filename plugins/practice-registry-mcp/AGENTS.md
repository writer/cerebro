# Agent Instructions

Before editing non-trivial code in this repository, check the intended approach against the local practice registry.

```bash
npm run build --workspace @writer/cerebro-practice-registry-mcp
node plugins/practice-registry-mcp/dist/cli.js check-plan --intent "<work>" --language "<language>" --file "<path>" --approach "<approach>"
```

Before the final response, check the final diff. Pass `--plan-observation-id` with the matching `check-plan` `observation_id` when available; omit it only when no id was returned.

```bash
git diff -- plugins/practice-registry-mcp | node plugins/practice-registry-mcp/dist/cli.js finalize-change --plan-observation-id "<id>"
```

Trust the `passed` field. Treat `banned` results as blockers. Treat `discouraged` and `legacy_accepted` results as changes to make unless a recorded context applies. If the result is `needs_review`, resolve it through the listed owner or a research approval recorded with at least two directly supporting HTTPS sources from independent publishers and domains. Research approval adds reusable guidance; it does not approve an exception or an unindexed practice.

Keep practice copy concrete: name the state, action, owner, and alternative. Do not write hype or generic best-practice language.
