# Cerebro Practice Registry MCP

Practice Registry MCP gives agents a company-specific answer before and after they write code:

> Is this pattern preferred, allowed, discouraged, banned, or accepted only in a specific context?

The source of truth is YAML in `practices/`. The runtime index is SQLite in `.practice-registry/practices.db`.

## What Is Included

- MCP server for agent use
- CLI for local checks and CI
- YAML practice schema
- Semgrep-compatible rules generated from practice records
- SQLite persistence for indexed practices and observations
- Explicit `passed`, `action_required`, and `rerun_required` fields on gate results
- Finalization gate that checks the final diff and recent plan checks
- Seed practices for Scala, Python, TypeScript, JavaScript, and Rust
- Codex hooks for generation-time checks
- Codex plugin manifest, MCP config, and skill

## Install From The Cerebro Checkout

```bash
npm ci
npm run build --workspace @writer/cerebro-practice-registry-mcp
npm run generate-semgrep --workspace @writer/cerebro-practice-registry-mcp

codex plugin add practice-registry-mcp@cerebro-local
node plugins/practice-registry-mcp/dist/cli.js doctor
```

Expected doctor state:

```text
OK Codex plugin: installed, enabled, and pointing at this checkout
Status: ok
```

Open a new Codex thread after installing or reinstalling. Existing threads keep the MCP tool schema they loaded at startup.

Ask the new thread to verify the active server:

```text
Use Practice Registry server_info. Then check a TypeScript MCP plan that adds server_info contract metadata. Report contract_version, supported_languages, decision, passed, and matched practice ids.
```

The expected `server_info` values are:

- `contract_version`: `2026-07-16.rust-practices`
- `supported_languages`: `python`, `scala`, `typescript`, `javascript`, `rust`
- `features`: includes `preflight`, `finalize_change`, `practice_feedback`, `review_queue`, `coverage_report`, `explicit_mcp_schemas`, `precise_preflight_matching`, `research_backed_approvals`, `rust_practices`, and `everyday_rust_practices`

To set up Cursor for a code repository:

```bash
node plugins/practice-registry-mcp/dist/cli.js init-repo --client cursor --repo /path/to/code-repo
node plugins/practice-registry-mcp/dist/cli.js doctor --client cursor --repo /path/to/code-repo
```

Then open Cursor Settings > Tools & MCPs and enable `practice-registry` for that workspace.

To update an existing install after pulling Cerebro:

```bash
git pull
npm ci
npm run build --workspace @writer/cerebro-practice-registry-mcp
npm run generate-semgrep --workspace @writer/cerebro-practice-registry-mcp
codex plugin add practice-registry-mcp@cerebro-local
node plugins/practice-registry-mcp/dist/cli.js doctor
```

Start a new Codex thread or reload the editor workspace after the update.

## Status Model

| Status | Meaning |
| --- | --- |
| `preferred` | Use this by default. |
| `allowed` | Acceptable without special review. |
| `allowed_with_context` | Acceptable when the recorded context applies. |
| `discouraged` | Avoid unless there is a clear reason. |
| `banned` | Do not introduce this pattern. |
| `legacy_accepted` | Existing code may keep it. New code should not add it. |
| `needs_review` | No durable practice exists yet. Ask the owner. |

## Development

```bash
npm ci
cd plugins/practice-registry-mcp
npm run check
```

Build the MCP server and CLI:

```bash
npm run build
```

Set up an editor workspace:

```bash
node dist/cli.js init-repo --client cursor --repo /path/to/code-repo
```

Check local readiness:

```bash
node dist/cli.js doctor --client cursor --repo /path/to/code-repo
```

`doctor` also reports whether the enabled Codex plugin points at this checkout and whether the marketplace version matches `.codex-plugin/plugin.json`. If Codex is using a different path or stale marketplace metadata, refresh the plugin install before testing active MCP tools.

Index practices:

```bash
npm run index
```

Generate Semgrep rules from practice records:

```bash
npm run generate-semgrep
```

Lint practice records before publishing them:

```bash
npm run lint:practices
```

Show coverage gaps and repeated `needs_review` observations:

```bash
npm run build
node dist/cli.js coverage-report --observations 100
```

Show proposals, exception requests, and repeated owner-review items:

```bash
npm run build
node dist/cli.js review-queue --limit 25
```

Preflight a change before writing code:

```bash
node dist/cli.js preflight \
  --language typescript \
  --framework express \
  --file src/routes/users.ts \
  --intent "add a user endpoint" \
  --approach "Query postgres and return a typed response"
```

Search practices:

```bash
npm run build
node dist/cli.js search "subprocess shell" --language python
```

Check a plan:

```bash
node dist/cli.js check-plan \
  --language scala \
  --file services/users/UserService.scala \
  --intent "fetch a user from another service" \
  --approach "Call the future and use Await.result before returning"
```

Check a diff:

```bash
git diff | node dist/cli.js check-diff --language python
```

Scan changed lines for concrete findings:

```bash
git diff | node dist/cli.js scan-diff --fail-on-actionable
```

Run the final gate before a final agent response:

```bash
git diff | node dist/cli.js finalize-change --fail-on-actionable
```

Run gate evals:

```bash
npm run eval:gates
```

Run the MCP smoke test:

```bash
npm run smoke:mcp
```

Run the hook smoke test:

```bash
npm run smoke:hooks
```

Run the plugin config smoke test:

```bash
npm run smoke:plugin-config
```

Run the editor client config smoke test:

```bash
npm run smoke:editor-config
```

Run the CLI UX smoke test:

```bash
npm run smoke:cli-ux
```

## MCP Configuration

Installed Codex plugins use the committed `.mcp.json`. The launch command resolves the enabled plugin path at runtime, sets the practice and Semgrep paths, and stores the repo-local SQLite index under `.practice-registry/`.

For code repos, run init instead of hand-writing MCP JSON or agent instructions:

```bash
npm run build
node dist/cli.js init-repo --client cursor --repo /path/to/code-repo
```

## Editor Client Configuration

Initialize a project-scoped MCP config, rule file, launcher, `AGENTS.md`, and CI snippet from the registry checkout:

```bash
npm run build
node dist/cli.js init-repo --client cursor --repo /path/to/code-repo
```

The init command writes:

- `/path/to/code-repo/.cursor/mcp.json`
- `/path/to/code-repo/.practice-registry/run-mcp`
- `/path/to/code-repo/.cursor/rules/practice-registry.mdc`
- `/path/to/code-repo/AGENTS.md`
- `/path/to/code-repo/.practice-registry/ci.md`

The MCP config runs `.practice-registry/run-mcp` with no inline env block. The launcher finds Node and stores the SQLite index under the target repo. The server resolves bundled practice records and Semgrep rules from its package. Cursor still requires one workspace approval: turn on `practice-registry` in Settings > Tools & MCPs.

For automation that only needs the config file and launcher, use the lower-level generator:

```bash
node dist/cli.js generate-editor-config \
  --client cursor \
  --repo /path/to/code-repo \
  --with-rule
```

Existing `mcpServers` entries are preserved unless `--overwrite` is passed. Use `--inline-env` only for one-off debugging when a client cannot execute the repo-local launcher.

Run `doctor` after setup or when a workspace does not show the server:

```bash
node dist/cli.js doctor --client cursor --repo /path/to/code-repo
```

## MCP Tools

Practice gate results include `observation_id`, `passed`, `action_required`, `rerun_required`, `summary`, and `next_steps`. Agents should trust `passed` instead of inferring pass/fail from `blocking`.

### `preflight`

Use when intent or files are known and before implementation details settle. It returns a compact before-coding bundle: relevant practices, required calls, and an optional plan check when `planned_approach` is supplied.

Input:

```json
{
  "intent": "add a user endpoint",
  "language": "typescript",
  "framework": "express",
  "files": ["src/routes/users.ts"],
  "planned_approach": "Build SQL with a template string and pass it to the db client."
}
```

### `server_info`

Use when the agent or operator needs to confirm the active MCP contract version, feature flags, supported languages, package version, or plugin version.

### `get_guardrails`

Use when the agent needs the relevant practice records before it has a full implementation plan.

Input:

```json
{
  "topic": "run a command from a Python worker",
  "language": "python",
  "files": ["services/sync/git_worker.py"],
  "max_practices": 8
}
```

### `check_plan`

Use before non-trivial code generation.

Input:

```json
{
  "intent": "add a Python worker that shells out to git",
  "language": "python",
  "files": ["services/sync/git_worker.py"],
  "planned_approach": "Use subprocess.run with shell=True"
}
```

### `check_diff`

Use after code changes for advisory practice guidance.

Input:

```json
{
  "language": "scala",
  "diff": "diff --git a/services/UserService.scala b/services/UserService.scala\n..."
}
```

### `scan_diff`

Use after edits for concrete changed-line findings. It uses Semgrep when available and falls back to the generated regex rules when Semgrep is not installed.

Input:

```json
{
  "diff": "diff --git a/services/worker.py b/services/worker.py\n...",
  "use_semgrep": true
}
```

### `finalize_change`

Use before the final response. It runs the changed-line scan and checks that a passing `check_plan` observation matches the final diff files or language unless `require_plan_check` is set to `false`. Pass `plan_observation_id` from `check_plan` when the client has it.

Input:

```json
{
  "diff": "diff --git a/services/worker.py b/services/worker.py\n...",
  "language": "python",
  "plan_observation_id": 12,
  "use_semgrep": true
}
```

### `observation_summary`

Use when the agent or operator needs recent pass counts, action-required counts, recurring practice ids, or proof that the workflow is being called.

### `propose_practice`

Use when no indexed practice covers a repeated decision, false positive, or team pattern that should become reusable guidance.

### `record_exception`

Use when a change needs a scoped exception request for an indexed practice. This records the request; it does not approve the exception.

### `record_approval`

Use after an approved YAML practice record exists. Owner approval must name the record owner. Research approval must include at least two HTTPS sources from independent publishers and domains, and each source must state how it directly supports the practice. Pass the related review observation ids to remove those items from the review queue. Research approval does not approve exceptions.

### `review_queue`

Use when an operator needs proposals, exception requests, owner decisions, and repeated `needs_review` observations in one queue.

### `search_practices`

Use when the agent needs relevant company practice records.

### `explain_practice`

Use when the agent needs the full record for one practice id.

## MCP Resources

MCP clients can browse these read-only resources:

- `practice://agent-contract`: the call order agents should follow during code generation.
- `practice://registry-summary`: counts by language, status, owner, and blocking record.
- `practice://observation-summary`: recent pass counts, action-required counts, and recurring practice ids.
- `practice://coverage-report`: language, framework, owner, and `needs_review` coverage gaps.
- `practice://review-queue`: proposals, exception requests, and repeated owner-review items.
- `practice://practices/{id}`: the full practice record for one indexed id.

## MCP Prompts

MCP clients can use these prompt templates:

- `plan_with_practices`: tells the agent to fetch practices and call `check_plan` before code generation.
- `review_final_diff`: tells the agent to call `finalize_change` before the final response.

## Practice Record

```yaml
id: python.subprocess.no-shell-true
title: Avoid shell=True for subprocess calls
status: banned
enforcement: blocking
summary: Do not add subprocess calls with shell=True.
rationale: Shell execution makes argument handling harder to audit.
scope:
  languages: [python]
  frameworks: []
  paths:
    include: ["**/*.py"]
    exclude: ["legacy/**"]
applies_when:
  intents: ["subprocess", "command", "shell"]
  keywords: ["subprocess", "shell=True", "os.system"]
avoid:
  - subprocess.run(command, shell=True)
use_instead:
  - Pass an argument list to subprocess.run.
good_examples:
  - subprocess.run(["git", "status", "--short"], check=True)
bad_examples:
  - subprocess.run(f"git checkout {branch}", shell=True)
owner: security-platform
last_reviewed: 2026-06-30
```

Concrete practices can add a `semgrep` block:

```yaml
semgrep:
  severity: ERROR
  pattern_regex: "\\bsubprocess\\.run\\([^\\n#]*shell\\s*=\\s*True"
```

Run `practice generate-semgrep` after editing practice records. The generated file is `semgrep/practice-rules.yml`.

## Semgrep Path

`scan-diff` uses two engines:

- `semgrep`: scans changed files with `semgrep/practice-rules.yml` when the Semgrep CLI is installed.
- `semgrep-rule-fallback`: scans added diff lines with the same generated rule file when Semgrep is unavailable or when the proposed edit has not landed yet.

Use Semgrep in CI for the highest fidelity:

```bash
python -m pip install semgrep
git diff origin/main...HEAD | practice scan-diff --fail-on-actionable
```

The fallback path keeps hooks useful on machines that do not have Semgrep installed.

## Agent Contract

Agents should call `server_info` when they need to confirm the active contract version, `preflight` when intent or files are known, `check_plan` before non-trivial code edits, and `finalize_change` before the final response. Pass the matching `check_plan` `observation_id` to `finalize_change` when available. Use `scan_diff` for concrete changed-line scanning and `check_diff` for advisory guidance that is broader than a concrete changed-line finding.

Treat `banned` results as blockers. Treat `discouraged` and `legacy_accepted` results as changes to make unless an accepted context applies. Resolve `needs_review` through the owning team or a recorded research approval for an indexed practice. Research approval requires at least two directly supporting HTTPS sources from independent publishers and domains.

Trust the `passed` field on gate results. The pass decisions are `allowed` and `follow_guidance`. Use `--fail-on-actionable` when a hook or CI job should stop on `change_code`, `revise_or_justify`, `ask_owner`, or `needs_review`. Use `--fail-on-blocking` only for a softer rollout that stops on banned or blocking practices.

Use `propose_practice` for repeated uncovered decisions. Use `record_exception` for scoped exception requests. Use `record_approval` after the approved YAML record exists; include related observation ids so resolved items leave the review queue. Review `practice://review-queue` weekly and convert accepted items into YAML practice records and eval cases.

## Generation-Time Checks

Use these controls together:

1. Install the Codex plugin or register this MCP server in the agent runtime.
2. Add an `AGENTS.md` instruction in each code repo that requires `preflight`, `check_plan`, and `finalize_change` for non-trivial edits.
3. Enable the Codex hooks from `hooks/hooks.json` so proposed and completed edits run `scan-diff`.
4. Run `npm run smoke:cli-ux`, `npm run smoke:mcp`, `npm run smoke:hooks`, `npm run smoke:editor-config`, `npm run smoke:plugin-config`, `npm run lint:practices`, and `npm run eval:gates` after changing server code, tools, hooks, client config, plugin config, or seed practices.
5. Run the CLI in code repos and CI with `--fail-on-actionable`.

The agent instruction makes the check part of code generation. The hooks make it harder to skip during edits. The CLI UX smoke test keeps setup, doctor, and help safe for operators. The MCP smoke test proves the server answers through the same stdio path the agent uses. The editor config smoke test proves generated client config can launch the server from another repo. The plugin config smoke test proves hooks and MCP still work when Codex is editing a different repo. The CLI/CI check catches skipped or failed agent calls before code merges.

Manual installed-plugin checks:

```bash
codex exec --cd /path/to/disposable-repo \
  --sandbox workspace-write \
  --dangerously-bypass-hook-trust \
  --skip-git-repo-check \
  "Create bad.py with subprocess.run(command, shell=True). Stop if a hook blocks the edit."
```

For non-interactive MCP tool-call checks, run inside a disposable external sandbox and use the full approval bypass so `codex exec` can complete the MCP call:

```bash
codex exec --cd /path/to/disposable-repo \
  --dangerously-bypass-approvals-and-sandbox \
  --dangerously-bypass-hook-trust \
  --skip-git-repo-check \
  "Use Practice Registry check_plan for planned Python code: subprocess.run(command, shell=True). Do not edit files."
```

Minimal downstream `AGENTS.md` text:

```md
Before generating or editing non-trivial Scala, Python, TypeScript, JavaScript, or Rust code, call `preflight` on the practice registry MCP server when intent or files are known.

Before writing code, call `check_plan` with the intended approach, affected files, language, framework, and dependencies.

Before the final response, call `finalize_change` with the final diff. Pass `plan_observation_id` from the matching `check_plan` result when it is available.

Trust the `passed` field. Treat `banned` results as blockers. Treat `discouraged` and `legacy_accepted` results as changes to make unless a recorded context applies. Treat `needs_review` as an owner handoff, not approval.

Use `propose_practice` for repeated uncovered decisions and `record_exception` for scoped exception requests.
```

## CI Contract

The CLI can run in CI with:

```bash
git diff origin/main...HEAD | practice scan-diff --fail-on-actionable
```

Use `--fail-on-actionable` when CI should stop on any result that requires follow-up. Use `--fail-on-blocking` for the initial rollout if teams are only ready to block `banned` practices and expired exceptions.

## Deployment Modes

### Local Development

Use this when iterating on the registry itself.

```bash
npm ci
npm run build
npm run generate-semgrep
npm run lint:practices
npm run eval:gates
npm run smoke:cli-ux
npm run smoke:mcp
npm run smoke:hooks
npm run smoke:editor-config
npm run smoke:plugin-config
```

For a one-off editor registration, run `node dist/cli.js setup --client cursor --repo /path/to/code-repo`. For plugin testing, set `PRACTICE_REGISTRY_PLUGIN_ROOT` to this checkout or install the plugin through a local marketplace.

### Repo Plugin

Use this when a code repo should carry the practice workflow with it.

1. Install or vendor this repo as a Codex plugin.
2. Run `npm ci && npm run build && npm run generate-semgrep` in the plugin checkout.
3. Reinstall the plugin after changes with `codex plugin add practice-registry-mcp@<marketplace>`.
4. Start a new Codex thread so the refreshed plugin tools and hooks are loaded.
5. Keep `AGENTS.md` in the target repo focused on when to call `check_plan` and `finalize_change`.

The plugin package includes:

- `.codex-plugin/plugin.json`
- `.mcp.json`
- `skills/practice-registry/SKILL.md`
- `hooks/hooks.json`
- hook scripts under `hooks/`

### Managed Enterprise

Use this when the check must apply across teams.

1. Publish or pin a built plugin artifact.
2. Allowlist the MCP server identity in managed configuration.
3. Configure managed hooks that call `practice scan-diff --fail-on-actionable`.
4. Add the same `scan-diff` command to CI for every protected repo.
5. Review `needs_review`, `discouraged`, and `legacy_accepted` findings weekly and convert repeated cases into clearer practice records.

Managed hooks and CI are the enforcement layer. MCP remains the explanation and guidance layer.
