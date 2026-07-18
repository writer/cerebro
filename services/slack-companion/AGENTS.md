# AGENTS.md

## Product Copy

Write UI copy like a product operator wrote it: concrete nouns, real states, real actions, no hype, no self-congratulation, no meta commentary about the design, and no phrases that describe the UI instead of helping the user do the job.

## Assistant Routing

Do not add synchronous deterministic routing for Slack assistant questions.

All non-command Slack assistant questions must go through the Pi assistant work loop. Do not add regex, keyword, classifier, or hand-authored intent routers that answer app mentions directly, bypass Pi, or choose self-context, memory, Slack search, graph, or casual-response paths before Pi runs.

When Pi is disabled or unavailable, return the blocked response. Do not substitute graph reasoning, memory lookup, Slack search, self-context, or canned conversational replies as a deterministic fallback.

Slash commands, Block Kit actions, modals, safety refusals, and explicit memory-save commands may stay deterministic because they are user-selected commands or safety controls, not assistant-question routing.

## Autonomy

Preserve the assistant autonomy contract. Broad operator requests should be treated as goals: inspect context, plan, execute available tools, checkpoint progress, revise after results, and ask for input only when no safe default exists.

Guardrails should stay narrow and capability-based. Hard blocks should focus on secret exfiltration, credential exposure, workspace escape, and disabling exfiltration or audit controls. Irreversible production, infrastructure, graph, and data changes need dry-run evidence and a reviewed approval path before execution.

## Operating Contracts

- Keep agent tools in `src/agent/tools` and update `src/agent/tools/tool-metadata.ts` when adding or changing tools.
- Use [docs/operating-contracts.md](docs/operating-contracts.md) for tool authority, runtime boundary, credential, and target-ownership rules.
- Use [docs/testing-strategy.md](docs/testing-strategy.md) before adding tests. Synthetic evals cover model behavior, integration-style tests cover Slack/runtime behavior, and unit tests cover local deterministic logic.
- Use [TELEMETRY.md](TELEMETRY.md) when debugging production behavior from a Slack thread, trace id, tool name, or event name.
- Run `npm run architecture:check` after changing tool locations, operating docs, telemetry docs, or architecture rules.
