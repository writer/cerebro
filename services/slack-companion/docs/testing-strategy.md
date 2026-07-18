# Testing Strategy

Use this guide before adding or changing tests.

## Default Decision Rule

Start from the behavior contract, then choose the smallest test layer that proves it.

1. Use synthetic evals when the contract depends on model interpretation, prompt behavior, answer quality, or multi-turn continuity.
2. Use integration-style tests when the contract is Slack-visible behavior, command routing, durable state, approval flow, schedule execution, goal execution, or final delivery.
3. Use component tests when the contract crosses modules but can be proven through local ports such as clocks, stores, queues, or fake agent runners.
4. Use unit tests for local deterministic logic: parsing, normalization, scoring, guardrails, formatters, and pure state transitions.

## Mocking Rules

- Mock one boundary, not a whole workflow.
- Prefer existing fixtures from `test/fixtures.ts`.
- Do not assert logging, span attributes, or metrics in behavior tests unless telemetry output is the contract.
- If a user-visible workflow needs several mocks to pass, move the test up a layer.
- If an eval or integration test already proves the user-visible behavior, keep unit tests focused on local edge cases.

## Coverage Budget

For one behavior contract, aim for:

1. One happy path.
2. One likely failure or guardrail path.
3. One boundary case only when it has production risk or prior regression history.

Do not add parallel tests that exercise the same contract through different implementation details.

## Existing Layers

| Layer | Files | Use |
| --- | --- | --- |
| Synthetic evals | `test/autonomy-synthetic-evals.test.ts` | Prompt and agent behavior contracts with controlled inputs. |
| Assistant replay evals | `src/learning/assistant-replay-eval.ts`, `npm run eval:assistant` | Follow-up continuity, exact source-subject binding, evidence grounding, coverage honesty, execution efficiency, latency, human follow-up burden, outcome closure, correction learning, goal understanding, teammate ownership, and natural Slack copy. |
| Specialist routing eval | `scripts/specialist-routing-eval-report.ts`, `npm run eval:specialists` | Exact bounded preservation of model-selected Librarian, Researcher, Analyst, Coordinator, Triage, QA, Developer, and Compliance work, including rejection of host-inferred roles. |
| Real-traffic replay gate | `src/learning/traffic-replay.ts`, `npm run eval:traffic` | Redacted traffic cases, exact or capability-equivalent source choice, evidence refs, required and forbidden answer facts, outcome closure, verified corrections, evidence counterfactuals, citation latency, teammate expectations, and baseline regression. |
| Frontier hillclimb | `scripts/assistant-frontier-hillclimb.ts`, `src/learning/assistant-frontier-eval.ts`, `src/learning/assistant-encounter-corpus.ts`, `npm run eval:hillclimb` | Backfilled human requests, Opus-generated compositional cases, Opus-generated policy mutations, real production-path candidate runs, three independently blinded Opus judges, separate Opus deliberation, a second mutation round, and two independently sealed held-out promotion decisions. |
| Contract corpus | `evals/assistant-hard-corpus.jsonl`, `src/learning/assistant-hillclimb.ts`, `npm run eval:contract:dev`, `npm run eval:contract` | Fast low-level contract regression checks over exact receipts, subject bindings, action truthfulness, safe refusal, private-work resilience, and teammate closure. These checks do not select the production policy. |
| Offline assistant harness | `src/learning/assistant-offline-harness.ts`, `src/learning/assistant-offline-judge.ts`, `scripts/assistant-offline-harness.ts`, `npm run eval:offline` | The production Flue and Opus planner, fixture-backed source tools, claim ledger, recovery, Slack presentation, thread state, delivery receipt, and blind Opus judgment without a Slack connection. |
| Agent-run integration | `test/agent-runtime.test.ts` | Exact tool lookup, argument validation, approval resume, independent verification, acceptance checks, and completion receipts. |
| Offboarding-control integration | `test/offboarding-control-tools.test.ts` | Exact Okta, GitHub, and AWS coverage, source refresh stages, stable dry-run binding, provider-action approval, post-action recollection, independent closure, and a complete durable run through two approval checkpoints. |
| Response feedback | `test/assistant-feedback.test.ts`, `test/evidence-governance.test.ts`, `test/operational-intelligence.test.ts`, `test/traffic-replay.test.ts` | Idempotent ratings, atomic typed personal/team projections, durable evidence receipts, source-version invalidation, corroborated source feedback, reversible durable preferences, task-correction ranking, outcome signals, legacy compatibility, time-ordered reads, Slack author resolution, safe prompt boundaries, and replay privacy gates. |
| Recursive improvement | `test/improvement-control-plane.test.ts`, `test/improvement-delegation.test.ts`, `test/improvement-worker.test.ts`, `test/improvement-worker-config.test.ts`, `test/improvement-candidate-receipt.test.ts`, `test/improvement-workflow-contract.test.ts` | Signal aggregation, private artifact boundaries, signed expiring author delegations, deterministic rollout cohorts, hard budgets, author/verifier job isolation, credential separation, exact-candidate signatures, state transitions, evaluator separation, candidate receipts, and promotion gates. |
| Policy discovery candidates | `test/cerebro-policy-candidates.test.ts` | Exact Cerebro request and response contract, operator authorization, opaque Slack origin, hypothesis and graph privacy, proof and shadow lifecycle, and separation from GitHub writes or policy promotion. |
| Teammate goal reconciliation | `test/teammate-goals.test.ts` | Host-observed goal linking, live state refresh, acceptance criteria, and rejection of unpersisted promises. |
| Integration-style tests | `test/*runner*.test.ts`, `test/slack-*.test.ts`, `test/scheduled-jobs.test.ts` | Runtime wiring, Slack flows, schedules, and durable goal behavior. |
| Component tests | focused service tests under `test/*.test.ts` | Cross-module deterministic contracts with local fakes. |
| Unit tests | parser, formatter, safety, and normalizer tests | Local deterministic helpers. |

Run focused checks first, then finish with:

```sh
npm run typecheck
npm run architecture:check
npm test
npm run eval:specialists
```

For a deployment canary of terminated-identity access control, run the companion inside its existing VPC task definition and use the production assistant path. The canary must name exact Okta, GitHub, and AWS runtime IDs, create a read-only snapshot first, and reopen its decision-packet receipt. Source refresh requires the normal reviewed approval. Never execute a provider action against a real identity as a canary; stop after the dry-run proposal unless the exact finding, target, proposal digest, rollback, and human approval are all present.

Run `AWS_PROFILE=cerebro-sec-dev AWS_REGION=us-east-1 CEREBRO_IMPROVEMENT_ARTIFACT_BUCKET=<bucket> npm run eval:hillclimb` for policy optimization. The runner reads only redacted human requests from encounter stories and the encrypted conversation corpus. It never treats prior assistant prose as factual training data and never writes conversations to source control or event logs. Opus creates development cases that compose at least three difficulty axes, including ambiguous subjects, stale and conflicting evidence, partial coverage, failed sources, frustrated corrections, multi-intent requests, authorization boundaries, action verification, safe secret alternatives, machine noise, incident pressure, long-thread distractions, risk attestation, bounded negative conclusions, and delivery follow-through.

The production assistant and each mutation run through the actual Flue planner, tool policy, fixture-backed sources, evidence ledger, recovery, presentation, thread state, and delivery path. Policy mutations come from Opus reviews of development failures rather than a hand-authored candidate list. Three Opus judges independently see anonymous responses in different orders: a security principal, the requesting teammate, and an adversarial evidence examiner. A separate Opus deliberator reads their disagreements and selects the generalizing policy. The train winner produces a second generation of mutations, validation selects the finalist, and production plus that finalist see the untouched static held-out partition. A second shadow partition is generated from unused historical requests and sealed before the static decision. A finalist must clear both independent held-out decisions. If the static decision rejects it, Opus may generate a third repair generation from those failures; only the new repairs can earn promotion on the untouched shadow partition. No substring matcher or deterministic quality score selects or promotes a policy.

`npm run eval:hillclimb:dev` runs the same complete architecture with smaller case and mutation counts for wiring checks. Use `npm run eval:contract:dev` for fast exact-field regression while editing corpus contracts. Contract scores are not hillclimb results.

Run `AWS_PROFILE=cerebro-sec-dev npm run eval:offline -- --case <case-id> --candidate production` to reproduce one human interaction through the production assistant path without Slack. Source tools are replaced with fixed evidence packets from the corpus; research planning, tool policy, evidence receipts, recovery, presentation, thread persistence, and delivery bookkeeping remain active. An Anthropic Claude Opus judge then reads the full interaction, authoritative sources, actual source calls, grounded subjects, and delivered answer. It evaluates task completion, factual correctness, grounding, uncertainty calibration, subject integrity, initiative, and communication semantically. Success criteria are examples rather than substring tests, and visible citation markers or receipt ids are not required. When multiple candidates are supplied, they are compared under anonymous labels in the same judgment call.

Use repeated `--case` and `--candidate` flags for a bounded development comparison. Development mode excludes held-out cases, writes the judge's failure modes and actionable feedback as one JSONL record per failed response, and reuses cached assistant runs and judgments unless `--refresh` is supplied. Set `CEREBRO_IMPROVEMENT_ARTIFACT_BUCKET` or pass `--conversation-bucket` to include newly redacted conversation failures in development runs.

Run `AWS_PROFILE=cerebro-sec-dev npm run eval:offline:held-out -- --candidate production --candidate <development-winner>` once after selecting a development winner. Held-out mode reads only static held-out cases and reports promotion readiness when exactly two candidates are supplied. Both planner and execution models must be Anthropic Claude Opus models; the harness rejects other model families.

Before a release that changes prompts, model selection, tool packs, durable planning, correction handling, citations, or answer policy, pipe the redacted traffic JSONL corpus to `npm run eval:traffic`. Human cases should state whether the answer must capture an objective, resolve scope, make a recommendation, own follow-up, or avoid a user decision. Use tool capabilities when several registered tools satisfy the same evidence job. Add required or forbidden answer facts when correctness depends on a source-backed state that proxy scores cannot verify. Citation changes must pass missing, restricted, stale, and contradicted evidence counterfactuals and stay inside the configured p95 overhead budget. Keep raw Slack text and private traffic artifacts outside the repository.
