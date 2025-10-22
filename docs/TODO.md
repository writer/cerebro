## AI Security Autonomy Roadmap

### Stage 0 – Planning & Inventory
- [ ] Audit existing SOC playbooks, historical incident data, and agent telemetry to understand current coverage and gaps.
- [ ] Identify available sandbox tenants, red-team environments, and simulation assets that Cerebro can reuse.
- [ ] Map current frontend (FE) analyst workflows, instrumentation, and UI components that can surface simulations or collect feedback.
- [ ] Align stakeholders (product, security engineering, infra, data) on success metrics, review processes, and ownership for the autonomy initiative.
- [ ] Define budgetary / compute constraints and target cadence for evaluation and training cycles.

### Stage 1 – Evaluation Foundation ("Walk")
- [ ] Convert prioritized playbooks and past incidents into reproducible benchmark suites with success/failure assertions.
- [ ] Automate benchmark execution in CI/CD so agent scaffolding, prompts, and tools are scored on every change.
- [ ] Instrument dashboards / alerts for benchmark drift, failure trends, and regression detection.
- [ ] Document baseline benchmark performance as reference for future fine-tuning or RL interventions.

### Stage 2 – Data Operations Loop
- [ ] Expand capture of investigation transcripts, tool telemetry, and review decisions into a normalized event schema.
- [ ] Stand up pipelines that label traces (outcomes, failure modes, remediation steps) and surface low-quality data for curation.
- [x] Instrument the Cerebro frontend to log rich analyst interaction events (queries run, hypotheses tested, tool invocations, approvals) and join them with backend traces.
- [ ] Produce exportable fine-tuning corpora for Cerebro-specific model adaptation, including prompt/response/tool traces.
- [ ] Establish data governance (privacy, retention, redaction) and monitor for sensitive leakage before training usage.

### Stage 3 – Cybersecurity Training Gym & RL
- [ ] Design containerized attack/defense scenarios that mirror priority customer environments, with automated scoring APIs.
- [ ] Build “analyst-in-the-loop” FE experiences that replay simulated incidents, capture UI-driven actions, and emit reward signals (accept/reject, dwell time, analyst grading).
- [ ] Integrate gym invocation into Cerebro agent workflows (sandboxed execution, telemetry capture, rollback controls).
- [ ] Implement reinforcement learning loops (e.g., RLHF + execution feedback) that leverage gym results to improve agent policies.
- [ ] Schedule periodic regression runs to validate that RL updates outperform Stage 1 baselines.

### Stage 4 – Organizational Enablement & Guardrails
- [ ] Prototype high-trust red-team sandboxes with graduated access controls and audit trails.
- [ ] Update human-in-loop guardrails, approval workflows, and escalation policies to accommodate higher autonomy levels.
- [ ] Partner with the FE team to ship UI affordances for simulations, analyst scoring prompts, and safe-mode toggles with traceability.
- [ ] Train SOC operators and reviewers on new evaluation dashboards, autonomy behaviors, and override mechanisms.
- [ ] Create cross-functional operating rhythm (e.g., weekly triage of benchmark regressions, monthly RL review board).

### Stage 5 – Rollout & Continuous Improvement
- [ ] Define release gates for promoting autonomous capabilities from pilot to production tenants.
- [ ] Launch A/B tests or phased rollouts, measuring labor savings, detection efficacy, and false-positive impacts.
- [ ] Run coordinated FE experiments (e.g., UI-driven A/B tests) that measure analyst productivity and reward quality as autonomy increases.
- [ ] Feed post-deployment telemetry back into the data pipelines for continual fine-tuning and gym scenario updates.
- [ ] Publish quarterly progress reports to maintain stakeholder alignment and adjust priorities as adversary capabilities evolve.

### OODA Loop Integration
#### Observe
- [x] Extend FE instrumentation to capture real-time analyst context (active entity, filters, timeline selections) and stream to the autonomy data plane.
- [ ] Mirror observation telemetry with live attack-surface and sensor feeds so agents see the same picture analysts do.
- [ ] Stand up observability pipelines that flag missing or low-signal observations for data-quality remediation.

#### Orient
- [ ] Layer graph/embedding analytics over observation streams to surface emerging threats, playbook gaps, and scenario priors inside Cerebro dashboards.
- [ ] Auto-refresh benchmark inputs and training gym scenarios based on orientation analytics (e.g., new TTP clusters).
- [ ] Provide analysts with orientation summaries (hypothesis suggestions, relevant historical incidents) linked to the live case.

#### Decide
- [ ] Embed decision-support panes in the FE/agent console showing benchmark deltas, autonomy risk scores, and recommended next actions.
- [ ] Capture analyst approvals/overrides as structured decision events with rationale tagging for downstream RL signals.
- [ ] Implement policy checks that gate high-risk decisions while logging outcomes for governance review.

#### Act
- [ ] Wrap containment/remediation tools with action adapters that report execution traces, success metrics, and collateral effects.
- [ ] Feed action outcomes back into the RL gym and evaluation suites to close the reward loop automatically.
- [ ] Automate post-action reviews (retros, diffing expected vs. observed impacts) and schedule them when anomalies are detected.
