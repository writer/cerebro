# Telemetry Map Spec

Status: active
Target file: `TELEMETRY.md`

## Purpose

`TELEMETRY.md` is the production query map for this service. It helps an operator or agent move from a Slack symptom, trace id, tool name, or event name to the first useful query and the next diagnostic step.

## Required Shape

Start with YAML frontmatter:

```yaml
---
spec: ./TELEMETRY.spec.md
---
```

Use these sections in order:

1. `Goal`
2. `Where To Query`
3. `Investigation Pivots`
4. `Query Recipes`
5. `Domains`
6. `Configuration`

## Rules

- Keep the file short enough to scan during an incident.
- Prefer stable event names, span names, metrics, and attributes over prose.
- Use fake placeholders such as `<trace_id>`, `<channel_id>`, and `<thread_ts>`.
- Do not include raw Slack text, prompts, generated code, code hashes, tool arguments, tool results, IPC payloads, child output, target identifiers, toolset digests, evidence receipts, exception messages, credentials, tokens, cookies, or real ids.
- Code Mode telemetry uses fixed outcome, termination, limit, and child-exit enums plus bounded counts and durations. Nested tools retain their normal tool spans; the outer executor must not copy nested inputs or outputs into its span.
- Put setup and instrumentation design elsewhere. This file is for incident triage.
- Query recipes should answer one question: did ingress accept the event, did the worker run, did the assistant fail, did a tool fail, or did Slack delivery fail?

## Review Checklist

- A Slack thread can be joined to logs through `messaging.message.conversation_id` or `messaging.message.thread_ts`.
- A captured error can be joined to surrounding logs through `trace_id`.
- Tool failures can be filtered by `tool.name`.
- A terminated Code Mode execution can be filtered by `operation.name=assistant.code.execute` and `assistant.code.outcome` without reading the program, tool payloads, or target identifiers.
- The file names the metric and log switches that change visibility.
- No raw request bodies, messages, generated code, tool payloads, child output, target identifiers, receipts, secrets, or real user identifiers are present.
