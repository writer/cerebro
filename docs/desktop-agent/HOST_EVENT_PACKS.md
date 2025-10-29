# Desktop Agent Host Event Packs

## Overview

Host event packs let the desktop agent schedule repeatable snapshot tasks and ad-hoc artifact collections without baking schedules into the binary. Packs can be sourced locally from disk or delivered by the control plane and executed alongside regular snapshot and event collectors.

At runtime the `Manager` loads packs, materialises scheduled tasks, and invokes the listed collectors with merged configuration values. Telemetry produced by pack tasks is tagged so the backend can attribute results to the originating pack and task.

## Pack Sources

- **Local packs** – YAML files under `CEREBRO_PACK_DIRECTORY` (or `--pack-dir`) are parsed by `pack.Loader`. Missing directories are ignored so development environments can run without local packs.
- **Remote packs** – When `CEREBRO_ARTIFACT_POLL_INTERVAL` is set, the agent requests matching packs from `/telemetry/host/packs`. Remote schedules are merged with local ones on every poll using `syncSourceTasks`.

The agent keeps local and remote packs in the same scheduler map. Tasks are keyed by `source:pack:task`, letting newer definitions replace older copies without requiring a restart.

## Scheduling Lifecycle

1. **Initialization** – `initializeScheduledTasks` loads local packs at startup and seeds `scheduledTasks`.
2. **Polling** – `pollRemotePacks` periodically calls `FetchArtifactPacks`, converting API definitions into internal `pack.Pack` structs.
3. **Eligibility** – Before each run, `taskEligible` evaluates discovery clauses (tags, site, org, hostname, registered collectors). Clauses can be negated with `!` and support regex host matching via `hostname~`.
4. **Execution** – Due tasks are cloned to prevent mutation, merged with collector configuration (`buildTaskParameters`), and executed by the referenced snapshot collector.
5. **Result tagging** – `tagTelemetryWithTask` annotates telemetry with `pack`, `task`, and optional resource hints so downstream systems can trace execution.

Intervals default to the task’s `interval`, then fall back to `CEREBRO_COLLECTION_INTERVAL`, and finally one minute. A 50% jitter is applied to stagger execution across hosts.

## Pack Definition Schema

Pack files are standard YAML documents that map directly to `pack.Pack` and `pack.Task` structs.

```yaml
name: baseline-inventory
version: "1.0.0"
description: Collects steady-state host inventory
selectors:
  platform: macos
tasks:
  - name: running-processes
    collector: snapshot.process
    interval: 10m
    tags:
      category: inventory
    discovery:
      - tag:env=prod
      - !site:lab
    parameter_values:
      include_command_line: true
    resources:
      timeout_seconds: 120

  - name: usb-history
    collector: snapshot.usb
    interval: 1h
    tools:
      - name: system_profiler
    config:
      diff_output: true
```

### Field Reference

| Field | Purpose |
| --- | --- |
| `name`, `version`, `description` | Human-friendly metadata shown in backend tooling. |
| `selectors` | Arbitrary JSON/YAML used by the control plane to target hosts. Ignored for local-only packs. |
| `tasks[].collector` | Registered snapshot collector to execute (e.g. `snapshot.process`). |
| `tasks[].interval` | Override cadence (e.g. `30s`, `5m`). Defaults to the agent interval if omitted. |
| `tasks[].tags` | Key/value tags merged onto telemetry. Useful for filtering results. |
| `tasks[].discovery` | Host-level predicates evaluated before execution (`tag:key=value`, `site:corp`, `hostname~^edge-`, `!collector:snapshot.usb`). |
| `tasks[].parameters` / `parameter_values` | Declarative parameter definitions and defaults surfaced to collectors. |
| `tasks[].resources` | Optional resource hints (`timeout_seconds`, `max_rows`, etc.). |
| `tasks[].tools` | External tool dependencies advertised to the backend for fulfilment.

## Configuration

| Setting | Environment Variable | Flag | Description |
| --- | --- | --- | --- |
| Pack directory | `CEREBRO_PACK_DIRECTORY` | `--pack-dir` | Path containing `.yml/.yaml` pack files. |
| Remote poll interval | `CEREBRO_ARTIFACT_POLL_INTERVAL` | `--artifact-poll` | Frequency for control plane sync (`0` disables). |
| Event flush interval | `CEREBRO_EVENT_FLUSH_INTERVAL` | `--event-flush` | Determines how often host events collected by packs are uploaded. |
| Event batch size | `CEREBRO_EVENT_BATCH_SIZE` | `--event-batch` | Maximum queued host events per batch before forcing a flush.

Packs rely on host identity populated by snapshot collectors. Ensure at least one snapshot collector (e.g. `collector.NewSnapshotCollector`) is registered so `host_id` and `hostname` are available to remote polling.

## Running the Agent with Packs

```bash
cd /path/to/cerebro
go run ./desktop-agent/cmd/desktop-agent \
  --pack-dir ./packs \
  --artifact-poll 2m \
  --event-flush 30s
```

Place pack files inside `./packs`. The agent logs scheduling decisions (e.g. `artifact task <name> send failed`) to stdout with the `cerebro-agent` prefix.

## Troubleshooting

- **Pack directory ignored** – Confirm the path exists and contains `.yml`/`.yaml` files. Non-existent directories are skipped without error.
- **Tasks never run** – Check discovery clauses and ensure the referenced collector is registered. The runtime logs when collectors are missing.
- **Remote packs missing** – Verify snapshots are reaching the backend so the host receives an identifier. Without `host_id`, the agent will skip `/telemetry/host/packs` requests.
- **Telemetry dropped** – Failed uploads are retried on the next flush if `force` is false. Persistent failures are logged with the HTTP status code for investigation.

## Next Steps

Use the `tests/desktop-agent` suite (or targeted unit tests around collectors) to validate new pack collectors. When introducing new pack parameters, extend `types.ArtifactTaskParameter` and align backend validation to keep schemas consistent.
