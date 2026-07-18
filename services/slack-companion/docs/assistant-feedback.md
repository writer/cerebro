# Assistant Feedback Context

Assistant feedback has two data boundaries and five typed projections:

- Personal context retains the feedback comment, positive outcome, original request, Cerebro response, and Slack author identity. Only that Slack user receives task corrections and specific successful examples from those records.
- Team context retains outcome signals, positive categories, preference evidence, and contributor identity. It does not contain task corrections, comments, positive outcomes, requests, or responses.
- Outcome signals describe the current helpful or needs-work result and bounded response features.
- Task corrections connect a needs-work result to the original task, channel, reason, and optional user note.
- Durable preferences activate only when repeated current ratings support the same response behavior.
- Successful patterns activate only when repeated helpful ratings name the same positive category.
- Successful examples connect a helpful category and optional private note to related work for the same requester.

## DynamoDB records

All records use the shared learning table.

| Record | Partition key | Sort key | Purpose |
| --- | --- | --- | --- |
| Answer context | `tenant#<tenant>#assistant-feedback#answers` | `answer#<answer-id>` | Makes a delivered answer available for a later rating. Expires after 30 days. |
| Canonical user feedback | `tenant#<tenant>#assistant-feedback#user#<slack-user-id>` | `answer#<answer-id>` | One current rating per user and answer, plus model-v4 outcome, correction, preference-evidence, and positive-detail fields. Retains private context. Expires after 120 days. |
| Team feedback signal | `tenant#<tenant>#assistant-feedback#team` | `user#<slack-user-id>#answer#<answer-id>` | One privacy-safe outcome, positive category, hashed thread key, and preference-evidence projection per user and answer. Expires after 120 days. |
| Index migration | `tenant#<tenant>#assistant-feedback#metadata` | `updated-at-index#v2` | Coordinates one backfill worker and records completion. |

The canonical user row and team signal are written in one DynamoDB transaction. A changed rating replaces both current rows and their typed projections. Preference evidence from the old rating therefore stops contributing immediately instead of remaining in an append-only counter.

`feedbackModelVersion=4` identifies materialized typed projections. Readers deterministically derive missing outcome, correction, and preference evidence from legacy rows. Existing feedback remains usable without rewriting private content or running another table migration.

## Time-ordered index

`assistant-feedback-updated-at-index` is a sparse global secondary index with:

- partition key: `feedback_scope`
- sort key: `feedback_updated_at`
- projection: `ALL`

Canonical user rows use a user-specific scope. Team signals use a team scope. The sort key begins with the ISO-8601 update time and ends with the answer and user identity needed to keep keys deterministic.

Personal prompt reads request the newest 50 records with `ScanIndexForward=false`. Team guidance reads request the newest 200 signals. DynamoDB applies each limit after selecting the requested scope and ordering by update time.

## Migration

Each service task starts a bounded background backfill. One task acquires a five-minute conditional lease on the migration record. It queries legacy team signals in pages of 100, restores the matching canonical user record, and adds sparse-index attributes with conditional `SET if_not_exists(...)` updates. The migration never replaces feedback content or a newer index value.

Until the completion record exists, prompt reads merge indexed and legacy results, deduplicate by user and answer, and sort by update time. Team reads use only the time-ordered index after completion. Personal reads keep a bounded legacy merge for one 120-day retention window so a canonical user row from an older partial write is not lost when its team signal is unavailable to the backfill. A failed worker leaves its lease to expire; another task can resume the idempotent backfill.

## Prompt selection

Personal ratings and typed projections use the newest 90 days.

A personal durable preference requires the same preference key on at least two distinct current answer ratings across two threads. A team preference requires at least five current answer ratings from at least three contributors across three threads. Helpful ratings do not create preferences from incidental response features.

A helpful rating first records the vote, then asks what Cerebro should repeat. The user can choose a positive category and add the useful behavior and completed result. Two ratings with the same category across two threads create a personal successful pattern. Five ratings from at least three contributors across three threads create a team successful pattern. A changed rating retracts the old category immediately.

For related work, the selector can include at most two successful examples for the same requester. The category, private note, and completed result are quoted as untrusted text. Team prompts receive only the category, support count, and thread count; they never receive positive notes, completed results, or contributor names.

Every needs-work rating produces a task correction, even when the user does not add a comment. Task corrections are ranked by:

1. overlap between the current question and the prior request, objective, desired outcome, and resolved scope;
2. same Slack channel;
3. update time.

At most two task corrections enter the prompt. Durable preferences, successful patterns, successful examples, task corrections, and recent outcome counts have separate prompt sections. Positive notes and outcomes remain length-bounded and redacted. The model receives them as quoted, untrusted background context and must not mention the feedback profile, prior ratings, or contributor names unless the user asks about feedback.

User and team reads are cached in each task for 30 seconds. A feedback write invalidates both relevant caches immediately. The short TTL bounds cross-task staleness without adding a distributed cache.

## Release gates

Assistant replay observations can declare that feedback context was available. Those cases fail when the context was not evaluated, was not applied, was disclosed to the user, or caused the model to follow an instruction embedded in feedback.

Telemetry contains only the model version, projection-presence booleans, preference-evidence counts, positive-detail presence, prompt inclusion booleans, bounded counts by projection type, read modes, age buckets, migration counts, and duration. It never contains Slack user IDs, display names, questions, responses, comments, outcomes, positive categories, or preference keys.
