# Infosec Assistant Knowledge

This doc defines the context Cerebro needs to be useful for Infosec work and how that context should be stored for recall.

Memory is context, not authority. Current security state must still come from live tools such as Cerebro, Panther MCP, EvidenceCAS, Slack source context, GitHub, ticketing, or runtime checks.

## Knowledge Buckets

| Bucket | Memory kind | Store here | Staleness |
| --- | --- | --- | --- |
| Asset context | `asset_context` | Service names, environments, criticality, data classification, regulated scope, cloud account scope | `until_reverified` for ownership or runtime state, `durable` for policy-defined criticality |
| Owner context | `owner_context` | Service owner, security owner, escalation channel, on-call queue, approver group | `until_reverified` |
| Connector context | `connector_context` | Vendor connectors, code/build providers, alert destinations, cloud onboarding providers, scanner inputs, source docs | `until_reverified` |
| Detection context | `detection_context` | Panther alert meaning, useful fields, false-positive patterns, suppression review rules, linked runbook | `until_reverified` |
| Access context | `access_context` | IAM boundary, Okta group, app entitlement, GitHub org/repo access, approved write surface | `until_reverified` |
| Severity context | `severity_context` | Severity rubric, SLA, paging rule, incident declaration trigger, comms audience | `durable` unless policy is under review |
| Exception context | `exception_context` | Accepted risk, exception owner, compensating control, due date, review ticket | `short_lived` or `until_reverified` |
| Response playbook | `runbook_note` | Step-by-step triage, rollback, containment, evidence collection, approval sequence | `durable` |
| Investigation lesson | `investigation_note` | Reusable lesson from a completed investigation, with source artifacts and checks | `durable` or `until_reverified` |
| Normal pattern | `normal_pattern` | Known benign pattern that should reduce repeated triage work | `until_reverified` |
| Team preference | `team_context` | Slack channel preference, escalation style, aliases, who to ask when a source is missing | `durable` |

Promoted `access_context`, `asset_context`, `connector_context`, `detection_context`, `exception_context`, `owner_context`, and `severity_context` records are written into `SECURITY_KNOWLEDGE.md`. Promoted runbooks and investigation lessons stay in their dedicated learning docs.

## Source Intake

Start with source-backed records, not summaries from memory.

| Source | Minimum fields | Best source artifact |
| --- | --- | --- |
| Service catalog | service id, repo, owner, security owner, environment, tier, data class | `service-catalog:<service-id>` |
| Cloud inventory | AWS account, region, VPC, resource type, tag owner, production flag | `aws-account:<id>` or `aws-resource:<arn>` |
| Detection catalog | Panther rule id, severity, alert fields, source log type, linked runbook | `panther-rule:<id>` |
| Alert history | alert id, disposition, reason, affected asset, verifier | `panther-alert:<id>` |
| Connector catalog | provider, connector family, supported destination/source, setup page, SDK repo, API docs, auth mode | `connector-doc:<provider>` or `github:<owner>/<repo>` |
| Identity inventory | Okta group, app assignment, privileged role, owner | `okta-group:<group>` or `app:<name>` |
| Ticketing | exception ticket, remediation ticket, due date, status | `jira:<key>` or `linear:<id>` |
| GitHub | repo, CODEOWNERS, security workflow, deployment workflow, latest reviewed PR | `github:<org>/<repo>` or `pr#<number>` |
| Runbooks | title, owner, approval path, rollback path, evidence requirements | `runbook:<slug>` |
| Postmortems | incident id, root cause, missed detection, durable lesson | `incident:<id>` |

Each stored knowledge record should include:

- `kind`: one of the memory kinds above.
- `topic`: a stable noun phrase, such as `Payments API asset context`.
- `summary`: one concrete fact or rule.
- `details`: optional short retrieval hints, not raw logs.
- `entities`: service ids, repo names, account ids, group names, detection ids.
- `scope`: the bounded object, such as `service:payments-api`.
- `source_artifacts`: source ids that can be re-opened later.
- `verified_by`: tool or source that confirmed the record.
- `staleness_policy`: how quickly the assistant should distrust the record.
- `promotion_state`: `promoted` only when the source artifact confirms it.

## Recall Rules

Use memory to choose the next check, not to skip checks.

- For current posture, open findings, deployed versions, access membership, alert volume, and ticket status, verify live before answering.
- For routing, severity, and expected triage steps, use promoted security knowledge as the starting context.
- For repeated alerts, recall `detection_context`, `normal_pattern`, and prior `investigation_note` records, then verify the current alert and affected asset.
- For connector questions, recall `connector_context` to find the right source page, SDK repo, API docs, and supported family, then use source docs or live connector status for exact setup and current configuration.
- For ownership questions, recall `owner_context`, then verify if the action is time-sensitive or high-impact.
- For exceptions, recall `exception_context`, then verify the ticket status and due date before treating it as active.
- For conflicting memories, prefer source-verified records and name the missing source needed to resolve the conflict.

## First Data To Add

Add these in order because they improve the most answers quickly.

1. Severity rubric and paging rules.
2. Service and owner map for Tier 0 and regulated services.
3. Panther detection catalog for high-volume and high-severity alerts.
4. Exception register for active accepted risks.
5. IAM and Okta privileged-access boundaries.
6. Incident and postmortem lessons from the last quarter.
7. GitHub repo ownership and production deploy workflows.
8. Slack escalation channels and on-call aliases.
9. Connector source maps, starting with [Prisma Cloud connector sources](prisma-cloud-connector-sources.md).
10. SDK and API source maps, starting with [Security connector SDK sources](security-connector-sdk-sources.md).

## Other Useful Signals

These are not required for v1, but they make the assistant much sharper:

- Data classification by service and datastore.
- Business process criticality, such as revenue path, writer workspace access, customer data path, or admin plane.
- Vendor and SaaS owner map.
- Detection suppression history with reason and expiry.
- Change calendar and freeze windows.
- Incident commander schedule and backup approvers.
- Known scanner false positives with source evidence.
- SDK freshness, archived-client warnings, and API-only connector notes.
- Approval policy for response actions, including who can approve production changes.
- Evidence retention rules and report-safe fields.
- Metrics for assistant usefulness: triage time saved, reopened alerts, wrong-owner escalations, stale-memory warnings, and live-verification failures.
