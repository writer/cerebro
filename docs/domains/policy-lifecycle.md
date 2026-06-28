# Policy Lifecycle

## Why This Exists

Cerebro already has policy finding rules, control packs, evidence packets, framework readiness, and graph-backed GRC facts. Those objects answer whether a control is supported, failing, missing evidence, or stale.

They do not fully answer whether a company policy has been drafted, approved, assigned, accepted, reviewed, renewed, waived, and tied to certification readiness.

Mature GRC programs treat policies as operating records. A policy has a draft, a current approved version, owners, approvers, employee assignments, acceptance history, review cadence, exceptions, and control mappings.

The Cerebro gap is not more framework mapping. It is first-class policy lifecycle state.

## Existing Terms

Keep these objects separate:

| Object | Current role |
| --- | --- |
| `PolicyFindingRule` | Detection and finding authoring DSL under `policies/`. |
| Control pack | Auditor-facing control catalog, framework mappings, evidence expectations, and readiness scoring. |
| Finding | A remediable control gap or risk state. |
| Evidence | Runtime or document proof that supports a finding, control, policy version, review, approval, or acceptance. |
| Policy lifecycle object | Employee-facing or auditor-facing policy document lifecycle record. |

Do not rename `PolicyFindingRule` to policy lifecycle. Use lifecycle-specific event kinds and API resources so rule authoring and company policy operations do not collapse into one noun.

## Target Model

Policy lifecycle should model these records:

| Record | Stable key | Purpose |
| --- | --- | --- |
| Policy | `policy_id` | The operating policy, such as Access Control Policy. |
| Policy template | `template_id` | Starter policy content with framework and control coverage metadata. |
| Policy version | `policy_version_id` | A draft, pending approval, approved, renewed, expired, or retired version. |
| Policy approval | `approval_id` | One approval action or approval step for a version. |
| Policy acceptance | `acceptance_id` | One person's acceptance or attestation for a version. |
| Policy review | `review_id` | Owner or reviewer cadence evidence for annual or ad hoc review. |
| Policy exception | `exception_id` or `waiver_id` | Time-bound waiver, deferral, or scoped exception. |
| Policy reminder | `reminder_id` | Reminder or escalation record for an approval, review, exception, or employee attestation. |
| Policy assignment | policy or version plus group/user | Employee group or user population required to accept the policy. |
| Policy document | `document_id` | Approved policy, standard, procedure, risk register, exception register, or training document evidence. |
| Risk register item | `risk_id` | One risk scenario with owner, treatment, review date, residual risk, controls, and source document links. |

Lifecycle states should stay concrete:

| State | Meaning |
| --- | --- |
| `not_started` | No draft or imported version exists. |
| `draft` | Content exists but has not been sent for approval. |
| `pending_approval` | A version is waiting for one or more approvers. |
| `approved` | A version has required approval and can be used as document evidence. |
| `renew_soon` | Approved version is close to review or expiration. |
| `expired` | Approved version is past its review or expiration date. |
| `retired` | Policy is no longer in the active program. |

Acceptance states should stay separate from document states:

| State | Meaning |
| --- | --- |
| `not_assigned` | No employee population is assigned. |
| `assigned` | The employee population has acceptance tasks. |
| `in_progress` | Some assigned people have accepted. |
| `accepted` | Required acceptance is complete. |
| `overdue` | At least one required acceptance is past due. |
| `reacceptance_required` | A new version requires employee acceptance again. |

## Graph Contract

The source projection layer now accepts imported policy lifecycle event kinds. This does not add a new store. It turns source/runtime events into graph facts that existing GRC evidence, readiness, and report surfaces can consume.

| Event kind | Required identity | Main graph entity |
| --- | --- | --- |
| `grc.policy` | `policy_id` | `policy` |
| `grc.policy_template` | `template_id` | `policy.template` |
| `grc.policy_version` | `policy_version_id` or derived policy/version/date | `policy.version` |
| `grc.policy_approval` | `approval_id` or derived policy/version/approver/date | `policy.approval` |
| `grc.policy_acceptance` | `acceptance_id` or derived person/policy/version/date | `policy.acceptance` |
| `grc.policy_review` | `review_id` or derived policy/version/review date | `policy.review` |
| `grc.policy_exception` | `exception_id`, `waiver_id`, or derived policy/target/expiration | `policy.exception` |
| `grc.policy_reminder` | `reminder_id`, `policy_reminder_id`, `escalation_id`, or derived policy/target/date | `policy.reminder` |
| `grc.document` | `document_id` | `document` |
| `grc.risk_scenario` | `risk_id` | `claim` with `claim_type=risk_scenario` |

Common attributes:

| Attribute | Use |
| --- | --- |
| `provider` | Source system, for example `policy_system`, `document_repository`, `identity_source`, or `manual`. |
| `template_id`, `policy_template_id` | Policy template identity. |
| `policy_id` | Parent policy identity. |
| `policy_version_id`, `version_id` | Policy version identity. |
| `reminder_id`, `policy_reminder_id`, `escalation_id` | Reminder or escalation identity. |
| `status` plus specific status fields | Lifecycle, approval, acceptance, review, or exception state. |
| `owner_id`, `policy_owner_user_id` | Accountable policy owner. |
| `approver_user_id`, `approver_user_ids`, `reviewer_user_id`, `reviewer_user_ids` | Reviewer and approver actors. |
| `sent_by_user_id`, `created_by_user_id`, `escalated_to_user_id`, `escalated_to_user_ids` | Reminder sender and escalation targets. |
| `person_id`, `user_id`, `email` | Employee acceptance subject. |
| `group_id`, `employee_group_id`, `acceptance_group_id` | Assigned employee group. |
| `control_id`, `control_ids`, `control_references` | Explicit policy-to-control mappings. |
| `document_id`, `approved_document_id`, `url` | Approved document evidence or source document identity. |
| `document_type`, `document_class` | Policy document class such as `policy`, `standard`, `procedure`, `risk_register`, `control_narrative`, `exception_register`, or `training_material`. |
| `risk_id`, `risk_ids`, `risk_register_id` | Risk scenario or risk register identity. |
| `risk_category`, `inherent_risk_level`, `residual_risk_level`, `likelihood`, `impact`, `treatment`, `treatment_due_at` | Risk register posture and treatment metadata. |
| `evidence_id`, `evidence_cas_uri` | Runtime evidence packet link. |
| `target_id`, `resource_id`, `asset_id`, `service_id`, `system_id`, `person_id`, `user_id` | Scoped exception target. |

Graph relationships:

| From | Relation | To |
| --- | --- | --- |
| Policy or policy version | `supports` | Control |
| Policy template | `supports` | Control |
| Policy or policy version | `has_evidence` | Document or runtime evidence |
| Policy template | `has_evidence` | Document or runtime evidence |
| Policy version | `belongs_to` | Policy |
| Approval, acceptance, review, exception, or reminder | `associated_with` | Policy version or policy |
| Policy, version, or acceptance | `assigned_to` | Employee group or user |
| Reminder | `assigned_to` | Employee group or user |
| Person or user | `has_evidence` | Policy acceptance |
| Author | `acted_on` | Policy version |
| Approver or reviewer | `acted_on` | Approval, review, or exception |
| Sender or escalation owner | `acted_on` | Reminder |
| Policy exception | `targeted` | Scoped asset, service, system, resource, or user target |
| Policy exception | `associated_with` | Control |
| Document | `associated_with` | Policy, policy version, or risk scenario |
| Document | `supports` | Control |
| Risk scenario | `associated_with` | Policy or control |
| Risk scenario | `has_evidence` | Source risk register document or runtime evidence |

## Readiness Semantics

Policy lifecycle readiness should become a first-class section in `/grc/program-readiness`, not a hidden control side effect.

Recommended summary fields:

| Field | Meaning |
| --- | --- |
| `policies` | Active policies in selected framework or profile scope. |
| `approved_policies` | Policies with an approved, unexpired version. |
| `pending_approval_policies` | Policies with a latest version waiting for approval. |
| `expired_policies` | Policies with no approved current version. |
| `acceptance_required_policies` | Policies assigned to employees. |
| `acceptance_overdue_policies` | Assigned policies with overdue employee acceptance. |
| `exceptions_active` | Active policy exceptions in scope. |
| `exceptions_expiring_soon` | Active exceptions nearing expiration. |
| `governance_gaps` | Document records that are not drafts, including records with no status, and open risk-register records missing ownership, review dates, links, controls, treatment, or evidence. |
| `policy_document_gaps` | Document records that are not drafts, including records with no status, that are missing operating metadata or mappings. |
| `risk_register_gaps` | Open risk-register records missing owner, treatment, dates, links, controls, or evidence. |

Recommended work items:

| Condition | Work item |
| --- | --- |
| Draft has no approval request | Submit policy for approval. |
| Approval is pending past SLA | Follow up with approver. |
| Approved version renews soon | Review policy before due date. |
| Version expired | Renew or replace policy. |
| Employee acceptance is overdue | Remind assigned employees. |
| New version requires acceptance | Assign reacceptance task. |
| Exception expires soon | Renew, close, or replace exception. |
| Policy has no mapped controls | Map policy to controls before audit reliance. |
| Policy has no approved document evidence | Attach approved policy document. |
| Document has no owner or review date | Assign an owner and set the next review date. |
| Document is not linked to a policy | Link the document to the policy it supports. |
| Open risk has no treatment or treatment date | Add a treatment plan and due date. |
| Open risk has no source document, control, policy, or evidence link | Link the risk to its source register, policy, controls, and supporting evidence. |

## API Shape

The repo does not ship an end-user web UI. Lifecycle operations should be exposed as typed APIs and CLI surfaces, then consumed by a separate console.

Implemented endpoints:

| Endpoint | Purpose |
| --- | --- |
| `GET /grc/policy-lifecycle` | Tenant-scoped aggregate of policy templates, policy records, documents, risk-register records, governance gaps, versions, approvals, attestations, reviews, exceptions, reminders, work queue items, and explicit control/evidence mappings. |
| `POST /grc/policy-lifecycle/actions` | Append and project a lifecycle action event for template, draft, approval, publish, attestation, review, exception, reminder, or escalation work. |
| `GET /grc/policy-lifecycle/export` | CSV export of policy versions, approvals, attestations, reviews, exceptions, lifecycle events, and control/evidence mappings, with optional `start` and `end` date filters. |

Candidate follow-on read endpoints:

| Endpoint | Purpose |
| --- | --- |
| `GET /grc/policies` | List policy lifecycle posture by tenant, framework, control, owner, status, and acceptance state. |
| `GET /grc/policies/{policyID}` | Read policy detail, versions, approvals, acceptances, controls, evidence, reviews, and exceptions. |
| `GET /grc/policies/{policyID}/diff?from=&to=` | Compare two policy versions once content storage exists. |
| `GET /grc/policies/{policyID}/acceptances` | List employee acceptance state for one policy/version. |
| `GET /grc/policy-exceptions` | List active, expired, and upcoming policy exceptions. |

Candidate resource-specific write endpoints:

| Endpoint | Purpose |
| --- | --- |
| `POST /grc/policies` | Create or import a policy shell. |
| `POST /grc/policies/{policyID}/versions` | Create or import a draft/new version. |
| `POST /grc/policies/{policyID}/versions/{versionID}/approval-requests` | Submit a version for approval. |
| `POST /grc/policies/{policyID}/versions/{versionID}/approvals` | Record approval, rejection, or cancellation. |
| `POST /grc/policies/{policyID}/assignments` | Assign employee groups or users. |
| `POST /grc/policies/{policyID}/acceptances` | Record employee acceptance from a trusted source. |
| `POST /grc/policy-exceptions` | Create a time-bound policy exception. |
| `PATCH /grc/policy-exceptions/{exceptionID}` | Renew, close, reject, or expire an exception. |

Write APIs should append workflow events first and project graph/read-model state from those events. Direct Neo4j writes remain out of scope.

## Implementation Plan

1. Project lifecycle facts from imported source events.
2. Add a bounded GRC policy read model in Postgres backed by workflow/source events.
3. Add `/grc/policies` list and detail endpoints with tenant, framework, control, owner, lifecycle state, acceptance state, and exception filters.
4. Add policy lifecycle summary and work items to `/grc/program-readiness`.
5. Add draft-review-approval write APIs as workflow events.
6. Add employee assignment, acceptance import, reminder intent, and escalation intent events.
7. Add exception lifecycle APIs with owner, approver, target, compensating control, expiration, and renewal state.
8. Add policy version content references and diffs. Do not add arbitrary blob storage until content storage is designed as its own subsystem.
9. Add policy template packs beside control packs, with mapped framework/control coverage and starter assignment rules.
10. Let the console consume these APIs. Do not ship console UI from this repo.

## Product Position

Cerebro should not start with a document editor. Cerebro's strength is the graph: owners, controls, evidence, source coverage, findings, assets, people, groups, and runtime state can explain why a policy is audit-ready or blocked.

The right wedge is policy lifecycle as evidence-backed operations:

- Which policies are required for this framework?
- Which policies have approved current versions?
- Which controls does each policy support?
- Which employees still need to accept the latest version?
- Which owners or approvers are blocking readiness?
- Which exceptions are active, expired, or missing approval?
- Which policy gaps block the proof bundle?

That is the policy lifecycle Cerebro can make first-class without turning this repository into a policy document editor or end-user console.
