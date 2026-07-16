import { describe, expect, it } from "vitest";

import type { GRCQuestionnaireRun, GRCVendor } from "@/lib/grc";
import { inferQuestionnaireIntakeFormat, initialQuestionnaireRowID, primaryAnswerForRun, questionnaireQueueRows, questionnaireRollups, suggestQuestionnaireVendor } from "@/lib/questionnaires";

describe("questionnaire queue helpers", () => {
  it("builds answer rows and rollups from questionnaire runs", () => {
    const runs: GRCQuestionnaireRun[] = [
      {
        id: "run-1",
        run_id: "run-1",
        title: "Customer review",
        direction: "customer_security_review",
        requester: "Acme",
        status: "needs_input",
        owner_id: "security@example.com",
        due_at: "2026-01-10T00:00:00.000Z",
        created_at: "2026-01-01T00:00:00.000Z",
        updated_at: "2026-01-02T00:00:00.000Z",
        question_count: 2,
        answer_count: 2,
        ready_answer_count: 1,
        blocked_answer_count: 1,
        review_answer_count: 0,
        missing_evidence_count: 1,
        stale_evidence_count: 0,
        unassigned_count: 1,
        assignments: [{ id: "assignment-2", question_id: "q-2", team: "legal", status: "open" }],
        answers: [
          {
            id: "answer-1",
            question_id: "q-1",
            question: "Is MFA enforced?",
            answer_state: "supported",
            review_state: "ready",
            freshness: { status: "current" },
            citations: [{ id: "citation-1" }],
            controls: ["IAM-01"],
          },
          {
            id: "answer-2",
            question_id: "q-2",
            question: "Is the audit report current?",
            answer_state: "blocked",
            review_state: "blocked",
            freshness: { status: "missing" },
            missing_evidence: [{ id: "gap-1", code: "missing_required_evidence", reason: "Audit report is missing." }],
          },
        ],
      },
      {
        id: "run-2",
        run_id: "run-2",
        title: "Vendor review",
        direction: "vendor_review",
        vendor_id: "core-sso",
        status: "ready_for_approval",
        created_at: "2026-01-01T00:00:00.000Z",
        updated_at: "2026-01-02T00:00:00.000Z",
        question_count: 1,
        answer_count: 1,
        ready_answer_count: 0,
        blocked_answer_count: 0,
        review_answer_count: 1,
        missing_evidence_count: 0,
        stale_evidence_count: 1,
        unassigned_count: 0,
        answers: [{
          id: "answer-3",
          question_id: "q-3",
          question: "Is SOC 2 current?",
          answer_state: "partial",
          review_state: "needs_review",
          freshness: { status: "stale" },
          citations: [{ id: "citation-2" }],
        }],
      },
    ];

    const rows = questionnaireQueueRows(runs);

    expect(rows).toHaveLength(3);
    expect(rows[0]).toMatchObject({ state: "supported", citationCount: 1, mappedControls: ["IAM-01"] });
    expect(rows[1]).toMatchObject({ state: "blocked", blocker: "Audit report is missing.", owner: "legal", missingEvidenceCount: 1 });
    expect(questionnaireRollups(runs, undefined, new Date("2026-01-15T00:00:00.000Z"))).toMatchObject({
      total: 2,
      due: 1,
      blocked: 1,
      needsReview: 1,
      ready: 1,
      stale: 1,
      missingEvidence: 1,
      unassigned: 1,
    });
    expect(primaryAnswerForRun(runs[0], "q-2")?.id).toBe("answer-2");
    expect(primaryAnswerForRun(runs[0], "missing")).toBeNull();
  });

  it("infers structured intake formats from filenames before broad MIME types", () => {
    expect(inferQuestionnaireIntakeFormat("review.csv", "text/plain")).toBe("csv");
    expect(inferQuestionnaireIntakeFormat("review.tsv", "text/plain")).toBe("tsv");
    expect(inferQuestionnaireIntakeFormat("review.json", "text/plain")).toBe("json");
    expect(inferQuestionnaireIntakeFormat("review.xlsx", "application/octet-stream")).toBe("xlsx");
    expect(inferQuestionnaireIntakeFormat("", "application/pdf")).toBe("pdf");
  });

  it("uses run-level assignments for portal capture rows without questions", () => {
    const rows = questionnaireQueueRows([{
      id: "run-1",
      run_id: "run-1",
      title: "Portal capture",
      direction: "customer_security_review",
      requester: "Acme",
      status: "intake",
      assigned_team: "security",
      created_at: "2026-01-01T00:00:00.000Z",
      updated_at: "2026-01-02T00:00:00.000Z",
      question_count: 0,
      answer_count: 0,
      assignments: [{
        id: "assignment-1",
        question_id: "",
        owner_id: "sales-ops@example.com",
        status: "open",
        due_at: "2026-01-08T00:00:00.000Z",
      }],
    }]);

    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ id: "run-1", owner: "sales-ops@example.com", dueAt: "2026-01-08T00:00:00.000Z" });
    expect(rows[0].questionID).toBeUndefined();
  });

  it("shows parsed question rows before answer generation", () => {
    const runs: GRCQuestionnaireRun[] = [{
      id: "run-1",
      run_id: "run-1",
      title: "Portal review",
      direction: "customer_security_review",
      requester: "Acme",
      status: "intake",
      owner_id: "security@example.com",
      created_at: "2026-01-01T00:00:00.000Z",
      updated_at: "2026-01-02T00:00:00.000Z",
      question_count: 2,
      answer_count: 0,
      ready_answer_count: 0,
      blocked_answer_count: 0,
      review_answer_count: 0,
      missing_evidence_count: 0,
      stale_evidence_count: 0,
      unassigned_count: 1,
      assignments: [{ id: "assignment-2", question_id: "q-2", team: "legal", status: "open" }],
      questions: [
        {
          id: "q-1",
          question: "Do you enforce MFA?",
          section: "Access",
          mapped_controls: ["SOC2-CC6.1"],
          required_evidence_slots: ["identity_mfa"],
          answer_state: "blocked",
          review_state: "blocked",
        },
        {
          id: "q-2",
          question: "Attach SOC 2 report.",
          section: "Audit",
          answer_state: "blocked",
          review_state: "blocked",
        },
      ],
    }];

    const rows = questionnaireQueueRows(runs);

    expect(rows).toHaveLength(2);
    expect(rows[0]).toMatchObject({ id: "run-1:q-1", question: "Do you enforce MFA?", questionID: "q-1", owner: "security@example.com", mappedControls: ["SOC2-CC6.1"] });
    expect(rows[1]).toMatchObject({ id: "run-1:q-2", question: "Attach SOC 2 report.", questionID: "q-2", owner: "legal" });
    expect(initialQuestionnaireRowID(runs[0])).toBe("run-1:q-1");
  });

  it("keeps unanswered questions visible on partially processed runs", () => {
    const runs: GRCQuestionnaireRun[] = [{
      id: "run-1",
      run_id: "run-1",
      title: "Partial review",
      direction: "customer_security_review",
      requester: "Acme",
      status: "needs_input",
      created_at: "2026-01-01T00:00:00.000Z",
      updated_at: "2026-01-02T00:00:00.000Z",
      question_count: 2,
      answer_count: 1,
      ready_answer_count: 1,
      blocked_answer_count: 0,
      review_answer_count: 0,
      missing_evidence_count: 0,
      stale_evidence_count: 0,
      unassigned_count: 1,
      questions: [
        { id: "q-1", question: "Do you enforce MFA?", answer_state: "blocked", review_state: "blocked" },
        { id: "q-2", question: "Attach SOC 2 report.", answer_state: "blocked", review_state: "blocked" },
      ],
      answers: [{
        id: "answer-1",
        question_id: "q-1",
        question: "Do you enforce MFA?",
        answer_state: "supported",
        review_state: "ready",
        citations: [{ id: "citation-1" }],
      }],
    }];

    const rows = questionnaireQueueRows(runs);

    expect(rows).toHaveLength(2);
    expect(rows[0]).toMatchObject({ questionID: "q-1", state: "supported", citationCount: 1 });
    expect(rows[1]).toMatchObject({ questionID: "q-2", question: "Attach SOC 2 report.", state: "blocked", citationCount: 0 });
  });

  it("keeps terminal runs out of due rollups and counts review-intent fallback states", () => {
    const runs: GRCQuestionnaireRun[] = [
      {
        id: "run-1",
        run_id: "run-1",
        title: "Rejected review",
        direction: "customer_security_review",
        status: "rejected",
        due_at: "2026-01-10T00:00:00.000Z",
        created_at: "2026-01-01T00:00:00.000Z",
        updated_at: "2026-01-02T00:00:00.000Z",
        question_count: 0,
        answer_count: 0,
      },
      {
        id: "run-2",
        run_id: "run-2",
        title: "Conditional review",
        direction: "customer_security_review",
        status: "ready_for_approval",
        due_at: "2026-01-10T00:00:00.000Z",
        created_at: "2026-01-01T00:00:00.000Z",
        updated_at: "2026-01-02T00:00:00.000Z",
        question_count: 2,
        answer_count: 2,
        answers: [
          {
            id: "answer-1",
            question_id: "q-1",
            question: "Is access reviewed?",
            answer_state: "ready_for_approval",
            review_state: "needs_review",
          },
          {
            id: "answer-2",
            question_id: "q-2",
            question: "Is encryption enabled?",
            answer_state: "supported",
            review_state: "approved",
            reviewer_decision: "approved_with_conditions",
          },
        ],
      },
    ];

    expect(questionnaireRollups(runs, undefined, new Date("2026-01-15T00:00:00.000Z"))).toMatchObject({
      due: 1,
      blocked: 0,
      needsReview: 2,
    });
  });

  it("uses run-level assignments when an answer has no question-specific owner", () => {
    const rows = questionnaireQueueRows([{
      id: "run-1",
      run_id: "run-1",
      title: "Customer review",
      direction: "customer_security_review",
      status: "ready_for_approval",
      created_at: "2026-01-01T00:00:00.000Z",
      updated_at: "2026-01-02T00:00:00.000Z",
      question_count: 1,
      answer_count: 1,
      owner_id: "run-owner@example.com",
      assignments: [{ id: "assignment-1", owner_id: "queue-owner@example.com", status: "open" }],
      answers: [{
        id: "answer-1",
        question_id: "q-1",
        question: "Is the report current?",
        answer_state: "partial",
        review_state: "needs_review",
      }],
    }]);

    expect(rows[0]).toMatchObject({ owner: "queue-owner@example.com" });
  });

  it("selects the first answer row for a newly created run", () => {
    expect(initialQuestionnaireRowID({
      id: "run-1",
      run_id: "run-1",
      title: "Customer review",
      direction: "customer_security_review",
      status: "intake",
      created_at: "2026-01-01T00:00:00.000Z",
      updated_at: "2026-01-02T00:00:00.000Z",
      question_count: 1,
      answer_count: 1,
      answers: [{ id: "answer-1", question_id: "q-1", answer_state: "blocked" }],
    })).toBe("run-1:q-1");
  });

  it("surfaces question reviewer decisions in row state", () => {
    const rows = questionnaireQueueRows([{
      id: "run-1",
      run_id: "run-1",
      title: "Customer review",
      direction: "customer_security_review",
      status: "needs_input",
      created_at: "2026-01-01T00:00:00.000Z",
      updated_at: "2026-01-02T00:00:00.000Z",
      question_count: 2,
      answer_count: 2,
      answers: [
        {
          id: "answer-1",
          question_id: "q-1",
          question: "Is MFA enforced?",
          answer_state: "blocked",
          review_state: "rejected",
          reviewer_decision: "rejected",
          reviewer_reason: "Evidence is not current.",
          freshness: { status: "missing" },
        },
        {
          id: "answer-2",
          question_id: "q-2",
          question: "Is the audit report current?",
          answer_state: "supported",
          review_state: "approved",
          reviewer_decision: "approved_with_conditions",
          reviewer_reason: "Refresh before sending.",
          freshness: { status: "current" },
        },
      ],
    }]);

    expect(rows[0]).toMatchObject({ state: "rejected", blocker: "Evidence is not current." });
    expect(rows[1]).toMatchObject({ state: "approved_with_conditions", blocker: "Refresh before sending." });
  });

  it("suggests a vendor only when intake context has a clear match", () => {
    const vendors = [
      { urn: "urn:cerebro:demo:vendor:core-sso", vendor_id: "core-sso", name: "Core SSO", risk_level: "high", owner_state: "assigned", review_state: "current", contract_count: 0, security_review_count: 0, questionnaire_count: 0, assurance_document_count: 0 },
      { urn: "urn:cerebro:demo:vendor:storage-grid", vendor_id: "storage-grid", name: "Storage Grid", risk_level: "medium", owner_state: "assigned", review_state: "current", contract_count: 0, security_review_count: 0, questionnaire_count: 0, assurance_document_count: 0 },
    ] satisfies GRCVendor[];

    expect(suggestQuestionnaireVendor(vendors, { sourceFilename: "core-sso-security-questionnaire.xlsx" })?.urn).toBe("urn:cerebro:demo:vendor:core-sso");
    expect(suggestQuestionnaireVendor(vendors, { requester: "storage-grid vendor portal" })?.urn).toBe("urn:cerebro:demo:vendor:storage-grid");
    expect(suggestQuestionnaireVendor(vendors, { title: "Security questionnaire", intakeText: "Do you enforce MFA?" })).toBeNull();
  });
});
