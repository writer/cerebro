import type {
  GRCQuestionnaireQuestion,
  GRCQuestionnaireRun,
  GRCQuestionnaireRunAnswer,
  GRCQuestionnaireRunSummary,
  GRCVendor,
} from "@/lib/grc";

export type QuestionnaireQueueRollups = {
  total: number;
  due: number;
  blocked: number;
  needsReview: number;
  ready: number;
  stale: number;
  missingEvidence: number;
  unassigned: number;
};

export type QuestionnaireQueueRow = {
  id: string;
  runID: string;
  questionID?: string;
  title: string;
  question: string;
  direction: string;
  requester: string;
  state: string;
  blocker: string;
  owner: string;
  dueAt?: string;
  mappedControls: string[];
  citationCount: number;
  missingEvidenceCount: number;
  staleEvidence: boolean;
};

export const questionnaireDirectionLabel = (direction?: string) => {
  switch ((direction ?? "").toLowerCase()) {
    case "vendor_review":
      return "Vendor review";
    case "customer_security_review":
      return "Customer review";
    default:
      return direction || "Questionnaire";
  }
};

export const questionnaireStateIntent = (state?: string): "neutral" | "danger" | "warning" | "success" => {
  switch ((state ?? "").toLowerCase()) {
    case "supported":
    case "ready":
    case "approved":
    case "not_applicable":
      return "success";
    case "blocked":
    case "needs_input":
    case "rejected":
      return "danger";
    case "needs_review":
    case "partial":
    case "ready_for_approval":
    case "approved_with_conditions":
      return "warning";
    default:
      return "neutral";
  }
};

export const questionnaireQueueRows = (runs: GRCQuestionnaireRun[]): QuestionnaireQueueRow[] =>
  runs.flatMap((run) => {
    const answers = run.answers ?? [];
    const questions = run.questions ?? [];
    if (questions.length > 0) {
      const answersByQuestionID = new Map(answers.map((answer) => [answer.question_id, answer]));
      const rows = questions.map((question) => {
        const answer = answersByQuestionID.get(question.id);
        return answer ? queueRowFromAnswer(run, answer) : queueRowFromQuestion(run, question);
      });
      const questionIDs = new Set(questions.map((question) => question.id));
      return rows.concat(answers.filter((answer) => !questionIDs.has(answer.question_id)).map((answer) => queueRowFromAnswer(run, answer)));
    }
    if (answers.length === 0) return [queueRowFromRun(run)];
    return answers.map((answer) => queueRowFromAnswer(run, answer));
  });

export const questionnaireRollups = (
  runs: GRCQuestionnaireRun[],
  summary?: GRCQuestionnaireRunSummary,
  now: Date = new Date(),
): QuestionnaireQueueRollups => {
  const rows = questionnaireQueueRows(runs);
  return {
    total: summary?.total_runs ?? runs.length,
    due: summary?.due_runs ?? runs.filter((run) => isDue(run.due_at, run.status, now)).length,
    blocked: summary?.blocked_answers ?? rows.filter((row) =>
      row.state === "blocked" || row.state === "needs_input" || (row.state === "rejected" && row.questionID)
    ).length,
    needsReview: summary?.review_answers ?? rows.filter((row) =>
      row.state === "needs_review" || row.state === "partial" || row.state === "ready_for_approval" || row.state === "approved_with_conditions"
    ).length,
    ready: summary?.ready_answers ?? rows.filter((row) => row.state === "supported" || row.state === "not_applicable" || row.state === "approved").length,
    stale: summary?.stale_evidence ?? rows.filter((row) => row.staleEvidence).length,
    missingEvidence: summary?.missing_evidence ?? rows.reduce((total, row) => total + row.missingEvidenceCount, 0),
    unassigned: summary?.unassigned ?? runs.reduce((total, run) => total + (run.unassigned_count ?? 0), 0),
  };
};

export const primaryAnswerForRun = (run?: GRCQuestionnaireRun | null, questionID?: string | null) => {
  const answers = run?.answers ?? [];
  if (!answers.length) return null;
  if (questionID) {
    return answers.find((answer) => answer.question_id === questionID) ?? null;
  }
  return answers[0];
};

export const initialQuestionnaireRowID = (run: GRCQuestionnaireRun) => {
  const questionID = run.answers?.[0]?.question_id || run.questions?.[0]?.id;
  return questionID ? `${run.run_id}:${questionID}` : run.run_id;
};

export const inferQuestionnaireIntakeFormat = (filename: string, contentType = "") => {
  const lower = filename.toLowerCase();
  if (lower.endsWith(".pdf")) return "pdf";
  if (lower.endsWith(".xlsx")) return "xlsx";
  if (lower.endsWith(".xlsm")) return "xlsm";
  if (lower.endsWith(".json")) return "json";
  if (lower.endsWith(".tsv")) return "tsv";
  if (lower.endsWith(".txt")) return "text";
  if (lower.endsWith(".csv")) return "csv";

  const normalizedType = contentType.toLowerCase();
  if (normalizedType === "application/pdf") return "pdf";
  if (normalizedType === "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet") return "xlsx";
  if (normalizedType === "application/vnd.ms-excel.sheet.macroenabled.12") return "xlsm";
  if (normalizedType === "text/tab-separated-values") return "tsv";
  if (normalizedType === "application/json") return "json";
  if (normalizedType === "text/plain") return "text";
  return "csv";
};

export const isQuestionnaireBinaryIntakeFormat = (format: string) => ["pdf", "xlsx", "xlsm"].includes(format);

export type QuestionnaireVendorSuggestionInput = {
  title?: string;
  requester?: string;
  sourceFilename?: string;
  portalURL?: string;
  intakeText?: string;
};

export const suggestQuestionnaireVendor = (
  vendors: GRCVendor[],
  input: QuestionnaireVendorSuggestionInput,
): GRCVendor | null => {
  const haystack = normalizeVendorMatchText([
    input.title,
    input.requester,
    input.sourceFilename,
    portalHost(input.portalURL),
    input.portalURL,
    input.intakeText?.slice(0, 2_000),
  ].filter(Boolean).join(" "));
  if (!haystack) return null;

  const scored = vendors.map((vendor) => {
    const name = normalizeVendorMatchText(vendor.name);
    const vendorID = normalizeVendorMatchText(vendor.vendor_id ?? "");
    const urnParts = vendor.urn.split(":").filter(Boolean);
    const urnTail = normalizeVendorMatchText(urnParts[urnParts.length - 1] ?? "");
    const websiteHost = normalizeVendorMatchText(portalHost(vendor.website_url));
    const nameTokens = name.split(" ").filter((token) => token.length >= 3);
    let score = 0;
    if (name && phraseMatches(haystack, name)) score += 80;
    if (vendorID && phraseMatches(haystack, vendorID)) score += 55;
    if (urnTail && phraseMatches(haystack, urnTail)) score += 45;
    if (websiteHost && phraseMatches(haystack, websiteHost)) score += 35;
    score += nameTokens.filter((token) => phraseMatches(haystack, token)).length * 10;
    if (nameTokens.length === 1 && !phraseMatches(haystack, name) && score < 80) score = 0;
    return { vendor, score };
  }).filter((item) => item.score >= 40).sort((left, right) => right.score - left.score);

  if (scored.length === 0) return null;
  if (scored.length > 1 && scored[0].score === scored[1].score) return null;
  return scored[0].vendor;
};

const queueRowFromAnswer = (run: GRCQuestionnaireRun, answer: GRCQuestionnaireRunAnswer): QuestionnaireQueueRow => {
  const missing = answer.missing_evidence ?? [];
  const staleEvidence = (answer.freshness?.status ?? "").toLowerCase() === "stale" || missing.some((gap) => gap.code === "stale_evidence");
  return {
    id: `${run.run_id}:${answer.question_id}`,
    runID: run.run_id,
    questionID: answer.question_id,
    title: run.title,
    question: answer.question || answer.question_id,
    direction: run.direction,
    requester: runRequester(run),
    state: answerQueueState(answer),
    blocker: missing[0]?.reason || answer.reviewer_reason || run.decision_reason || "",
    owner: answerOwner(run, answer.question_id),
    dueAt: answerDueAt(run, answer.question_id),
    mappedControls: answer.controls ?? [],
    citationCount: answer.citations?.length ?? 0,
    missingEvidenceCount: missing.length,
    staleEvidence,
  };
};

const queueRowFromQuestion = (run: GRCQuestionnaireRun, question: GRCQuestionnaireQuestion): QuestionnaireQueueRow => ({
  id: `${run.run_id}:${question.id}`,
  runID: run.run_id,
  questionID: question.id,
  title: run.title,
  question: question.question || question.id,
  direction: run.direction,
  requester: runRequester(run),
  state: question.answer_state || run.status,
  blocker: run.decision_reason || "",
  owner: answerOwner(run, question.id),
  dueAt: answerDueAt(run, question.id),
  mappedControls: question.mapped_controls ?? [],
  citationCount: 0,
  missingEvidenceCount: 0,
  staleEvidence: false,
});

const queueRowFromRun = (run: GRCQuestionnaireRun): QuestionnaireQueueRow => ({
  id: run.run_id,
  runID: run.run_id,
  title: run.title,
  question: run.title,
  direction: run.direction,
  requester: runRequester(run),
  state: run.status,
  blocker: run.decision_reason || "",
  owner: answerOwner(run),
  dueAt: answerDueAt(run),
  mappedControls: [],
  citationCount: 0,
  missingEvidenceCount: run.missing_evidence_count ?? 0,
  staleEvidence: (run.stale_evidence_count ?? 0) > 0,
});

const answerQueueState = (answer: GRCQuestionnaireRunAnswer) => {
  if (answer.reviewer_decision === "rejected") return "rejected";
  if (answer.reviewer_decision === "approved_with_conditions") return "approved_with_conditions";
  if (answer.reviewer_decision === "approved") return "approved";
  if (answer.reviewer_decision === "needs_input") return "needs_input";
  if (answer.review_state === "rejected") return "rejected";
  if (answer.review_state === "approved" && answer.answer_state !== "blocked") return "approved";
  return answer.answer_state;
};

const runRequester = (run: GRCQuestionnaireRun) =>
  run.customer_name || run.requester || run.vendor_id || run.vendor_urn || "Unspecified";

const answerOwner = (run: GRCQuestionnaireRun, questionID?: string) => {
  const assignments = run.assignments ?? [];
  const assignment = questionID ? assignments.find((item) => item.question_id === questionID) : undefined;
  const runAssignment = assignments.find((item) => !item.question_id);
  const question = (run.questions ?? []).find((item) => !questionID || item.id === questionID);
  return assignment?.owner_id || assignment?.team || runAssignment?.owner_id || runAssignment?.team ||
    question?.owner_id || run.owner_id || run.assigned_team || "";
};

const answerDueAt = (run: GRCQuestionnaireRun, questionID?: string) => {
  const assignment = (run.assignments ?? []).find((item) => !questionID || item.question_id === questionID);
  return assignment?.due_at || run.due_at;
};

const isDue = (dueAt: string | undefined, status: string | undefined, now: Date) => {
  if (!dueAt || status === "approved" || status === "rejected") return false;
  const due = Date.parse(dueAt);
  return Number.isFinite(due) && due <= now.getTime();
};

const normalizeVendorMatchText = (value?: string) =>
  (value ?? "")
    .toLowerCase()
    .replace(/https?:\/\//g, " ")
    .replace(/[^a-z0-9]+/g, " ")
    .trim()
    .replace(/\s+/g, " ");

const phraseMatches = (haystack: string, needle: string) =>
  Boolean(needle) && (` ${haystack} `).includes(` ${needle} `);

const portalHost = (value?: string) => {
  const trimmed = (value ?? "").trim().toLowerCase();
  if (!trimmed) return "";
  const withoutScheme = trimmed.replace(/^[a-z][a-z0-9+.-]*:\/\//, "");
  const authority = withoutScheme.split(/[/?#]/, 1)[0] ?? "";
  return authority.replace(/^www\./, "").split("@").pop()?.split(":")[0] ?? "";
};
