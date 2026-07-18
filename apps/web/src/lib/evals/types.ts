export type EvalStatus = "passed" | "failed";

export type EvalRubricResult = {
  id: string;
  label: string;
  passed: boolean;
  detail: string;
};

export type AskEvalEvent = {
  event: string;
  data?: unknown;
};

export type AskEvalJudgeResult = {
  passed: boolean;
  detail: string;
};

export type AskEvalProvenance = {
  source: string;
  generatedAt?: string;
  sourceTraceId?: string;
};

export type AskEvalDiff = {
  added: string[];
  removed: string[];
  changed: boolean;
};

export type AskEvalRun = {
  id: string;
  kind: "ask" | "security-agent";
  name: string;
  question: string;
  tenantId: string;
  model: string;
  scopeUrn?: string;
  status: EvalStatus;
  score: number;
  startedAt: string;
  completedAt: string;
  durationMs: number;
  traceId?: string;
  rowCount: number;
  citationCount: number;
  cypherRefused: boolean;
  queryPlanIntent?: string;
  queryPlanSource?: string;
  queryPlanCorrected?: boolean;
  conversionDiagnosticsCount?: number;
  summary: string;
  events?: AskEvalEvent[];
  fixtureKind?: "golden" | "candidate";
  provenance?: AskEvalProvenance;
  baseline?: { summary: string };
  diff?: AskEvalDiff;
  judges?: Record<string, AskEvalJudgeResult>;
  cypherPreview?: string;
  rubrics: EvalRubricResult[];
};

export type AskEvalReport = {
  generatedAt: string;
  localOnly: boolean;
  outputPath?: string;
  totals: {
    passed: number;
    failed: number;
    total: number;
  };
  runs: AskEvalRun[];
};
