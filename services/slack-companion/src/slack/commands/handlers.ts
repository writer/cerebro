import {
  handleAsk,
  handleEvidence,
  handleFindings,
  handleHealth,
  handleHelp,
  handleHome,
  handleSkill,
  handleSkills,
} from "./core.js";
import {
  handleGoalCancel,
  handleGoalComplete,
  handleGoalCreate,
  handleGoalPause,
  handleGoalResume,
  handleGoals,
  handleGoalShow,
} from "./goals.js";
import {
  handleScheduleCreate,
  handleSchedulePause,
  handleScheduleResume,
  handleScheduleRun,
  handleSchedules,
} from "./schedules.js";
import { handleEvaluate, handleIngest, handleSync } from "./runtime.js";
import { handleOperator } from "./operator.js";
import type { CommandHandlers } from "./types.js";

export const commandHandlers = {
  help: handleHelp,
  home: handleHome,
  health: handleHealth,
  findings: handleFindings,
  ask: handleAsk,
  evidence: handleEvidence,
  skills: handleSkills,
  skill: handleSkill,
  schedule_create: handleScheduleCreate,
  schedules: handleSchedules,
  schedule_run: handleScheduleRun,
  schedule_pause: handleSchedulePause,
  schedule_resume: handleScheduleResume,
  goal_create: handleGoalCreate,
  goals: handleGoals,
  goal_show: handleGoalShow,
  goal_pause: handleGoalPause,
  goal_resume: handleGoalResume,
  goal_cancel: handleGoalCancel,
  goal_complete: handleGoalComplete,
  operator: handleOperator,
  sync: handleSync,
  ingest: handleIngest,
  evaluate: handleEvaluate,
} satisfies CommandHandlers;
