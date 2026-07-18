import { SecurityAssistantService, type SecurityAssistantAnswer } from "../agent/security-assistant.js";
import type { CerebroClient } from "../cerebro/client.js";
import type { AppConfig } from "../config/index.js";
import type { SecurityMemoryStore } from "../learning/security-memory/index.js";
import {
  findSecuritySkill,
  listSecuritySkills,
  skillPrompt,
  type SecuritySkill,
} from "./security-skills.js";
import { learnedGuidanceForSkill } from "./security-skill-learning.js";

export interface SecuritySkillRunInput {
  skillId: string;
  details?: string;
  channelId: string;
  userId?: string;
  ts: string;
  threadTs?: string;
}

export interface SecurityPromptRunInput {
  prompt: string;
  channelId: string;
  userId?: string;
  ts: string;
  threadTs?: string;
}

export interface SecuritySkillRunResult {
  skill: SecuritySkill;
  answer: SecurityAssistantAnswer;
}

export class SecuritySkillService {
  private readonly assistant: SecurityAssistantService;

  constructor(
    config: AppConfig,
    cerebro: CerebroClient,
    private readonly memory: SecurityMemoryStore,
  ) {
    this.assistant = new SecurityAssistantService(config, cerebro, memory);
  }

  list(): SecuritySkill[] {
    return listSecuritySkills();
  }

  resolve(skillId: string | undefined): SecuritySkill | undefined {
    return findSecuritySkill(skillId);
  }

  async runSkill(input: SecuritySkillRunInput): Promise<SecuritySkillRunResult> {
    const skill = findSecuritySkill(input.skillId);
    if (!skill) {
      throw new Error(`Unknown Cerebro skill: ${input.skillId}`);
    }
    const answer = await this.runPrompt({
      prompt: skillPrompt(skill, input.details, learnedGuidanceForSkill(this.memory, skill, input.details)),
      channelId: input.channelId,
      userId: input.userId,
      ts: input.ts,
      threadTs: input.threadTs,
    });
    return { skill, answer };
  }

  async runPrompt(input: SecurityPromptRunInput): Promise<SecurityAssistantAnswer> {
    return this.assistant.answer({
      channelId: input.channelId,
      userId: input.userId,
      question: input.prompt,
      ts: input.ts,
      threadTs: input.threadTs,
    });
  }
}
