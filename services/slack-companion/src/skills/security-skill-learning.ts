import type { LearningDocEntry } from "../learning/learning-docs.js";
import type { SecurityMemoryStore } from "../learning/security-memory/index.js";
import type { SecuritySkill } from "./security-skills.js";
import { normalizeSkillText } from "./security-skills.js";

export function learnedGuidanceForSkill(memory: SecurityMemoryStore, skill: SecuritySkill, details = ""): string[] {
  const docs = memory.readLearningDocs("skill-improvements")[0];
  if (!docs) return [];
  const queryTerms = new Set([
    skill.id,
    skill.title,
    ...skill.aliases,
    ...details.split(/\s+/).filter((term) => term.length > 3).slice(0, 8),
  ].map(normalizeSkillText).filter(Boolean));

  return docs.entries
    .map((entry) => ({ entry, score: scoreEntry(entry, queryTerms) }))
    .filter((item) => item.score > 0)
    .sort((left, right) => right.score - left.score || right.entry.updatedAt.localeCompare(left.entry.updatedAt))
    .slice(0, 6)
    .map(({ entry }) => [entry.topic, entry.summary].filter(Boolean).join(": "));
}

function scoreEntry(entry: LearningDocEntry, queryTerms: Set<string>): number {
  const topic = normalizeSkillText(entry.topic);
  const summary = normalizeSkillText(entry.summary);
  const details = normalizeSkillText(entry.details ?? "");
  const tags = entry.tags.map(normalizeSkillText);
  let score = 0;
  for (const term of queryTerms) {
    if (!term) continue;
    if (topic.includes(term)) score += 4;
    if (tags.includes(term)) score += 3;
    if (summary.includes(term)) score += 2;
    if (details.includes(term)) score += 1;
  }
  if (tags.includes("skill improvement") || tags.includes("skill_improvement")) score += 1;
  return score;
}
