import assert from "node:assert/strict";
import test from "node:test";
import { findSecuritySkill, findSecuritySkillsInText, listSecuritySkills, skillPrompt } from "../src/skills/security-skills.js";

test("security skills expose concrete reusable checks", () => {
  const skills = listSecuritySkills();
  assert.ok(skills.length >= 5);
  assert.ok(skills.some((skill) => skill.id === "login-posture"));
  assert.ok(skills.some((skill) => skill.id === "operator-investigation"));
  assert.ok(skills.some((skill) => skill.id === "terminated-identity-access"));
  assert.ok(skills.some((skill) => skill.id === "source-coverage-diff"));
  assert.ok(skills.every((skill) => skill.summary.length > 20));
});

test("skill aliases resolve user wording", () => {
  assert.equal(findSecuritySkill("okta")?.id, "login-posture");
  assert.equal(findSecuritySkill("newest findings")?.id, "scary-findings");
  assert.equal(findSecuritySkill("manifest")?.id, "evidence-integrity");
  assert.equal(findSecuritySkill("get it healthy")?.id, "operator-investigation");
  assert.equal(findSecuritySkill("offboarding control")?.id, "terminated-identity-access");
  assert.equal(findSecuritySkill("source diff")?.id, "source-coverage-diff");
});

test("skill text matching can find parallel checks", () => {
  const matches = findSecuritySkillsInText("run login posture and runtime health, then check pr health");
  assert.deepEqual(matches.map((skill) => skill.id), ["login-posture", "runtime-health", "change-review-health"]);
});

test("skillPrompt includes request details without losing base prompt", () => {
  const skill = findSecuritySkill("login-posture");
  assert.ok(skill);
  const prompt = skillPrompt(skill, "focus on Okta and GitHub users");
  assert.match(prompt, /Run security skill: Login posture/);
  assert.match(prompt, /focus on Okta and GitHub users/);
});

test("terminated identity canaries route through the bounded provider preflight", () => {
  const skill = findSecuritySkill("offboarding-control canary");
  assert.ok(skill);
  assert.equal(skill.id, "terminated-identity-access");
  assert.match(skill.prompt, /cerebro_offboarding_preflight/);
  assert.match(skill.prompt, /create_snapshot_when_ready=true/);
  assert.match(skill.prompt, /do not reconstruct the same answer with repeated generic runtime calls/);
});
