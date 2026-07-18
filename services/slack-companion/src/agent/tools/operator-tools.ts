import type { AgentTool } from "@earendil-works/pi-agent-core";
import { Type } from "@earendil-works/pi-ai";
import { createHash } from "node:crypto";
import {
  RuntimeCodeWorkspace,
  type RuntimeCodeFileInput,
  type RuntimeCodeGithubChecksInput,
  type RuntimeCodeGithubPrStatusInput,
  type RuntimeCodeGithubSourceListInput,
  type RuntimeCodeGithubSourceReadInput,
  type RuntimeCodeReadManyInput,
  type RuntimeCodeSearchInput,
} from "../../code/runtime-code.js";
import { learnedGuidanceForSkill } from "../../skills/security-skill-learning.js";
import { findSecuritySkill, listSecuritySkills, skillPrompt } from "../../skills/security-skills.js";
import { companionSelfContext } from "../self-context.js";
import type { SecurityToolDeps } from "./types.js";
import { toolResult } from "./tool-result.js";

export function createSelfContextTool(deps: SecurityToolDeps, tools: AgentTool[]): AgentTool {
  const companionSelfContextParams = Type.Object({
    include_tools: Type.Optional(Type.Boolean()),
    include_commands: Type.Optional(Type.Boolean()),
    include_debug_plan: Type.Optional(Type.Boolean()),
  });
  return {
    name: "cerebro_companion_self_context",
    label: "Cerebro companion self context",
    description: "Read sanitized context about the Cerebro Slack companion itself: service identity, configured runtimes, command registry, skills, agent tools, feature flags, storage modes, and self-debugging playbook. Use when users ask what Cerebro can do, why Cerebro failed, how Cerebro is configured, or how to debug the companion.",
    parameters: companionSelfContextParams,
    execute: async (_toolCallId, params) => {
      const args = params as { include_tools?: boolean; include_commands?: boolean; include_debug_plan?: boolean };
      return toolResult(companionSelfContext(deps.config, tools, {
        includeTools: args.include_tools,
        includeCommands: args.include_commands,
        includeDebugPlan: args.include_debug_plan,
      }));
    },
  };
}

export function createSkillTools(deps: SecurityToolDeps): AgentTool[] {
  const skillViewParams = Type.Object({
    skill_id: Type.String(),
    details: Type.Optional(Type.String()),
  });
  return [
    {
      name: "security_skills_list",
      label: "Security skills list",
      description: "List Cerebro security skills by metadata only. Use before choosing a skill or improving procedural behavior.",
      parameters: Type.Object({}),
      execute: async () => toolResult({
        skills: listSecuritySkills().map((skill) => ({
          id: skill.id,
          title: skill.title,
          summary: skill.summary,
          aliases: skill.aliases,
          category: skill.category,
        })),
        note: "Use security_skill_view for the full prompt and current learned procedural overlay.",
      }),
    },
    {
      name: "security_skill_view",
      label: "Security skill view",
      description: "Read one Cerebro security skill's full prompt before editing or running a learned procedure.",
      parameters: skillViewParams,
      execute: async (_toolCallId, params) => {
        const args = params as { skill_id: string; details?: string };
        const skill = findSecuritySkill(args.skill_id);
        return toolResult(skill
          ? {
              skill,
              prompt: skillPrompt(skill, args.details, learnedGuidanceForSkill(deps.memory, skill, args.details)),
              learned_guidance: learnedGuidanceForSkill(deps.memory, skill, args.details),
            }
          : { error: "unknown_skill", skill_id: args.skill_id });
      },
    },
  ];
}

export function createRuntimeCodeTools(deps: SecurityToolDeps): AgentTool[] {
  const code = new RuntimeCodeWorkspace(deps.config);
  const codeWorkspaceListParams = Type.Object({
    prefix: Type.Optional(Type.String()),
  });
  const codeWorkspaceReadParams = Type.Object({
    path: Type.String(),
  });
  const codeWorkspaceReadManyParams = Type.Object({
    paths: Type.Array(Type.String()),
  });
  const codeWorkspaceSearchParams = Type.Object({
    query: Type.String(),
    prefix: Type.Optional(Type.String()),
    max_results: Type.Optional(Type.Number()),
    case_sensitive: Type.Optional(Type.Boolean()),
  });
  const codeWorkspaceWriteParams = Type.Object({
    path: Type.String(),
    content: Type.String(),
  });
  const codeWorkspacePatchParams = Type.Object({
    path: Type.String(),
    old_text: Type.String(),
    new_text: Type.String(),
  });
  const codeGithubPrParams = Type.Object({
    repo: Type.Optional(Type.String()),
    title: Type.String(),
    body: Type.Optional(Type.String()),
    files: Type.Array(Type.Object({
      path: Type.String(),
      content: Type.String(),
    })),
    branch: Type.Optional(Type.String()),
    base: Type.Optional(Type.String()),
    draft: Type.Optional(Type.Boolean()),
  });
  const codeSelfImprovementPrParams = Type.Object({
    base_sha: Type.String({ minLength: 40, maxLength: 40, pattern: "^[a-fA-F0-9]{40}$" }),
    expected_head_sha: Type.Optional(Type.String({ minLength: 40, maxLength: 40, pattern: "^[a-fA-F0-9]{40}$" })),
    title: Type.String({ minLength: 1, maxLength: 160 }),
    body: Type.Optional(Type.String({ maxLength: 8_000 })),
    files: Type.Array(Type.Object({
      path: Type.String({ minLength: 1, maxLength: 240 }),
      content: Type.String(),
    })),
  });
  const codeGithubPrStatusParams = Type.Object({
    repo: Type.Optional(Type.String()),
    pull_number: Type.Number(),
    include_checks: Type.Optional(Type.Boolean()),
  });
  const codeGithubChecksParams = Type.Object({
    repo: Type.Optional(Type.String()),
    ref: Type.String(),
  });
  const codeGithubSourceListParams = Type.Object({
    repo: Type.Optional(Type.String()),
    ref: Type.String(),
    path: Type.Optional(Type.String()),
    max_entries: Type.Optional(Type.Number()),
  });
  const codeGithubSourceReadParams = Type.Object({
    repo: Type.Optional(Type.String()),
    ref: Type.String(),
    paths: Type.Array(Type.String()),
  });
  return [
    {
      name: "cerebro_code_status",
      label: "Cerebro runtime code status",
      description: "Check whether Cerebro can write code at runtime, where the bounded workspace lives, which GitHub orgs allow PR creation, and whether GitHub auth is configured.",
      parameters: Type.Object({}),
      execute: async () => toolResult(code.status()),
    },
    {
      name: "cerebro_code_workspace_list",
      label: "Cerebro code workspace list",
      description: "List runtime-authored files in Cerebro's bounded code workspace. Use before editing existing runtime artifacts.",
      parameters: codeWorkspaceListParams,
      execute: async (_toolCallId, params) => {
        const args = params as { prefix?: string };
        return toolResult(code.listFiles(args.prefix));
      },
    },
    {
      name: "cerebro_code_workspace_read",
      label: "Cerebro code workspace read",
      description: "Read one file from Cerebro's bounded runtime code workspace.",
      parameters: codeWorkspaceReadParams,
      execute: async (_toolCallId, params) => {
        const args = params as { path: string };
        return toolResult(code.readFile(args.path));
      },
    },
    {
      name: "cerebro_code_workspace_read_many",
      label: "Cerebro code workspace read many",
      description: "Read up to 8 files from Cerebro's bounded runtime code workspace. Use after search or list to inspect related code before deciding on a change.",
      parameters: codeWorkspaceReadManyParams,
      execute: async (_toolCallId, params) => {
        const args = params as { paths: string[] };
        const input: RuntimeCodeReadManyInput = { paths: args.paths };
        return toolResult(code.readMany(input));
      },
    },
    {
      name: "cerebro_code_workspace_search",
      label: "Cerebro code workspace search",
      description: "Search text inside Cerebro's bounded runtime code workspace without shelling out. Use before reading or editing files.",
      parameters: codeWorkspaceSearchParams,
      execute: async (_toolCallId, params) => {
        const args = params as { query: string; prefix?: string; max_results?: number; case_sensitive?: boolean };
        const input: RuntimeCodeSearchInput = {
          query: args.query,
          prefix: args.prefix,
          maxResults: args.max_results,
          caseSensitive: args.case_sensitive,
        };
        return toolResult(code.searchFiles(input));
      },
    },
    {
      name: "cerebro_code_workspace_write",
      label: "Cerebro code workspace write",
      description: "Write or replace one code file in Cerebro's bounded runtime workspace. Secrets, traversal paths, and oversized files are refused.",
      parameters: codeWorkspaceWriteParams,
      execute: async (_toolCallId, params) => {
        const args = params as RuntimeCodeFileInput;
        return toolResult(code.writeFile(args));
      },
    },
    {
      name: "cerebro_code_workspace_patch",
      label: "Cerebro code workspace patch",
      description: "Patch one runtime workspace file by unique old_text/new_text. Use for small corrections after reading the file.",
      parameters: codeWorkspacePatchParams,
      execute: async (_toolCallId, params) => {
        const args = params as { path: string; old_text: string; new_text: string };
        return toolResult(code.patchFile({ path: args.path, oldText: args.old_text, newText: args.new_text }));
      },
    },
    {
      name: "cerebro_code_github_pr",
      label: "Cerebro code GitHub PR",
      description: "Create a reviewable GitHub pull request with runtime-authored code in a configured write org. Requires CEREBRO_CODE_GITHUB_TOKEN or configured GitHub App installation credentials. Use for real service or skill changes; never store secrets or bypass review.",
      parameters: codeGithubPrParams,
      execute: async (_toolCallId, params) => {
        const args = params as {
          repo?: string;
          title: string;
          body?: string;
          files: RuntimeCodeFileInput[];
          branch?: string;
          base?: string;
          draft?: boolean;
        };
        return toolResult(await code.createGithubPullRequest(args));
      },
    },
    {
      name: "cerebro_code_self_improvement_pr",
      label: "Submit Cerebro self-improvement candidate",
      description: "Open or update one draft PR in the configured Slack companion repository for a trusted operator's explicit self-improvement request. Pass the immutable base SHA returned by source inspection. When updating the existing candidate, also pass expected_head_sha from a current PR status read. The host forces the repository, draft state, branch prefix, idempotent candidate id, exact inspected base and head, file bounds, and protected-path exclusions. This tool cannot merge, deploy, promote, change dependencies, or edit Code Mode, policy, credential, evaluator, release-gate, authorization, or Slack actor-ingress files.",
      parameters: codeSelfImprovementPrParams,
      execute: async (_toolCallId, params) => {
        const userId = deps.requestContext?.userId;
        if (!userId || !deps.config.slack.operatorUserIds.has(userId)) {
          return toolResult({
            ok: false,
            error: "trusted_operator_required",
            message: "Self-improvement candidates can be submitted only by a configured Slack operator.",
          });
        }
        const args = params as {
          base_sha: string;
          expected_head_sha?: string;
          title: string;
          body?: string;
          files: RuntimeCodeFileInput[];
        };
        const candidateId = createHash("sha256")
          .update([deps.requestContext?.channelId, deps.requestContext?.threadTs, userId].join("\u0000"))
          .digest("hex")
          .slice(0, 20);
        return toolResult(await code.createSelfImprovementPullRequest({
          candidateId,
          baseSha: args.base_sha,
          expectedHeadSha: args.expected_head_sha,
          title: args.title,
          body: args.body,
          files: args.files,
        }));
      },
    },
    {
      name: "cerebro_code_github_pr_status",
      label: "Cerebro code GitHub PR status",
      description: "Read one pull request in any GitHub repo, including head/base refs, merge state, and current check runs/status contexts. Pass the repo from the user's URL or owner/name when present; do not substitute the default repo for a different requested repo.",
      parameters: codeGithubPrStatusParams,
      execute: async (_toolCallId, params) => {
        const args = params as { repo?: string; pull_number: number; include_checks?: boolean };
        const input: RuntimeCodeGithubPrStatusInput = {
          repo: args.repo,
          pullNumber: args.pull_number,
          includeChecks: args.include_checks,
        };
        return toolResult(await code.githubPullRequestStatus(input));
      },
    },
    {
      name: "cerebro_code_github_checks",
      label: "Cerebro code GitHub checks",
      description: "Read check runs and commit statuses for a branch or SHA in any GitHub repo. Pass the repo from the user's URL or owner/name when present; do not substitute the default repo for a different requested repo.",
      parameters: codeGithubChecksParams,
      execute: async (_toolCallId, params) => {
        const args = params as { repo?: string; ref: string };
        const input: RuntimeCodeGithubChecksInput = {
          repo: args.repo,
          ref: args.ref,
        };
        return toolResult(await code.githubChecksStatus(input));
      },
    },
    {
      name: "cerebro_code_github_source_list",
      label: "Cerebro GitHub source list",
      description: "List up to 200 entries in one GitHub repository directory at an exact ref. Use an immutable commit SHA when inspecting source for a change. This tool is read-only and uses the configured GitHub credentials.",
      parameters: codeGithubSourceListParams,
      execute: async (_toolCallId, params) => {
        const args = params as { repo?: string; ref: string; path?: string; max_entries?: number };
        const input: RuntimeCodeGithubSourceListInput = {
          repo: args.repo,
          ref: args.ref,
          path: args.path,
          maxEntries: args.max_entries,
        };
        return toolResult(await code.githubSourceList(input));
      },
    },
    {
      name: "cerebro_code_github_source_read",
      label: "Cerebro GitHub source read",
      description: "Read up to 8 repository files at an exact GitHub ref, capped at 120 KB per file. Use an immutable commit SHA and inspect source plus its regression tests before preparing a change. Secret-like paths and traversal paths are refused.",
      parameters: codeGithubSourceReadParams,
      execute: async (_toolCallId, params) => {
        const args = params as { repo?: string; ref: string; paths: string[] };
        const input: RuntimeCodeGithubSourceReadInput = {
          repo: args.repo,
          ref: args.ref,
          paths: args.paths,
        };
        return toolResult(await code.githubSourceRead(input));
      },
    },
  ];
}
