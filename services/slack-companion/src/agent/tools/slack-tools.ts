import type { AgentTool } from "@earendil-works/pi-agent-core";
import { Type } from "@earendil-works/pi-ai";
import { SlackResearchClient } from "../../slack/research/index.js";
import {
  limit,
  normalizeSlackSearchSort,
  normalizeSlackSearchSortDir,
} from "./normalizers.js";
import type { SecurityToolDeps } from "./types.js";
import { safeToolResult } from "./tool-result.js";

export function createSlackTools(deps: SecurityToolDeps): AgentTool[] {
  const slack = new SlackResearchClient(deps.config);
  const slackSearchParams = Type.Object({
    query: Type.String(),
    days: Type.Optional(Type.Number()),
    channel_ids: Type.Optional(Type.Array(Type.String())),
    limit: Type.Optional(Type.Number()),
    max_channels: Type.Optional(Type.Number()),
  });
  const slackThreadParams = Type.Object({
    channel_id: Type.String(),
    thread_ts: Type.String(),
    limit: Type.Optional(Type.Number()),
  });
  const slackRecentQuestionsParams = Type.Object({
    days: Type.Optional(Type.Number()),
    channel_ids: Type.Optional(Type.Array(Type.String())),
    limit: Type.Optional(Type.Number()),
    max_channels: Type.Optional(Type.Number()),
  });
  const slackAppAuditParams = Type.Object({
    app_name: Type.String(),
    days: Type.Optional(Type.Number()),
    limit: Type.Optional(Type.Number()),
  });
  const slackScopeParams = Type.Object({});
  const slackAiSearchParams = Type.Object({
    query: Type.String(),
    limit: Type.Optional(Type.Number()),
    cursor: Type.Optional(Type.String()),
    content_types: Type.Optional(Type.Array(Type.String())),
    channel_types: Type.Optional(Type.Array(Type.String())),
    include_context_messages: Type.Optional(Type.Boolean()),
    context_channel_id: Type.Optional(Type.String()),
    include_bots: Type.Optional(Type.Boolean()),
    action_token: Type.Optional(Type.String()),
    after: Type.Optional(Type.Number()),
    before: Type.Optional(Type.Number()),
    sort: Type.Optional(Type.String()),
    sort_dir: Type.Optional(Type.String()),
    fallback_days: Type.Optional(Type.Number()),
  });
  const slackMessageContextParams = Type.Object({
    channel_id: Type.String(),
    ts: Type.String(),
    limit: Type.Optional(Type.Number()),
  });
  const slackChannelContextParams = Type.Object({
    channel_id: Type.String(),
    limit: Type.Optional(Type.Number()),
  });
  const slackUserContextParams = Type.Object({
    user_id: Type.String(),
  });
  const slackFileContextParams = Type.Object({
    file_id: Type.String(),
    limit: Type.Optional(Type.Number()),
  });
  const riskAttestationRequestParams = Type.Object({
    target_user_id: Type.String(),
    risk_ref: Type.String(),
    activity_summary: Type.String(),
    source_name: Type.Optional(Type.String()),
    observed_at: Type.Optional(Type.String()),
    identity_basis: Type.String(),
    evidence_receipts: Type.Array(Type.String()),
  });
  const riskAttestationStatusParams = Type.Object({
    request_id: Type.String(),
  });

  return [
    {
      name: "slack_scope_capabilities",
      label: "Slack scope capabilities",
      description: "Diagnose which Slack research capabilities are available to the bot from the installed OAuth scopes. Use when Slack research fails, coverage is unclear, or you need to explain a missing capability.",
      parameters: slackScopeParams,
      execute: async () => safeToolResult(async () => slack.scopeCapabilities()),
    },
    {
      name: "slack_ai_search_context",
      label: "Slack AI search context",
      description: "Use Slack assistant.search.context for broad Slack research with message/file/channel/user results and permalinks. Falls back to visible message history if the AI search API or scopes are unavailable.",
      parameters: slackAiSearchParams,
      execute: async (_toolCallId, params) => {
        const args = params as {
          query: string;
          limit?: number;
          cursor?: string;
          content_types?: string[];
          channel_types?: string[];
          include_context_messages?: boolean;
          context_channel_id?: string;
          include_bots?: boolean;
          action_token?: string;
          after?: number;
          before?: number;
          sort?: string;
          sort_dir?: string;
          fallback_days?: number;
        };
        return safeToolResult(async () => slack.assistantSearchContext({
          query: args.query,
          limit: limit(args.limit, 20),
          cursor: args.cursor,
          contentTypes: args.content_types,
          channelTypes: args.channel_types,
          includeContextMessages: args.include_context_messages,
          contextChannelId: args.context_channel_id,
          includeBots: args.include_bots,
          actionToken: args.action_token,
          after: args.after,
          before: args.before,
          sort: normalizeSlackSearchSort(args.sort),
          sortDir: normalizeSlackSearchSortDir(args.sort_dir),
          fallbackDays: args.fallback_days,
        }));
      },
    },
    {
      name: "slack_message_context",
      label: "Slack message context",
      description: "Read one Slack message's permalink, visible thread replies, and reactions. Use before answering follow-ups about linked evidence, false positives, or what a previous Slack message meant.",
      parameters: slackMessageContextParams,
      execute: async (_toolCallId, params) => {
        const args = params as { channel_id: string; ts: string; limit?: number };
        return safeToolResult(async () => slack.messageContext(args.channel_id, args.ts, limit(args.limit, 20)));
      },
    },
    {
      name: "slack_channel_context",
      label: "Slack channel context",
      description: "Read channel metadata, bookmarks, pins, and recent visible messages. Use for channel runbooks, pinned context, normal alert patterns, and owner hints.",
      parameters: slackChannelContextParams,
      execute: async (_toolCallId, params) => {
        const args = params as { channel_id: string; limit?: number };
        return safeToolResult(async () => slack.channelContext(args.channel_id, limit(args.limit, 20)));
      },
    },
    {
      name: "slack_user_context",
      label: "Slack user context",
      description: "Read a Slack user's profile and user-group membership visible to the bot. Use to understand requester/actor context and on-call or security group membership.",
      parameters: slackUserContextParams,
      execute: async (_toolCallId, params) => {
        const args = params as { user_id: string };
        return safeToolResult(async () => slack.userContext(args.user_id));
      },
    },
    {
      name: "slack_file_context",
      label: "Slack file context",
      description: "Read Slack file metadata and visible comments for a file id. Use when an alert or question points at an uploaded file, snippet, or canvas attachment.",
      parameters: slackFileContextParams,
      execute: async (_toolCallId, params) => {
        const args = params as { file_id: string; limit?: number };
        return safeToolResult(async () => slack.fileContext(args.file_id, limit(args.limit, 20)));
      },
    },
    {
      name: "slack_message_search",
      label: "Slack message search",
      description: "Search recent Slack messages visible to the Cerebro bot for people, tools, topics, and operational context. Use for questions like who is talking about a topic.",
      parameters: slackSearchParams,
      execute: async (_toolCallId, params) => {
        const args = params as { query: string; days?: number; channel_ids?: string[]; limit?: number; max_channels?: number };
        return safeToolResult(async () => slack.searchMessages({
          query: args.query,
          days: args.days,
          channelIds: args.channel_ids,
          limit: limit(args.limit, 20),
          maxChannels: limit(args.max_channels, deps.config.slack.researchMaxChannels),
        }));
      },
    },
    {
      name: "slack_thread_context",
      label: "Slack thread context",
      description: "Read the visible Slack thread around a follow-up question so the answer can use prior question and answer context.",
      parameters: slackThreadParams,
      execute: async (_toolCallId, params) => {
        const args = params as { channel_id: string; thread_ts: string; limit?: number };
        return safeToolResult(async () => slack.threadContext(args.channel_id, args.thread_ts, limit(args.limit, 20)));
      },
    },
    {
      name: "slack_cerebro_recent_questions",
      label: "Recent Cerebro questions",
      description: "Read recent Slack questions that mention the Cerebro bot. Use to learn what users are asking and adapt answers to active channel context.",
      parameters: slackRecentQuestionsParams,
      execute: async (_toolCallId, params) => {
        const args = params as { days?: number; channel_ids?: string[]; limit?: number; max_channels?: number };
        return safeToolResult(async () => slack.recentBotQuestions({
          days: args.days,
          channelIds: args.channel_ids,
          limit: limit(args.limit, 10),
          maxChannels: limit(args.max_channels, deps.config.slack.researchMaxChannels),
        }));
      },
    },
    {
      name: "slack_app_install_audit",
      label: "Slack app install audit",
      description: "Look for Slack app installation audit events by app name. Falls back to visible message search when Audit Logs are not configured.",
      parameters: slackAppAuditParams,
      execute: async (_toolCallId, params) => {
        const args = params as { app_name: string; days?: number; limit?: number };
        return safeToolResult(async () => slack.appInstallAudit(args.app_name, args.days, limit(args.limit, 10)));
      },
    },
    ...(deps.riskAttestations ? [
      {
        name: "slack_risk_attestation_request",
        label: "Ask a person about risk activity",
        description: "Send one security check to an active human after current evidence ties the risk and account to that unique Slack user. Available only from configured security channels. The reply is self-attestation, not proof, approval, permission, or risk disposition.",
        parameters: riskAttestationRequestParams,
        execute: async (_toolCallId: string, params: unknown) => {
          const args = params as {
            target_user_id: string;
            risk_ref: string;
            activity_summary: string;
            source_name?: string;
            observed_at?: string;
            identity_basis: string;
            evidence_receipts: string[];
          };
          return safeToolResult(async () => {
            const context = deps.requestContext;
            if (!context?.channelId || !context.threadTs) throw new Error("Security check requires a Slack thread context.");
            const currentEvidence = args.evidence_receipts.filter((receipt) => deps.researchState?.hasCurrentEvidenceReceipt(receipt));
            if (currentEvidence.length === 0) throw new Error("Security check requires an evidence receipt from a successful source check in this answer.");
            return deps.riskAttestations!.request({
              riskRef: args.risk_ref,
              sourceChannelId: context.channelId,
              sourceThreadTs: context.threadTs,
              requestedByUserId: context.userId,
              targetUserId: args.target_user_id,
              activitySummary: args.activity_summary,
              sourceName: args.source_name,
              observedAt: args.observed_at,
              identityBasis: args.identity_basis,
              evidenceRefs: currentEvidence,
            });
          });
        },
      },
      {
        name: "slack_risk_attestation_status",
        label: "Check a risk response",
        description: "Read the response state for a security check created in the current security channel. The result remains unverified self-attestation and cannot disposition a risk.",
        parameters: riskAttestationStatusParams,
        execute: async (_toolCallId: string, params: unknown) => {
          const args = params as { request_id: string };
          return safeToolResult(async () => {
            const channelId = deps.requestContext?.channelId;
            if (!channelId) throw new Error("Security check status requires a Slack channel context.");
            const status = await deps.riskAttestations!.status(args.request_id, channelId);
            return status ?? { found: false, request_id: args.request_id };
          });
        },
      },
    ] : []),
  ];
}
