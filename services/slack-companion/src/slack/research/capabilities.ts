import type { SlackScopeCapabilitiesResult } from "./types.js";

export function capabilityRows(granted: Set<string>, auditLogsConfigured: boolean): SlackScopeCapabilitiesResult["capabilities"] {
  const hasAny = (...scopes: string[]) => scopes.some((scope) => granted.has(scope));
  const rows: SlackScopeCapabilitiesResult["capabilities"] = [
    {
      name: "assistant thread status, titles, and suggested prompts",
      available: hasAny("assistant:write", "chat:write"),
      required_scopes: ["assistant:write"],
      note: "Lets Cerebro show working status and set assistant-thread prompts without posting extra channel chatter.",
    },
    {
      name: "Slack AI search for public content",
      available: hasAny("search:read.public", "search:read"),
      required_scopes: ["search:read.public"],
      note: "Best broad research path for messages with permalinks and source context.",
    },
    {
      name: "Slack AI search for files",
      available: granted.has("search:read.files"),
      required_scopes: ["search:read.files"],
    },
    {
      name: "Slack AI search for users",
      available: granted.has("search:read.users"),
      required_scopes: ["search:read.users"],
    },
    {
      name: "channel and thread history",
      available: hasAny("channels:history", "groups:history", "im:history", "mpim:history"),
      required_scopes: ["channels:history", "groups:history", "im:history", "mpim:history"],
    },
    {
      name: "channel metadata",
      available: hasAny("channels:read", "groups:read", "im:read", "mpim:read"),
      required_scopes: ["channels:read", "groups:read", "im:read", "mpim:read"],
    },
    {
      name: "user profile lookup",
      available: granted.has("users:read"),
      required_scopes: ["users:read"],
    },
    {
      name: "file metadata lookup",
      available: granted.has("files:read"),
      required_scopes: ["files:read"],
    },
    {
      name: "channel bookmarks",
      available: granted.has("bookmarks:read"),
      required_scopes: ["bookmarks:read"],
    },
    {
      name: "pinned items",
      available: granted.has("pins:read"),
      required_scopes: ["pins:read"],
    },
    {
      name: "message reactions",
      available: granted.has("reactions:read"),
      required_scopes: ["reactions:read"],
    },
    {
      name: "Slack user groups",
      available: granted.has("usergroups:read"),
      required_scopes: ["usergroups:read"],
    },
    {
      name: "Slack Audit Logs app-install events",
      available: auditLogsConfigured,
      required_scopes: ["SLACK_AUDIT_LOGS_TOKEN"],
      note: "Configured through the separate Slack Audit Logs token, not the bot token scope header.",
    },
  ];
  return rows;
}
