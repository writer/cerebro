import type {
  SlackAssistantSearchChannelSummary,
  SlackAssistantSearchFileSummary,
  SlackAssistantSearchMessageSummary,
  SlackAssistantSearchUserSummary,
} from "./types.js";
import {
  arrayFromRecord,
  booleanValue,
  isoFromSlackTs,
  numberValue,
  objectValue,
  safeOptionalSnippet,
  safeSnippet,
  searchText,
  stringValue,
} from "./utils.js";

export function searchMessageSummary(message: Record<string, unknown>): SlackAssistantSearchMessageSummary {
  const ts = stringValue(message.ts ?? message.message_ts);
  const context = objectValue(message.context_messages);
  return {
    channel_id: stringValue(message.channel_id),
    channel_name: stringValue(message.channel_name),
    ts,
    datetime: ts ? isoFromSlackTs(ts) : undefined,
    author_user_id: stringValue(message.author_user_id ?? message.user_id),
    author_name: stringValue(message.author_name),
    is_author_bot: booleanValue(message.is_author_bot),
    text: safeSnippet(searchText(message)),
    permalink: stringValue(message.permalink),
    context_messages: context
      ? {
          before: arrayFromRecord<Record<string, unknown>>(context, "before").map(searchContextMessage),
          after: arrayFromRecord<Record<string, unknown>>(context, "after").map(searchContextMessage),
        }
      : undefined,
  };
}

export function searchContextMessage(message: Record<string, unknown>): { ts?: string; datetime?: string; user_id?: string; text: string } {
  const ts = stringValue(message.ts);
  return {
    ts,
    datetime: ts ? isoFromSlackTs(ts) : undefined,
    user_id: stringValue(message.user_id ?? message["user_id:"] ?? message.user),
    text: safeSnippet(searchText(message)),
  };
}

export function searchFileSummary(file: Record<string, unknown>): SlackAssistantSearchFileSummary {
  return {
    file_id: stringValue(file.file_id ?? file.id),
    title: stringValue(file.title ?? file.name),
    file_type: stringValue(file.file_type ?? file.filetype ?? file.mimetype),
    author_user_id: stringValue(file.author_user_id),
    uploader_user_id: stringValue(file.uploader_user_id ?? file.user),
    permalink: stringValue(file.permalink),
    content: safeOptionalSnippet(file.content),
  };
}

export function searchChannelSummary(channel: Record<string, unknown>): SlackAssistantSearchChannelSummary {
  return {
    channel_id: stringValue(channel.channel_id ?? channel.id),
    name: stringValue(channel.name),
    purpose: safeOptionalSnippet(channel.purpose),
    topic: safeOptionalSnippet(channel.topic),
    permalink: stringValue(channel.permalink),
  };
}

export function searchUserSummary(user: Record<string, unknown>): SlackAssistantSearchUserSummary {
  const profile = objectValue(user.profile);
  return {
    user_id: stringValue(user.user_id ?? user.id),
    name: stringValue(user.name ?? user.real_name ?? profile?.display_name ?? profile?.real_name),
    title: stringValue(profile?.title),
    team_id: stringValue(user.team_id ?? user.team),
  };
}

export function channelSummary(channel: Record<string, unknown> | undefined): Record<string, unknown> | undefined {
  if (!channel) return undefined;
  const topic = objectValue(channel.topic);
  const purpose = objectValue(channel.purpose);
  return {
    id: stringValue(channel.id),
    name: stringValue(channel.name),
    is_channel: booleanValue(channel.is_channel),
    is_private: booleanValue(channel.is_private),
    is_archived: booleanValue(channel.is_archived),
    is_member: booleanValue(channel.is_member),
    num_members: numberValue(channel.num_members),
    topic: safeOptionalSnippet(topic?.value),
    purpose: safeOptionalSnippet(purpose?.value),
  };
}

export function bookmarkSummary(bookmark: Record<string, unknown>): Record<string, unknown> {
  return {
    id: stringValue(bookmark.id),
    title: stringValue(bookmark.title),
    type: stringValue(bookmark.type),
    link: stringValue(bookmark.link),
    entity_id: stringValue(bookmark.entity_id),
    date_created: numberValue(bookmark.date_created),
  };
}

export function pinSummary(pin: Record<string, unknown>): Record<string, unknown> {
  const message = objectValue(pin.message);
  const file = objectValue(pin.file);
  return {
    channel: stringValue(pin.channel),
    created: numberValue(pin.created),
    created_by: stringValue(pin.created_by),
    message_ts: stringValue(message?.ts),
    message_text: safeOptionalSnippet(message?.text),
    message_permalink: stringValue(message?.permalink),
    file_id: stringValue(file?.id),
    file_title: stringValue(file?.title ?? file?.name),
  };
}

export function userSummary(user: Record<string, unknown> | undefined): Record<string, unknown> | undefined {
  if (!user) return undefined;
  const profile = objectValue(user.profile);
  return {
    id: stringValue(user.id),
    team_id: stringValue(user.team_id ?? user.team),
    name: stringValue(user.name),
    real_name: stringValue(user.real_name ?? profile?.real_name),
    display_name: stringValue(profile?.display_name),
    title: stringValue(profile?.title),
    is_bot: booleanValue(user.is_bot),
    deleted: booleanValue(user.deleted),
    is_admin: booleanValue(user.is_admin),
    is_owner: booleanValue(user.is_owner),
    is_primary_owner: booleanValue(user.is_primary_owner),
  };
}

export function usergroupSummary(group: Record<string, unknown>): Record<string, unknown> {
  return {
    id: stringValue(group.id),
    team_id: stringValue(group.team_id),
    name: stringValue(group.name),
    handle: stringValue(group.handle),
    description: safeOptionalSnippet(group.description),
    user_count: stringValue(group.user_count) ?? numberValue(group.user_count),
    auto_type: stringValue(group.auto_type),
    is_disabled: Boolean(numberValue(group.date_delete)),
  };
}

export function fileSummary(file: Record<string, unknown> | undefined): Record<string, unknown> | undefined {
  if (!file) return undefined;
  return {
    id: stringValue(file.id),
    name: stringValue(file.name),
    title: stringValue(file.title),
    filetype: stringValue(file.filetype),
    mimetype: stringValue(file.mimetype),
    user: stringValue(file.user),
    created: numberValue(file.created),
    timestamp: numberValue(file.timestamp),
    size: numberValue(file.size),
    channels: Array.isArray(file.channels) ? file.channels.map(String).slice(0, 20) : undefined,
    permalink: stringValue(file.permalink),
    url_private: stringValue(file.url_private),
  };
}

export function fileCommentSummary(comment: Record<string, unknown>): Record<string, unknown> {
  return {
    id: stringValue(comment.id),
    timestamp: numberValue(comment.timestamp),
    user: stringValue(comment.user),
    comment: safeOptionalSnippet(comment.comment),
  };
}

export function reactionSummaries(value: unknown): Array<{ name?: string; count?: number; user_count_returned?: number }> {
  if (!Array.isArray(value)) return [];
  return value.flatMap((reaction) => {
    const item = objectValue(reaction);
    if (!item) return [];
    const users = arrayFromRecord<string>(item, "users");
    return [{
      name: stringValue(item.name),
      count: numberValue(item.count),
      user_count_returned: users.length,
    }];
  });
}
