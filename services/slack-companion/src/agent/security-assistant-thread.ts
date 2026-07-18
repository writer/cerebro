export function formatThreadContext(messages: Array<{ user_name?: string; user_id?: string; bot_id?: string; text: string }>): string {
  return messages
    .map((message) => `${message.user_name ?? message.user_id ?? message.bot_id ?? "unknown"}: ${message.text}`)
    .join("\n");
}
