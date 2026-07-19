export function latestAssistantText(messages: readonly unknown[]): string {
  for (let index = messages.length - 1; index >= 0; index -= 1) {
    const message = messages[index] as { role?: string; content?: unknown };
    if (message?.role !== "assistant" || !Array.isArray(message.content)) continue;
    return message.content
      .flatMap((part) => {
        if (part === null || typeof part !== "object") return [];
        const item = part as { type?: string; text?: unknown };
        return item.type === "text" && typeof item.text === "string" ? [item.text] : [];
      })
      .join("\n")
      .trim();
  }
  return "";
}
