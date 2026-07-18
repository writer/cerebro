export interface RememberCommand {
  content: string;
  topic: string;
  summary: string;
  details: string;
  tags: string[];
  workingMemoryTarget: "memory" | "team";
  explicitTopic: string;
  explicitSummary: string;
  explicitDetails: string;
}

interface RememberCommandOptions {
  authorName?: string;
}

export function parseRememberCommand(text: string, options: RememberCommandOptions = {}): RememberCommand | undefined {
  const match = text.trim().match(/^(?:<@[A-Z0-9]+>\s*)*(?:(?:hey|hi)\s+)?(?:cerebro[,:]?\s+)?(?:please\s+)?remember\b(?:\s+(?:that|this))?(?:\s*[:,-]\s*|\s+)?([\s\S]*)$/i);
  if (!match) return undefined;
  const content = cleanContent(match[1] ?? "");
  if (!content) {
    return {
      content: "",
      topic: "Slack remember command",
      summary: "",
      details: "",
      tags: ["slack-remember"],
      workingMemoryTarget: "memory",
      explicitTopic: "Explicit Slack memory",
      explicitSummary: "",
      explicitDetails: "",
    };
  }

  const subject = subjectFromContent(content) ?? firstPersonSubject(content, options.authorName);
  const topic = subject ? `Slack context: ${subject}` : `Remembered note: ${topicSnippet(content)}`;
  const summary = summaryFor(content, subject);
  const teamContext = Boolean(subject) || looksLikeTeamContext(content);
  const tags = unique([
    "slack-remember",
    teamContext ? "team-context" : "operator-note",
    ...keywordTags(content),
  ]).slice(0, 8);

  return {
    content,
    topic,
    summary,
    details: `Explicit Slack remember command: ${content}`,
    tags,
    workingMemoryTarget: teamContext ? "team" : "memory",
    explicitTopic: `Explicit memory: ${topicSnippet(content)}`,
    explicitSummary: `Cerebro was explicitly told to remember: ${content}`,
    explicitDetails: [
      `Raw remembered text: ${content}`,
      `Interpreted topic: ${topic}`,
      subject ? `Interpreted subject: ${subject}` : "",
      `Working memory target: ${teamContext ? "team" : "memory"}`,
    ].filter(Boolean).join("\n"),
  };
}

export function containsSlackMention(text: string): boolean {
  return /<@[A-Z0-9]+>/.test(text);
}

function cleanContent(value: string): string {
  return value
    .replace(/^[\s"'`]+|[\s"'`]+$/g, "")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 900);
}

function subjectFromContent(content: string): string | undefined {
  const match = content.match(/^([\p{L}][\p{L}0-9_.-]{1,40})(?:\s+(?:says|said|jokes|is|has|often|usually|mostly|prefers|likes|does|will|can)\b|['’]s\b)/iu);
  return match?.[1] ? titleCaseName(match[1]) : undefined;
}

function firstPersonSubject(content: string, authorName: string | undefined): string | undefined {
  if (!authorName?.trim()) return undefined;
  if (!/\b(I|me|my|mine|what I say|I say)\b/i.test(content)) return undefined;
  return authorName.trim().slice(0, 60);
}

function summaryFor(content: string, subject: string | undefined): string {
  if (!subject) return content;
  const subjectPattern = new RegExp(`^${escapeRegExp(subject)}\\b`, "i");
  return subjectPattern.test(content) ? content : `${subject}: ${content}`;
}

function looksLikeTeamContext(content: string): boolean {
  return /\b(slack|team|channel|thread|person|people|joke|jokes|joking|tone|preference|prefers|usually|often|mostly)\b/i.test(content);
}

function keywordTags(content: string): string[] {
  const tags: string[] = [];
  if (/\bslack|thread|channel\b/i.test(content)) tags.push("slack");
  if (/\bjoke|jokes|joking\b/i.test(content)) tags.push("tone");
  if (/\bgraph|cypher|finding|alert|triage\b/i.test(content)) tags.push("security-triage");
  return tags;
}

function topicSnippet(content: string): string {
  return content.replace(/[.?!]+$/g, "").slice(0, 72) || "note";
}

function titleCaseName(value: string): string {
  if (!value) return value;
  return value.charAt(0).toUpperCase() + value.slice(1);
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function unique<T>(values: T[]): T[] {
  return [...new Set(values)];
}
