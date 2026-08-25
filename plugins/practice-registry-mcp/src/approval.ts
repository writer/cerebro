import type { ApprovalSource } from "./schema.js";

export type ResearchApprovalValidation = {
  valid: boolean;
  errors: string[];
};

export function validateResearchApprovalSources(sources: ApprovalSource[]): ResearchApprovalValidation {
  const errors: string[] = [];
  if (sources.length < 2) {
    errors.push("Add at least two sources that directly support the practice.");
  }

  const publishers = new Set<string>();
  const hosts = new Set<string>();
  for (const source of sources) {
    publishers.add(source.publisher.trim().toLowerCase());
    try {
      const url = new URL(source.url);
      if (url.protocol !== "https:") {
        errors.push(`Use an HTTPS source URL: ${source.url}`);
      }
      hosts.add(url.hostname.replace(/^www\./, "").toLowerCase());
    } catch {
      errors.push(`Use a valid source URL: ${source.url}`);
    }
  }

  if (sources.length >= 2 && publishers.size < 2) {
    errors.push("Use sources from at least two independent publishers.");
  }
  if (sources.length >= 2 && hosts.size < 2) {
    errors.push("Use sources from at least two independent domains.");
  }

  return { valid: errors.length === 0, errors };
}
