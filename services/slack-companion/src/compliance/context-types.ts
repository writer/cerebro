export interface ComplianceContextSearchInput {
  query: string;
  limit?: number;
  paths?: string[];
  includeOverview?: boolean;
}

export interface ComplianceContextServiceOptions {
  fetch?: typeof fetch;
  now?: () => number;
}

export interface CorpusSource {
  path: string;
  category: "docs" | "catalog" | "policy" | "service";
}

export interface LoadedSource extends CorpusSource {
  content: string;
  bytes: number;
  sha256: string;
  mode: "local" | "github";
}

export interface SkippedSource {
  path: string;
  reason: string;
  bytes?: number;
}

export interface CorpusChunk {
  path: string;
  category: CorpusSource["category"];
  title: string;
  text: string;
  textLower: string;
  lineStart: number;
  lineEnd: number;
  tokens: Map<string, number>;
  pathTokens: Set<string>;
  titleTokens: Set<string>;
}

export interface ComplianceCorpus {
  loadedAtMs: number;
  expiresAtMs: number;
  mode: "local" | "github";
  repo: string;
  ref: string;
  sourceCount: number;
  skipped: SkippedSource[];
  bytes: number;
  chunks: CorpusChunk[];
  digest: string;
}
