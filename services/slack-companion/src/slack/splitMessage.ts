// splitMessage.ts
// Slack response-formatting helper for the observed "header lands, body dropped"
// bug: long answers were emitted as a single block whose body exceeded Slack's
// per-message limit and was silently dropped on render. This splits a message
// body into ordered chunks that each stay under a safe per-message cap, so the
// caller can push every chunk into the Slack `messages` array instead of
// relying on one oversized message.
//
// Splitting prefers natural boundaries in priority order: paragraph breaks,
// then line breaks, then sentence ends, then hard char cut as a last resort.
// This keeps numbered lists and multi-line evidence readable across messages.

// Slack hard limit is ~4000 chars; we cap well below so client rendering and
// any prefix/emoji never push a chunk over the edge.
export const DEFAULT_MAX_CHARS = 2800;

export interface SplitOptions {
  maxChars?: number;
  // When true, prefix each chunk with "(i/n)" so multi-part replies stay ordered
  // and readers can tell when a part is missing.
  numberParts?: boolean;
}

function pushWrapped(out: string[], block: string, maxChars: number): void {
  // A single block longer than maxChars: break on sentence ends, then words,
  // then a hard slice so we never emit an over-cap chunk.
  let rest = block.trim();
  while (rest.length > maxChars) {
    let cut = rest.lastIndexOf(". ", maxChars);
    if (cut < maxChars * 0.5) cut = rest.lastIndexOf(" ", maxChars);
    if (cut <= 0) cut = maxChars;
    out.push(rest.slice(0, cut).trim());
    rest = rest.slice(cut).trim();
  }
  if (rest) out.push(rest);
}

// Split a message body into ordered chunks each <= maxChars.
export function splitMessage(body: string, opts: SplitOptions = {}): string[] {
  const maxChars = Math.max(80, opts.maxChars ?? DEFAULT_MAX_CHARS);
  const text = (body ?? "").trim();
  if (!text) return [];
  if (text.length <= maxChars) return [text];

  const chunks: string[] = [];
  let current = "";

  const flush = () => {
    if (current.trim()) chunks.push(current.trim());
    current = "";
  };

  // Prefer paragraph boundaries, then line boundaries within a paragraph.
  for (const para of text.split(/\n{2,}/)) {
    const block = para.trim();
    if (!block) continue;
    for (const line of block.split("\n")) {
      const piece = line; // preserve list/indent within the line
      if (piece.length > maxChars) {
        flush();
        pushWrapped(chunks, piece, maxChars);
        continue;
      }
      const sep = current ? "\n" : "";
      if ((current + sep + piece).length > maxChars) {
        flush();
        current = piece;
      } else {
        current += sep + piece;
      }
    }
    // paragraph boundary: try to keep paragraphs separated when room allows
    flush();
  }
  flush();

  if (opts.numberParts && chunks.length > 1) {
    const n = chunks.length;
    return chunks.map((c, i) => `(${i + 1}/${n}) ${c}`);
  }
  return chunks;
}
