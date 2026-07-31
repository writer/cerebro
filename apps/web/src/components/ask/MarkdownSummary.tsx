"use client";

import { Fragment, type ReactNode } from "react";

import type { AskCitation } from "@/lib/ask";
import { shortUrn } from "@/lib/ask";
import type { GRCGraph } from "@/lib/grc";

import EntityChip from "./EntityChip";

type Props = {
  markdown: string;
  citations?: AskCitation[] | null;
  /** Turn graph, used to enrich cited entity chips with labels and risk. */
  graph?: GRCGraph | null;
};

const INLINE_TOKEN = /(\*\*[^*]+\*\*|`[^`]+`)/g;

const renderInline = (text: string, keyBase: string): ReactNode[] => {
  const segments = text.split(INLINE_TOKEN);
  return segments.map((segment, index) => {
    if (!segment) return <Fragment key={`${keyBase}-${index}`} />;
    if (segment.startsWith("**") && segment.endsWith("**")) {
      return (
        <strong key={`${keyBase}-${index}`} className="font-semibold text-slate-900">
          {segment.slice(2, -2)}
        </strong>
      );
    }
    if (segment.startsWith("`") && segment.endsWith("`")) {
      return (
        <code key={`${keyBase}-${index}`} className="rounded bg-slate-100 px-1 py-0.5 font-mono text-[12px] text-slate-800">
          {segment.slice(1, -1)}
        </code>
      );
    }
    return <Fragment key={`${keyBase}-${index}`}>{segment}</Fragment>;
  });
};

const renderWithCitations = (
  markdown: string,
  citations?: AskCitation[] | null,
  baseOffset = 0,
  graph?: GRCGraph | null,
): ReactNode[] => {
  const safeCitations = citations ?? [];
  if (!safeCitations.length) {
    return renderInline(markdown, "no-citation");
  }
  const sorted = [...safeCitations].sort((left, right) => left.span[0] - right.span[0]);
  const result: ReactNode[] = [];
  let cursor = 0;
  sorted.forEach((citation, index) => {
    const [absoluteStart, absoluteEnd] = citation.span;
    const start = Math.max(absoluteStart - baseOffset, 0);
    const end = Math.min(absoluteEnd - baseOffset, markdown.length);
    if (absoluteEnd <= baseOffset || absoluteStart >= baseOffset + markdown.length) return;
    if (start < cursor || start >= markdown.length) return;
    if (start > cursor) {
      result.push(...renderInline(markdown.slice(cursor, start), `pre-${index}`));
    }
    const label = markdown.slice(start, end) || shortUrn(citation.urn);
    result.push(
      <EntityChip
        key={`citation-${index}`}
        urn={citation.urn}
        label={label}
        graph={graph}
      />,
    );
    cursor = end;
  });
  if (cursor < markdown.length) {
    result.push(...renderInline(markdown.slice(cursor), "tail"));
  }
  return result;
};

const markdownBlocks = (markdown: string): Array<{ text: string; offset: number }> => {
  const pieces = markdown.split(/(\n{2,})/);
  const blocks: Array<{ text: string; offset: number }> = [];
  let offset = 0;
  for (const piece of pieces) {
    if (!piece) continue;
    if (/^\n{2,}$/.test(piece)) {
      offset += piece.length;
      continue;
    }
    blocks.push({ text: piece, offset });
    offset += piece.length;
  }
  return blocks;
};

export default function MarkdownSummary({ markdown, citations, graph }: Props) {
  const blocks = markdownBlocks(markdown);
  return (
    <div className="space-y-3 text-[13px] leading-relaxed text-slate-800">
      {blocks.map((block, index) => {
        if (block.text.startsWith("- ") || block.text.startsWith("* ")) {
          let lineOffset = block.offset;
          const lines = block.text.split(/\n/).filter(Boolean);
          return (
            <ul key={index} className="list-disc space-y-1 pl-5">
              {lines.map((line, lineIndex) => {
                const prefix = line.match(/^[-*]\s+/)?.[0] ?? "";
                const content = line.slice(prefix.length);
                const contentOffset = lineOffset + prefix.length;
                lineOffset += line.length + 1;
                return (
                  <li key={lineIndex}>
                    {renderWithCitations(content, citations, contentOffset, graph)}
                  </li>
                );
              })}
            </ul>
          );
        }
        return <p key={index}>{renderWithCitations(block.text, citations, block.offset, graph)}</p>;
      })}
    </div>
  );
}
