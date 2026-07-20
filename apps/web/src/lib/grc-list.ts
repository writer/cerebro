import type { GRCListMeta } from "@/lib/grc";

export const GRC_WORKLIST_LIMIT = 200;
export const GRC_DETAIL_LIMIT = 100;
export const GRC_PICKER_LIMIT = 200;
export const GRC_FILTERED_EXPORT_LIMIT = 500;

export type GRCLoadedRows = {
  loaded: number;
  limit?: number;
  meta?: GRCListMeta;
};

const numericCount = (value: number | undefined) =>
  typeof value === "number" && Number.isFinite(value) && value >= 0 ? value : undefined;

export type GRCBoundedRowsInput<Row> = {
  rows?: Row[] | null;
  limit: number;
  meta?: GRCListMeta;
  total?: number;
};

export const grcBoundedRows = <Row>({
  rows,
  limit,
  meta,
  total,
}: GRCBoundedRowsInput<Row>): { rows: Row[]; meta: GRCListMeta } => {
  const sourceRows = rows ?? [];
  const safeLimit = Math.max(0, Math.floor(limit));
  const boundedRows = sourceRows.slice(0, safeLimit);
  const totalCandidate = numericCount(meta?.total) ?? numericCount(total) ?? sourceRows.length;
  const resolvedTotal = Math.max(totalCandidate, boundedRows.length);

  return {
    rows: boundedRows,
    meta: {
      limit: safeLimit,
      returned: boundedRows.length,
      total: resolvedTotal,
      truncated: Boolean(meta?.truncated ?? (sourceRows.length > boundedRows.length || resolvedTotal > boundedRows.length)),
    },
  };
};

export const grcLoadedRows = ({ loaded, limit, meta }: GRCLoadedRows) => ({
  limit: meta?.limit ?? limit,
  loaded: meta?.returned ?? loaded,
  total: meta?.total,
  truncated: Boolean(meta?.truncated ?? ((meta?.limit ?? limit ?? 0) > 0 && loaded >= (meta?.limit ?? limit ?? 0))),
});

const singularNoun = (noun: string) => {
  if (noun.endsWith("ies")) return `${noun.slice(0, -3)}y`;
  if (noun.endsWith("s") && !noun.endsWith("ss")) return noun.slice(0, -1);
  return noun;
};

const nounForCount = (noun: string, count: number) =>
  count === 1 ? singularNoun(noun) : noun;

export const grcLoadedRowsCopy = ({
  loaded,
  limit,
  meta,
  noun = "records",
}: GRCLoadedRows & { noun?: string }) => {
  const rows = grcLoadedRows({ loaded, limit, meta });
  const loadedLabel = rows.loaded.toLocaleString();
  const totalLabel = typeof rows.total === "number" ? rows.total.toLocaleString() : "";
  if (totalLabel) {
    const totalNoun = nounForCount(noun, rows.total ?? rows.loaded);
    return rows.truncated
      ? `Showing ${loadedLabel} of ${totalLabel} ${totalNoun}. Narrow filters or export the full file.`
      : `Showing ${loadedLabel} of ${totalLabel} ${totalNoun}.`;
  }
  if (rows.truncated) {
    return `Showing first ${loadedLabel} ${nounForCount(noun, rows.loaded)}. Narrow filters or export the full file.`;
  }
  return `Showing ${loadedLabel} ${nounForCount(noun, rows.loaded)}.`;
};
