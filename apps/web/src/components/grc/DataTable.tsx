"use client";

import {
  flexRender,
  getCoreRowModel,
  getPaginationRowModel,
  getSortedRowModel,
  useReactTable,
  type ColumnDef,
  type OnChangeFn,
  type Row as TableRowModel,
  type SortingState,
} from "@tanstack/react-table";
import { useVirtualizer } from "@tanstack/react-virtual";
import Link from "next/link";
import type { ReactNode } from "react";
import { useCallback, useMemo, useRef, useState } from "react";

import { countLabel } from "@/lib/format";
import type { GRCListMeta } from "@/lib/grc";
import { grcLoadedRowsCopy } from "@/lib/grc-list";

type SortValue = boolean | Date | number | string | null | undefined;

export type DataTableSort = {
  desc?: boolean;
  key: string;
};

export type TableColumn<Row extends object = Record<string, unknown>> = {
  key: string;
  label?: string;
  enableSorting?: boolean;
  render?: (value: unknown, row: Row) => ReactNode;
  sortValue?: (row: Row) => SortValue;
};

export const formatValue = (value: unknown) => {
  if (value === null || value === undefined) {
    return "—";
  }
  if (typeof value === "string") {
    return value;
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  if (value instanceof Date) {
    return value.toISOString();
  }
  if (Array.isArray(value)) {
    return value.length > 0 ? countLabel(value.length, "item") : "[]";
  }
  if (typeof value === "object") {
    return "{...}";
  }
  return String(value);
};

const valueText = (value: unknown): string => {
  if (value === null || value === undefined) {
    return "";
  }
  if (typeof value === "object") {
    return JSON.stringify(value);
  }
  return String(value);
};

export function KeyValueList({
  data,
  emptyMessage = "No data available.",
}: {
  data?: Record<string, unknown> | null;
  emptyMessage?: string;
}) {
  if (!data || Object.keys(data).length === 0) {
    return <div className="text-xs text-[var(--text-muted)]">{emptyMessage}</div>;
  }

  return (
    <div className="space-y-2 text-xs text-[var(--text-secondary)]">
      {Object.entries(data).map(([key, value]) => (
        <div key={key} className="flex justify-between gap-4">
          <span className="text-[var(--text-muted)]">{key}</span>
          <span className="text-right text-[var(--text-primary)]">
            {formatValue(value)}
          </span>
        </div>
      ))}
    </div>
  );
}

export type DataTableProps<Row extends object = Record<string, unknown>> = {
  rows: Row[];
  columns?: TableColumn<Row>[];
  emptyMessage?: string;
  searchPlaceholder?: string;
  showSearch?: boolean;
  filterKeys?: string[];
  pageSize?: number;
  defaultSort?: DataTableSort;
  virtualizationThreshold?: number;
  getRowHref?: (row: Row) => string | undefined;
  getRowKey?: (row: Row, index: number) => string;
  onRowClick?: (row: Row) => void;
  rowActions?: (row: Row) => ReactNode;
  selectedRowKey?: string | null;
  tableContainerClassName?: string;
  resultLimit?: number;
  resultMeta?: GRCListMeta;
  resultNoun?: string;
};

const rowValue = <Row extends object>(row: Row, key: string) =>
  (row as Record<string, unknown>)[key];

const ROW_LINK_COLUMN_ID = "__cerebro_row_link";
const ROW_ACTIONS_COLUMN_ID = "__cerebro_row_actions";
const DEFAULT_VIRTUALIZATION_THRESHOLD = 30;

const compareRowValues = <Row extends object>(
  left: TableRowModel<Row>,
  right: TableRowModel<Row>,
  columnID: string,
) =>
  valueText(left.getValue(columnID)).localeCompare(valueText(right.getValue(columnID)), undefined, {
    numeric: true,
    sensitivity: "base",
  });

const ariaSortFor = (direction: false | "asc" | "desc") => {
  if (direction === "asc") return "ascending";
  if (direction === "desc") return "descending";
  return "none";
};

export default function DataTable<Row extends object = Record<string, unknown>>({
  rows,
  columns,
  emptyMessage = "No rows available.",
  searchPlaceholder = "Filter loaded rows",
  showSearch = true,
  filterKeys,
  pageSize = 10,
  defaultSort,
  virtualizationThreshold = DEFAULT_VIRTUALIZATION_THRESHOLD,
  getRowHref,
  getRowKey,
  onRowClick,
  rowActions,
  selectedRowKey,
  tableContainerClassName = "overflow-auto rounded-lg border border-[color:var(--border)] bg-[var(--surface)]",
  resultLimit,
  resultMeta,
  resultNoun = "rows",
}: DataTableProps<Row>) {
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(1);
  const [sorting, setSorting] = useState<SortingState>(() =>
    defaultSort ? [{ desc: Boolean(defaultSort.desc), id: defaultSort.key }] : [],
  );
  const tableScrollRef = useRef<HTMLDivElement | null>(null);
  const sourceRows = useMemo(() => rows ?? [], [rows]);
  const safePageSize = Math.max(1, pageSize);
  const resolvedColumns = useMemo<TableColumn<Row>[]>(
    () => columns ?? Object.keys(sourceRows?.[0] ?? {}).slice(0, 6).map((key) => ({ key })),
    [columns, sourceRows],
  );
  const searchableKeys = useMemo(
    () => filterKeys ?? resolvedColumns.map((column) => column.key),
    [filterKeys, resolvedColumns],
  );
  const rowSearchText = useMemo(
    () =>
      sourceRows.map((row) =>
        searchableKeys.map((key) => valueText(rowValue(row, key))).join("\n").toLowerCase(),
      ),
    [sourceRows, searchableKeys],
  );
  const filteredRows = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase();
    if (!normalizedQuery) {
      return sourceRows;
    }
    return sourceRows.filter((_row, index) =>
      rowSearchText[index]?.includes(normalizedQuery),
    );
  }, [query, sourceRows, rowSearchText]);
  const totalPages = Math.max(1, Math.ceil(filteredRows.length / safePageSize));
  const currentPage = Math.min(page, totalPages);
  const pageStart = (currentPage - 1) * safePageSize;
  const tanstackColumns = useMemo<ColumnDef<Row>[]>(
    () => [
      ...resolvedColumns.map<ColumnDef<Row>>((column) => ({
        id: column.key,
        accessorFn: (row) => column.sortValue?.(row) ?? rowValue(row, column.key),
        cell: ({ row }) => {
          const value = rowValue(row.original, column.key);
          return column.render ? column.render(value, row.original) : formatValue(value);
        },
        enableSorting: column.enableSorting ?? true,
        header: column.label ?? column.key,
        sortingFn: compareRowValues,
      })),
      ...(getRowHref
        ? [{
            id: ROW_LINK_COLUMN_ID,
            cell: ({ row }) => {
              const href = getRowHref(row.original);
              return href ? (
                <Link className="text-indigo-600 hover:text-indigo-800 dark:text-indigo-400 dark:hover:text-indigo-300" href={href}>
                  Open
                </Link>
              ) : (
                <span className="text-[var(--text-muted)]">—</span>
              );
            },
            enableSorting: false,
            header: "Link",
          } satisfies ColumnDef<Row>]
        : []),
      ...(rowActions
        ? [{
            id: ROW_ACTIONS_COLUMN_ID,
            cell: ({ row }) => rowActions(row.original),
            enableSorting: false,
            header: "",
          } satisfies ColumnDef<Row>]
        : []),
    ],
    [getRowHref, resolvedColumns, rowActions],
  );
  const sortableColumnIDs = useMemo(
    () => new Set(tanstackColumns.map((column) => String(column.id)).filter((id) => id !== "undefined")),
    [tanstackColumns],
  );
  const validSorting = useMemo(
    () => sorting.filter((sort) => sortableColumnIDs.has(sort.id)),
    [sortableColumnIDs, sorting],
  );
  const handleSortingChange = useCallback<OnChangeFn<SortingState>>((updater) => {
    setSorting((current) => {
      const currentValidSorting = current.filter((sort) => sortableColumnIDs.has(sort.id));
      return typeof updater === "function" ? updater(currentValidSorting) : updater;
    });
    setPage(1);
  }, [sortableColumnIDs]);
  // eslint-disable-next-line react-hooks/incompatible-library -- TanStack Table owns the shared row model; its instance is rendered locally.
  const table = useReactTable({
    columns: tanstackColumns,
    data: filteredRows,
    getCoreRowModel: getCoreRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
    getRowId: (row, index) => getRowKey?.(row, index) ?? String(rowValue(row, "id") ?? index),
    getSortedRowModel: getSortedRowModel(),
    onSortingChange: handleSortingChange,
    state: {
      pagination: {
        pageIndex: currentPage - 1,
        pageSize: safePageSize,
      },
      sorting: validSorting,
    },
  });
  const tableRows = table.getRowModel().rows;
  const rowVirtualizer = useVirtualizer<HTMLDivElement, HTMLTableRowElement>({
    count: tableRows.length,
    estimateSize: () => 44,
    getScrollElement: () => tableScrollRef.current,
    overscan: 6,
    useFlushSync: false,
  });
  const shouldVirtualizeRows = tableRows.length >= virtualizationThreshold;
  const virtualRows = shouldVirtualizeRows ? rowVirtualizer.getVirtualItems() : [];
  const rowsToRender = shouldVirtualizeRows && virtualRows.length > 0
    ? virtualRows.map((virtualRow) => ({ tableRow: tableRows[virtualRow.index], virtualIndex: virtualRow.index }))
    : tableRows.map((tableRow, index) => ({ tableRow, virtualIndex: index }));
  const topSpacerHeight = shouldVirtualizeRows && virtualRows.length > 0 ? virtualRows[0].start : 0;
  const bottomSpacerHeight = shouldVirtualizeRows && virtualRows.length > 0
    ? Math.max(0, rowVirtualizer.getTotalSize() - virtualRows[virtualRows.length - 1].end)
    : 0;
  const columnCount = table.getVisibleLeafColumns().length;
  const resultCopy = grcLoadedRowsCopy({
    loaded: sourceRows.length,
    limit: resultLimit,
    meta: resultMeta,
    noun: resultNoun,
  });
  const queryActive = query.trim().length > 0;
  const filteredCopy = `Matched ${filteredRows.length.toLocaleString()} loaded ${resultNoun}`;

  if (!rows || sourceRows.length === 0) {
    return (
      <div className="rounded-md border border-dashed border-[color:var(--border)] bg-[var(--surface-muted)] px-3 py-4 text-xs text-[var(--text-muted)]">
        {emptyMessage}
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
        {showSearch && (
          <input
            value={query}
            onChange={(event) => {
              setQuery(event.target.value);
              setPage(1);
            }}
            placeholder={searchPlaceholder}
            className="w-full rounded-md border border-[color:var(--border)] bg-[var(--surface)] px-3 py-1.5 text-[13px] text-[var(--text-primary)] placeholder:text-[var(--text-muted)] focus:border-[color:var(--ring)] focus:outline-none focus:ring-1 focus:ring-[color:var(--ring)] sm:max-w-xs"
          />
        )}
        <div className="text-xs text-[var(--text-muted)]">
          {queryActive ? filteredCopy : resultCopy}
          {totalPages > 1 && (
            <span>
              {" "}Rows {filteredRows.length === 0 ? 0 : pageStart + 1}-
              {Math.min(pageStart + safePageSize, filteredRows.length)}
            </span>
          )}
        </div>
      </div>
      {filteredRows.length === 0 ? (
        <div className="rounded-md border border-dashed border-[color:var(--border)] bg-[var(--surface-muted)] px-3 py-4 text-xs text-[var(--text-muted)]">
          No rows match the current filter.
        </div>
      ) : (
        <div ref={tableScrollRef} className={tableContainerClassName}>
          <table className="w-full text-left text-xs text-[var(--text-secondary)]">
            <thead className="border-b border-[color:var(--border)] bg-[var(--surface-muted)] text-[11px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">
              {table.getHeaderGroups().map((headerGroup) => (
                <tr key={headerGroup.id}>
                  {headerGroup.headers.map((header) => {
                    const sortDirection = header.column.getIsSorted();
                    return (
                      <th key={header.id} aria-sort={header.column.getCanSort() ? ariaSortFor(sortDirection) : undefined} className="px-3 py-2 font-semibold">
                        {header.isPlaceholder ? null : header.column.getCanSort() ? (
                          <button
                            type="button"
                            onClick={header.column.getToggleSortingHandler()}
                            className="flex w-full items-center gap-1 text-left font-semibold uppercase text-inherit hover:text-[var(--text-primary)]"
                          >
                            <span>{flexRender(header.column.columnDef.header, header.getContext())}</span>
                            {sortDirection && (
                              <span aria-hidden="true" className="text-[10px]">
                                {sortDirection === "asc" ? "▲" : "▼"}
                              </span>
                            )}
                          </button>
                        ) : (
                          flexRender(header.column.columnDef.header, header.getContext())
                        )}
                      </th>
                    );
                  })}
                </tr>
              ))}
            </thead>
            <tbody>
              {topSpacerHeight > 0 && (
                <tr aria-hidden="true">
                  <td colSpan={columnCount} style={{ height: topSpacerHeight }} />
                </tr>
              )}
              {rowsToRender.map(({ tableRow, virtualIndex }) => {
                const row = tableRow.original;
                const selected = selectedRowKey !== undefined && selectedRowKey !== null && tableRow.id === selectedRowKey;
                const activateRow = () => onRowClick?.(row);
                return (
                  <tr
                    key={tableRow.id}
                    ref={shouldVirtualizeRows ? (element) => {
                      if (element) rowVirtualizer.measureElement(element);
                    } : undefined}
                    data-index={shouldVirtualizeRows ? virtualIndex : undefined}
                    onClick={onRowClick ? activateRow : undefined}
                    onKeyDown={onRowClick ? (event) => {
                      if (event.key === "Enter" || event.key === " ") {
                        event.preventDefault();
                        activateRow();
                      }
                    } : undefined}
                    tabIndex={onRowClick ? 0 : undefined}
                    aria-selected={selected || undefined}
                    className={`border-b border-[color:var(--border)] hover:bg-[var(--surface-muted)] ${onRowClick ? "cursor-pointer" : ""} ${selected ? "bg-indigo-50/70 dark:bg-indigo-500/15" : ""}`}
                  >
                    {tableRow.getVisibleCells().map((cell) => (
                      <td key={cell.id} className={`px-3 py-2 ${cell.column.id === ROW_ACTIONS_COLUMN_ID ? "text-right" : ""}`}>
                        {flexRender(cell.column.columnDef.cell, cell.getContext())}
                      </td>
                    ))}
                  </tr>
                );
              })}
              {bottomSpacerHeight > 0 && (
                <tr aria-hidden="true">
                  <td colSpan={columnCount} style={{ height: bottomSpacerHeight }} />
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}
      {totalPages > 1 && (
        <div className="flex items-center justify-end gap-2 text-xs">
          <button
            type="button"
            onClick={() => setPage(Math.max(1, currentPage - 1))}
            disabled={currentPage === 1}
            className="rounded-md border border-[color:var(--border)] px-2 py-1 text-[var(--text-secondary)] disabled:cursor-not-allowed disabled:opacity-40"
          >
            Previous
          </button>
          <span className="text-[var(--text-muted)]">
            Page {currentPage} of {totalPages}
          </span>
          <button
            type="button"
            onClick={() => setPage(Math.min(totalPages, currentPage + 1))}
            disabled={currentPage === totalPages}
            className="rounded-md border border-[color:var(--border)] px-2 py-1 text-[var(--text-secondary)] disabled:cursor-not-allowed disabled:opacity-40"
          >
            Next
          </button>
        </div>
      )}
    </div>
  );
}

export function WorklistTable<Row extends object = Record<string, unknown>>({
  title,
  description,
  action,
  refreshing,
  ...tableProps
}: DataTableProps<Row> & {
  title: string;
  description?: ReactNode;
  action?: ReactNode;
  refreshing?: boolean;
}) {
  const { tableContainerClassName, ...restTableProps } = tableProps;
  return (
    <div className="surface-panel overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[color:var(--border)] px-5 py-3.5">
        <div>
          <h2 className="text-[13px] font-semibold text-[var(--text-primary)]">{title}</h2>
          {description && <p className="mt-0.5 text-[12px] text-[var(--text-muted)]">{description}</p>}
        </div>
        {action}
      </div>
      {refreshing && (
        <div className="border-b border-[color:var(--border)] bg-[var(--surface-muted)] px-4 py-2 text-[12px] text-[var(--text-muted)]">
          Refreshing...
        </div>
      )}
      <div className="p-4">
        <DataTable {...restTableProps} tableContainerClassName={tableContainerClassName ?? "overflow-auto"} />
      </div>
    </div>
  );
}
