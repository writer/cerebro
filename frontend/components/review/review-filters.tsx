"use client";

import { useState } from "react";
import { Search, Filter, X, Calendar, User } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";

import { ReviewTaskStatus } from "@/lib/types";

export type FilterOptions = {
  status?: ReviewTaskStatus;
  search?: string;
  priority?: string;
  createdBy?: string;
  dateRange?: {
    from?: string;
    to?: string;
  };
  hasTicket?: boolean;
  isEscalated?: boolean;
};

type ReviewFiltersProps = {
  filters: FilterOptions;
  onChange: (filters: FilterOptions) => void;
  onReset: () => void;
};

const STATUS_OPTIONS: Array<{ label: string; value?: ReviewTaskStatus }> = [
  { label: "All statuses" },
  { label: "Pending", value: "pending" },
  { label: "Promoted", value: "promoted" },
  { label: "Escalated", value: "escalated" },
  { label: "Approved", value: "approved" },
  { label: "Rejected", value: "rejected" },
];

const PRIORITY_OPTIONS = [
  { label: "All priorities", value: "" },
  { label: "Critical", value: "critical" },
  { label: "High", value: "high" },
  { label: "Medium", value: "medium" },
  { label: "Low", value: "low" },
];

export function ReviewFilters({ filters, onChange, onReset }: ReviewFiltersProps) {
  const [isExpanded, setIsExpanded] = useState(false);

  const activeFilterCount = [
    filters.status,
    filters.search,
    filters.priority,
    filters.createdBy,
    filters.dateRange?.from,
    filters.dateRange?.to,
    filters.hasTicket !== undefined ? true : false,
    filters.isEscalated !== undefined ? true : false,
  ].filter(Boolean).length;

  const handleReset = () => {
    onReset();
    setIsExpanded(false);
  };

  return (
    <div className="space-y-3">
      {/* Search and toggle */}
      <div className="flex items-center gap-2">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-zinc-500" />
          <input
            type="text"
            placeholder="Search tasks by title, summary, or creator..."
            value={filters.search ?? ""}
            onChange={(e) => onChange({ ...filters, search: e.target.value || undefined })}
            className="w-full rounded-md border border-zinc-800 bg-zinc-950 py-2 pl-10 pr-4 text-sm text-zinc-200 placeholder-zinc-500 focus:border-zinc-600 focus:outline-none"
          />
          {filters.search && (
            <button
              onClick={() => onChange({ ...filters, search: undefined })}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-zinc-500 hover:text-zinc-300"
            >
              <X className="h-4 w-4" />
            </button>
          )}
        </div>

        <button
          onClick={() => setIsExpanded(!isExpanded)}
          className="flex items-center gap-2 rounded-md border border-zinc-800 bg-zinc-950 px-3 py-2 text-sm text-zinc-200 transition hover:border-zinc-600 hover:bg-zinc-900"
        >
          <Filter className="h-4 w-4" />
          <span>Filters</span>
          {activeFilterCount > 0 && (
            <span className="rounded-full bg-blue-600 px-2 py-0.5 text-xs font-semibold text-white">
              {activeFilterCount}
            </span>
          )}
        </button>
      </div>

      {/* Expandable advanced filters */}
      <AnimatePresence>
        {isExpanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="overflow-hidden"
          >
            <div className="rounded-lg border border-zinc-900 bg-black/70 p-4">
              <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
                {/* Status filter */}
                <div>
                  <label className="mb-1 block text-xs font-medium text-zinc-400">Status</label>
                  <select
                    value={filters.status ?? ""}
                    onChange={(e) =>
                      onChange({
                        ...filters,
                        status: (e.target.value as ReviewTaskStatus) || undefined,
                      })
                    }
                    className="w-full rounded-md border border-zinc-800 bg-zinc-950 px-3 py-2 text-sm text-zinc-200 focus:border-zinc-600 focus:outline-none"
                  >
                    {STATUS_OPTIONS.map((option) => (
                      <option key={option.label} value={option.value ?? ""}>
                        {option.label}
                      </option>
                    ))}
                  </select>
                </div>

                {/* Priority filter */}
                <div>
                  <label className="mb-1 block text-xs font-medium text-zinc-400">Priority</label>
                  <select
                    value={filters.priority ?? ""}
                    onChange={(e) =>
                      onChange({ ...filters, priority: e.target.value || undefined })
                    }
                    className="w-full rounded-md border border-zinc-800 bg-zinc-950 px-3 py-2 text-sm text-zinc-200 focus:border-zinc-600 focus:outline-none"
                  >
                    {PRIORITY_OPTIONS.map((option) => (
                      <option key={option.label} value={option.value}>
                        {option.label}
                      </option>
                    ))}
                  </select>
                </div>

                {/* Creator filter */}
                <div>
                  <label className="mb-1 block text-xs font-medium text-zinc-400">
                    <User className="mr-1 inline h-3 w-3" />
                    Created by
                  </label>
                  <input
                    type="text"
                    placeholder="Username or email"
                    value={filters.createdBy ?? ""}
                    onChange={(e) =>
                      onChange({ ...filters, createdBy: e.target.value || undefined })
                    }
                    className="w-full rounded-md border border-zinc-800 bg-zinc-950 px-3 py-2 text-sm text-zinc-200 placeholder-zinc-500 focus:border-zinc-600 focus:outline-none"
                  />
                </div>

                {/* Date range - From */}
                <div>
                  <label className="mb-1 block text-xs font-medium text-zinc-400">
                    <Calendar className="mr-1 inline h-3 w-3" />
                    Date from
                  </label>
                  <input
                    type="date"
                    value={filters.dateRange?.from ?? ""}
                    onChange={(e) =>
                      onChange({
                        ...filters,
                        dateRange: {
                          ...filters.dateRange,
                          from: e.target.value || undefined,
                        },
                      })
                    }
                    className="w-full rounded-md border border-zinc-800 bg-zinc-950 px-3 py-2 text-sm text-zinc-200 focus:border-zinc-600 focus:outline-none"
                  />
                </div>

                {/* Date range - To */}
                <div>
                  <label className="mb-1 block text-xs font-medium text-zinc-400">
                    <Calendar className="mr-1 inline h-3 w-3" />
                    Date to
                  </label>
                  <input
                    type="date"
                    value={filters.dateRange?.to ?? ""}
                    onChange={(e) =>
                      onChange({
                        ...filters,
                        dateRange: {
                          ...filters.dateRange,
                          to: e.target.value || undefined,
                        },
                      })
                    }
                    className="w-full rounded-md border border-zinc-800 bg-zinc-950 px-3 py-2 text-sm text-zinc-200 focus:border-zinc-600 focus:outline-none"
                  />
                </div>

                {/* Toggle filters */}
                <div className="flex flex-col gap-2">
                  <label className="flex items-center gap-2 text-sm text-zinc-300">
                    <input
                      type="checkbox"
                      checked={filters.hasTicket ?? false}
                      onChange={(e) =>
                        onChange({
                          ...filters,
                          hasTicket: e.target.checked ? true : undefined,
                        })
                      }
                      className="h-4 w-4 rounded border-zinc-700 bg-zinc-950 text-blue-600 focus:ring-blue-500"
                    />
                    Has ticket reference
                  </label>
                  <label className="flex items-center gap-2 text-sm text-zinc-300">
                    <input
                      type="checkbox"
                      checked={filters.isEscalated ?? false}
                      onChange={(e) =>
                        onChange({
                          ...filters,
                          isEscalated: e.target.checked ? true : undefined,
                        })
                      }
                      className="h-4 w-4 rounded border-zinc-700 bg-zinc-950 text-blue-600 focus:ring-blue-500"
                    />
                    Escalated tasks only
                  </label>
                </div>
              </div>

              {/* Action buttons */}
              <div className="mt-4 flex items-center justify-end gap-2 border-t border-zinc-900 pt-4">
                <button
                  onClick={handleReset}
                  className="rounded-md border border-zinc-800 bg-zinc-950 px-3 py-1.5 text-xs font-medium text-zinc-400 transition hover:border-zinc-600 hover:text-zinc-200"
                >
                  Reset all
                </button>
                <button
                  onClick={() => setIsExpanded(false)}
                  className="rounded-md border border-zinc-700 bg-zinc-900 px-3 py-1.5 text-xs font-medium text-zinc-200 transition hover:border-zinc-500 hover:bg-zinc-800"
                >
                  Apply filters
                </button>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
