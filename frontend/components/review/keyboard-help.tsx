"use client";

import { useState, useEffect } from "react";
import { X, Keyboard } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";

type KeyboardShortcut = {
  keys: string;
  description: string;
  category: string;
};

const SHORTCUTS: KeyboardShortcut[] = [
  // Navigation
  { keys: "?", description: "Show keyboard shortcuts", category: "Navigation" },
  { keys: "Esc", description: "Close dialogs or clear selection", category: "Navigation" },
  { keys: "j / k", description: "Move down / up in task list", category: "Navigation" },
  { keys: "Enter", description: "Open selected task details", category: "Navigation" },
  
  // Actions
  { keys: "a", description: "Approve selected task(s)", category: "Actions" },
  { keys: "r", description: "Reject selected task(s)", category: "Actions" },
  { keys: "p", description: "Promote selected task(s)", category: "Actions" },
  { keys: "e", description: "Escalate selected task(s)", category: "Actions" },
  { keys: "x", description: "Toggle selection on current task", category: "Actions" },
  { keys: "Shift + A", description: "Select all tasks", category: "Actions" },
  { keys: "Shift + D", description: "Deselect all tasks", category: "Actions" },
  
  // Filters
  { keys: "f", description: "Focus search/filter", category: "Filters" },
  { keys: "Ctrl + K", description: "Toggle advanced filters", category: "Filters" },
  { keys: "Ctrl + R", description: "Refresh task list", category: "Filters" },
  
  // View
  { keys: "m", description: "Toggle metrics view", category: "View" },
  { keys: "1-5", description: "Filter by status (pending, approved, etc.)", category: "View" },
];

export function KeyboardHelp() {
  const [isOpen, setIsOpen] = useState(false);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "?" && !e.ctrlKey && !e.metaKey && !e.shiftKey) {
        e.preventDefault();
        setIsOpen((prev) => !prev);
      }
      if (e.key === "Escape" && isOpen) {
        setIsOpen(false);
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [isOpen]);

  const categories = Array.from(new Set(SHORTCUTS.map((s) => s.category)));

  return (
    <>
      {/* Help button */}
      <button
        onClick={() => setIsOpen(true)}
        className="fixed bottom-4 left-4 z-40 rounded-full border border-zinc-800 bg-zinc-950 p-3 shadow-lg transition hover:border-zinc-600 hover:bg-zinc-900"
        title="Keyboard shortcuts (?)"
      >
        <Keyboard className="h-5 w-5 text-zinc-400" />
      </button>

      {/* Modal */}
      <AnimatePresence>
        {isOpen && (
          <>
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm"
              onClick={() => setIsOpen(false)}
            />
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="fixed left-1/2 top-1/2 z-50 w-full max-w-2xl -translate-x-1/2 -translate-y-1/2 rounded-xl border border-zinc-800 bg-zinc-950 p-6 shadow-2xl"
            >
              <div className="mb-4 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Keyboard className="h-5 w-5 text-blue-500" />
                  <h2 className="text-lg font-bold text-zinc-100">Keyboard Shortcuts</h2>
                </div>
                <button
                  onClick={() => setIsOpen(false)}
                  className="text-zinc-500 transition hover:text-zinc-200"
                >
                  <X className="h-5 w-5" />
                </button>
              </div>

              <div className="max-h-[60vh] space-y-6 overflow-y-auto pr-2">
                {categories.map((category) => (
                  <div key={category}>
                    <h3 className="mb-3 text-xs font-semibold uppercase tracking-wide text-zinc-500">
                      {category}
                    </h3>
                    <div className="space-y-2">
                      {SHORTCUTS.filter((s) => s.category === category).map((shortcut, idx) => (
                        <div
                          key={`${category}-${idx}`}
                          className="flex items-center justify-between rounded-md border border-zinc-900 bg-black/50 px-3 py-2"
                        >
                          <span className="text-sm text-zinc-300">{shortcut.description}</span>
                          <kbd className="rounded border border-zinc-700 bg-zinc-900 px-2 py-1 text-xs font-mono text-zinc-200">
                            {shortcut.keys}
                          </kbd>
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>

              <div className="mt-6 border-t border-zinc-900 pt-4 text-center text-xs text-zinc-500">
                Press <kbd className="rounded border border-zinc-800 bg-zinc-900 px-2 py-0.5 font-mono">?</kbd> anytime to toggle this dialog
              </div>
            </motion.div>
          </>
        )}
      </AnimatePresence>
    </>
  );
}
