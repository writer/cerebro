"use client";

import { useEffect, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { CheckCircle, XCircle, AlertTriangle, Info } from "lucide-react";

type ToastType = "success" | "error" | "warning" | "info";

type Toast = {
  id: string;
  type: ToastType;
  title: string;
  message?: string;
  duration?: number;
};

const TOAST_ICONS: Record<ToastType, React.ComponentType<{ className?: string }>> = {
  success: CheckCircle,
  error: XCircle,
  warning: AlertTriangle,
  info: Info,
};

const TOAST_COLORS: Record<ToastType, string> = {
  success: "border-green-900 bg-green-950/90",
  error: "border-red-900 bg-red-950/90",
  warning: "border-yellow-900 bg-yellow-950/90",
  info: "border-blue-900 bg-blue-950/90",
};

let toastIdCounter = 0;

const toastCallbacks = new Set<(toast: Toast) => void>();

export function showToast(type: ToastType, title: string, message?: string, duration = 5000) {
  const toast: Toast = {
    id: `toast-${++toastIdCounter}`,
    type,
    title,
    message,
    duration,
  };
  toastCallbacks.forEach((callback) => callback(toast));
}

export function ReviewNotifications() {
  const [toasts, setToasts] = useState<Toast[]>([]);

  useEffect(() => {
    const addToast = (toast: Toast) => {
      setToasts((prev) => [...prev, toast]);
      
      if (toast.duration && toast.duration > 0) {
        setTimeout(() => {
          setToasts((prev) => prev.filter((t) => t.id !== toast.id));
        }, toast.duration);
      }
    };

    toastCallbacks.add(addToast);
    return () => {
      toastCallbacks.delete(addToast);
    };
  }, []);

  const removeToast = (id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  };

  return (
    <div className="pointer-events-none fixed bottom-4 right-4 z-50 flex flex-col gap-2">
      <AnimatePresence>
        {toasts.map((toast) => {
          const Icon = TOAST_ICONS[toast.type];
          return (
            <motion.div
              key={toast.id}
              initial={{ opacity: 0, y: 20, scale: 0.95 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, x: 100, scale: 0.95 }}
              transition={{ duration: 0.2 }}
              className={`pointer-events-auto w-96 rounded-lg border p-4 shadow-xl ${TOAST_COLORS[toast.type]}`}
            >
              <div className="flex items-start gap-3">
                <Icon className="h-5 w-5 flex-shrink-0 text-white" />
                <div className="flex-1">
                  <h4 className="text-sm font-semibold text-white">{toast.title}</h4>
                  {toast.message && (
                    <p className="mt-1 text-xs text-zinc-300">{toast.message}</p>
                  )}
                </div>
                <button
                  onClick={() => removeToast(toast.id)}
                  className="text-zinc-400 transition hover:text-white"
                >
                  <XCircle className="h-4 w-4" />
                </button>
              </div>
            </motion.div>
          );
        })}
      </AnimatePresence>
    </div>
  );
}
