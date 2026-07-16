"use client";

import { type RefObject, useEffect } from "react";

export function usePopoverDismissal<T extends HTMLElement>({
  containerRef,
  enabled,
  onDismiss,
}: {
  containerRef: RefObject<T | null>;
  enabled: boolean;
  onDismiss: () => void;
}) {
  useEffect(() => {
    if (!enabled) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        onDismiss();
      }
    };
    const onPointerDown = (event: PointerEvent) => {
      const target = event.target;
      if (target instanceof Node && !containerRef.current?.contains(target)) {
        onDismiss();
      }
    };
    document.addEventListener("keydown", onKeyDown);
    document.addEventListener("pointerdown", onPointerDown);
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      document.removeEventListener("pointerdown", onPointerDown);
    };
  }, [containerRef, enabled, onDismiss]);
}
