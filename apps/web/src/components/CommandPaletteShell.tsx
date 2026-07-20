"use client";

import dynamic from "next/dynamic";
import { useEffect } from "react";

import { useCommandPalette } from "@/components/providers";

const CommandPalette = dynamic(() => import("@/components/CommandPalette"), {
  ssr: false,
  loading: () => null,
});

const isEditableTarget = (target: EventTarget | null) => {
  if (!(target instanceof HTMLElement)) return false;
  const tag = target.tagName.toLowerCase();
  return tag === "input" || tag === "textarea" || tag === "select" || target.isContentEditable;
};

export default function CommandPaletteShell() {
  const { isCommandPaletteOpen, openCommandPalette } = useCommandPalette();

  useEffect(() => {
    const onKeyDown = (event: globalThis.KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        openCommandPalette();
      }
      if (event.key === "/" && !isEditableTarget(event.target)) {
        event.preventDefault();
        openCommandPalette();
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [openCommandPalette]);

  if (!isCommandPaletteOpen) return null;
  return <CommandPalette />;
}
