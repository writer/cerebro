"use client";

import { parseAsString, useQueryState } from "nuqs";
import { useCallback } from "react";

export const useQueryParamState = (key: string, fallback = "") => {
  const [value, setQueryValue] = useQueryState(
    key,
    parseAsString.withDefault(fallback).withOptions({
      clearOnDefault: true,
      history: "replace",
      scroll: false,
      shallow: true,
    }),
  );
  const setValue = useCallback((nextValue: string) => {
    const normalized = nextValue.trim();
    void setQueryValue(!normalized || normalized === fallback ? null : normalized);
  }, [fallback, setQueryValue]);

  return [value, setValue] as const;
};
