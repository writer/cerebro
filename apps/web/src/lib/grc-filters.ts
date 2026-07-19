"use client";

import { useMemo } from "react";

export type GRCFilterBinding<Key extends string = string> = {
  key: Key;
  label: string;
  value: string;
  setValue: (value: string) => void;
};

export type GRCFilterChip = {
  label: string;
  value: string;
  onClear: () => void;
};

export function useGRCFilterState<Key extends string>(bindings: readonly GRCFilterBinding<Key>[]) {
  return useMemo(() => {
    const values = {} as Record<Key, string>;
    const trimmedValues = {} as Record<Key, string>;
    const chips: GRCFilterChip[] = bindings.map((binding) => {
      values[binding.key] = binding.value;
      trimmedValues[binding.key] = binding.value.trim();
      return {
        label: binding.label,
        value: binding.value,
        onClear: () => binding.setValue(""),
      };
    });
    const clearAll = () => bindings.forEach((binding) => binding.setValue(""));
    const hasActiveFilters = chips.some((chip) => chip.value.trim());
    return { chips, clearAll, hasActiveFilters, trimmedValues, values };
  }, [bindings]);
}
