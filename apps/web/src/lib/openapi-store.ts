"use client";

import { useEffect, useSyncExternalStore } from "react";

import { buildOpenApiModel, type OpenApiModel } from "@/lib/openapi";

type OpenApiState = {
  status: "idle" | "loading" | "ready" | "error";
  model?: OpenApiModel;
  error?: string;
};

const API_KEY_STORAGE = "cerebro.apiKey";

let state: OpenApiState = { status: "idle" };
const listeners = new Set<() => void>();
let isKeyListenerReady = false;
const serverSnapshot: OpenApiState = { status: "loading" };

const emit = () => {
  listeners.forEach((listener) => listener());
};

const loadOpenApi = async () => {
  if (state.status !== "idle") {
    return;
  }
  state = { status: "loading" };
  emit();

  try {
    const apiKey = window.localStorage.getItem(API_KEY_STORAGE) ?? "";
    const response = await fetch("/api/openapi", {
      cache: "no-store",
      headers: apiKey ? { "X-API-Key": apiKey } : {},
    });
    if (!response.ok) {
      throw new Error(`OpenAPI fetch failed (${response.status})`);
    }
    const spec = await response.json();
    state = { status: "ready", model: buildOpenApiModel(spec) };
  } catch (err) {
    state = {
      status: "error",
      error: err instanceof Error ? err.message : "Failed to load OpenAPI",
    };
  }

  emit();
};

export const ensureOpenApiLoaded = () => {
  if (typeof window === "undefined") {
    return;
  }
  if (!isKeyListenerReady) {
    const handleKeyChange = () => {
      state = { status: "idle" };
      emit();
      void loadOpenApi();
    };
    window.addEventListener("storage", handleKeyChange);
    window.addEventListener("cerebro-api-key", handleKeyChange);
    isKeyListenerReady = true;
  }
  void loadOpenApi();
};

const subscribe = (listener: () => void) => {
  listeners.add(listener);
  return () => listeners.delete(listener);
};

const getSnapshot = () => state;
const getServerSnapshot = () => serverSnapshot;

export const useOpenApi = () => {
  const snapshot = useSyncExternalStore(
    subscribe,
    getSnapshot,
    getServerSnapshot,
  );

  useEffect(() => {
    ensureOpenApiLoaded();
  }, []);

  return snapshot;
};
