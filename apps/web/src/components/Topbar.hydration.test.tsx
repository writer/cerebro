/**
 * @vitest-environment jsdom
 */
import { act, type ReactNode } from "react";
import { hydrateRoot, type Root } from "react-dom/client";
import { renderToString } from "react-dom/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

type MockCurrentUserState = {
  actor: string;
  error: string | null;
  loading: boolean;
  user: {
    actorId: string;
    actorLabel: string;
    confidence: "fallback";
    displayName: string;
    initials: string;
    provider: string;
    source: "local-fallback";
    username: string;
  } | null;
};

const providerState = vi.hoisted(() => ({
  currentUser: {
    actor: "",
    error: null,
    loading: true,
    user: null,
  } as MockCurrentUserState,
}));

vi.mock("next/link", () => ({
  default: ({ children }: { children: ReactNode }) => children,
}));

vi.mock("next/navigation", () => ({
  useSearchParams: () => new URLSearchParams(),
}));

vi.mock("@/components/providers", () => ({
  useApiKey: () => ({ apiKey: "", setApiKey: vi.fn() }),
  useCommandPalette: () => ({ openCommandPalette: vi.fn() }),
  useConsoleConfig: () => ({
    config: {
      apiBase: "/api/cerebro",
      forwardRequestAuth: false,
      serverAuthConfigured: false,
    },
  }),
  useCurrentUser: () => providerState.currentUser,
  useTheme: () => ({ setTheme: vi.fn(), theme: "light", toggleTheme: vi.fn() }),
  useUserPreferences: () => ({
    error: null,
    loading: false,
    persisted: false,
    preferences: {
      display: { density: "comfortable", theme: "light" },
      homepage: { sections: {} },
    },
    savePreferences: vi.fn().mockResolvedValue(undefined),
    saving: false,
    updatedAt: null,
  }),
}));

vi.mock("@/lib/grc-client", () => ({
  DASHBOARD_FINDING_LIMIT: 100,
  grcDashboardPath: vi.fn(() => "/api/cerebro/grc/dashboard"),
  grcPath: vi.fn((path: string) => path),
  useGRCQuery: () => ({ data: null, error: null, loading: false }),
}));

vi.mock("@/lib/use-popover-dismissal", () => ({
  usePopoverDismissal: vi.fn(),
}));

import Topbar from "./Topbar";

const reactActEnvironment = globalThis as typeof globalThis & {
  IS_REACT_ACT_ENVIRONMENT?: boolean;
};

describe("Topbar hydration", () => {
  let container: HTMLDivElement;
  let root: Root | null;

  beforeEach(() => {
    reactActEnvironment.IS_REACT_ACT_ENVIRONMENT = true;
    providerState.currentUser = {
      actor: "",
      error: null,
      loading: true,
      user: null,
    };
    container = document.createElement("div");
    document.body.appendChild(container);
    root = null;
  });

  afterEach(() => {
    if (root) act(() => root?.unmount());
    container.remove();
  });

  it("keeps the server identity posture until the Topbar hydrates", async () => {
    container.innerHTML = renderToString(<Topbar />);
    expect(container.textContent).toContain("No API key · Resolving identity");

    providerState.currentUser = {
      actor: "local-developer",
      error: null,
      loading: false,
      user: {
        actorId: "local-developer",
        actorLabel: "local-developer",
        confidence: "fallback",
        displayName: "Local developer",
        initials: "LD",
        provider: "local",
        source: "local-fallback",
        username: "local-developer",
      },
    };
    const recoverableErrors: unknown[] = [];

    await act(async () => {
      root = hydrateRoot(container, <Topbar />, {
        onRecoverableError: (error) => recoverableErrors.push(error),
      });
      await new Promise((resolve) => window.setTimeout(resolve, 0));
    });

    expect(recoverableErrors).toEqual([]);
    expect(container.textContent).toContain("No API key · Local identity");
  });
});
