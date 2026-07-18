"use client";

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createContext, useCallback, useContext, useEffect, useMemo, useState, useSyncExternalStore } from "react";

import { fetchCerebro } from "@/lib/cerebro-client";
import { currentUserActor } from "@/lib/identity";
import type { CurrentUser, CurrentUserResponse } from "@/lib/identity";
import {
  defaultUserPreferences,
  normalizeUserPreferences,
  sharedUserPreferencesFromURL,
  userPreferencesRequestBody,
  type UserPreferences,
} from "@/lib/user-preferences";

type ApiKeyContextValue = {
  apiKey: string;
  setApiKey: (value: string) => void;
};

type CommandPaletteContextValue = {
  isCommandPaletteOpen: boolean;
  openCommandPalette: () => void;
  closeCommandPalette: () => void;
};

type SidebarContextValue = {
  collapsed: boolean;
  toggleSidebar: () => void;
};

type ThemeMode = "light" | "dark";

type ThemeContextValue = {
  theme: ThemeMode;
  setTheme: (value: ThemeMode) => void;
  toggleTheme: () => void;
};

type CurrentUserContextValue = {
  actor: string;
  error: string | null;
  loading: boolean;
  user: CurrentUser | null;
};

type UserPreferencesContextValue = {
  error: string | null;
  loading: boolean;
  persisted: boolean;
  preferences: UserPreferences;
  reloadPreferences: () => Promise<void>;
  savePreferences: (value: UserPreferences) => Promise<void>;
  saving: boolean;
  setPreferences: (value: UserPreferences) => void;
  updatedAt: string | null;
};

type UserPreferencesResponse = {
  created_at?: string;
  persisted?: boolean;
  preferences?: unknown;
  tenant_id?: string;
  updated_at?: string;
  user_id?: string;
};

const ApiKeyContext = createContext<ApiKeyContextValue | undefined>(undefined);
const CommandPaletteContext = createContext<CommandPaletteContextValue | undefined>(undefined);
const SidebarContext = createContext<SidebarContextValue | undefined>(undefined);
const ThemeContext = createContext<ThemeContextValue | undefined>(undefined);
const CurrentUserContext = createContext<CurrentUserContextValue | undefined>(undefined);
const UserPreferencesContext = createContext<UserPreferencesContextValue | undefined>(undefined);

const STORAGE_KEY = "cerebro.apiKey";
const THEME_STORAGE_KEY = "cerebro.theme";
const THEME_CHANGE_EVENT = "cerebro-theme";

const notifyKeyChange = () => {
  window.dispatchEvent(new Event("cerebro-api-key"));
};

const subscribe = (callback: () => void) => {
  window.addEventListener("storage", callback);
  window.addEventListener("cerebro-api-key", callback);
  return () => {
    window.removeEventListener("storage", callback);
    window.removeEventListener("cerebro-api-key", callback);
  };
};

const getSnapshot = () => window.localStorage.getItem(STORAGE_KEY) ?? "";

const getServerSnapshot = () => "";

const notifyThemeChange = () => {
  window.dispatchEvent(new Event(THEME_CHANGE_EVENT));
};

const subscribeTheme = (callback: () => void) => {
  window.addEventListener("storage", callback);
  window.addEventListener(THEME_CHANGE_EVENT, callback);
  return () => {
    window.removeEventListener("storage", callback);
    window.removeEventListener(THEME_CHANGE_EVENT, callback);
  };
};

const getThemeSnapshot = (): ThemeMode => {
  const stored = window.localStorage.getItem(THEME_STORAGE_KEY);
  if (stored === "light" || stored === "dark") {
    return stored;
  }
  if (window.matchMedia?.("(prefers-color-scheme: dark)").matches) {
    return "dark";
  }
  return "light";
};

const getThemeServerSnapshot = (): ThemeMode => "light";

export function ApiKeyProvider({ children }: { children: React.ReactNode }) {
  const apiKey = useSyncExternalStore(subscribe, getSnapshot, getServerSnapshot);

  const setApiKey = (value: string) => {
    if (value) {
      window.localStorage.setItem(STORAGE_KEY, value);
    } else {
      window.localStorage.removeItem(STORAGE_KEY);
    }
    notifyKeyChange();
  };

  const contextValue = useMemo(() => ({ apiKey, setApiKey }), [apiKey]);

  return (
    <ApiKeyContext.Provider value={contextValue}>
      {children}
    </ApiKeyContext.Provider>
  );
}

export function GRCQueryProvider({ children }: { children: React.ReactNode }) {
  const [queryClient] = useState(() => new QueryClient({
    defaultOptions: {
      queries: {
        gcTime: 5 * 60_000,
        refetchOnWindowFocus: false,
        retry: false,
        staleTime: 30_000,
      },
    },
  }));

  return (
    <QueryClientProvider client={queryClient}>
      {children}
    </QueryClientProvider>
  );
}

export function CommandPaletteProvider({ children }: { children: React.ReactNode }) {
  const [isCommandPaletteOpen, setCommandPaletteOpen] = useState(false);

  const contextValue = useMemo(
    () => ({
      isCommandPaletteOpen,
      openCommandPalette: () => setCommandPaletteOpen(true),
      closeCommandPalette: () => setCommandPaletteOpen(false),
    }),
    [isCommandPaletteOpen],
  );

  return (
    <CommandPaletteContext.Provider value={contextValue}>
      {children}
    </CommandPaletteContext.Provider>
  );
}

export function SidebarProvider({ children }: { children: React.ReactNode }) {
  const [collapsed, setCollapsed] = useState(false);
  const contextValue = useMemo(
    () => ({ collapsed, toggleSidebar: () => setCollapsed((c) => !c) }),
    [collapsed],
  );
  return (
    <SidebarContext.Provider value={contextValue}>
      {children}
    </SidebarContext.Provider>
  );
}

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const localTheme = useSyncExternalStore(subscribeTheme, getThemeSnapshot, getThemeServerSnapshot);
  const userPreferences = useContext(UserPreferencesContext);
  const persistedTheme = userPreferences?.persisted ? userPreferences.preferences.display.theme : undefined;
  const theme = persistedTheme ?? localTheme;

  useEffect(() => {
    const root = document.documentElement;
    root.classList.toggle("dark", theme === "dark");
    root.dataset.theme = theme;
  }, [theme]);

  const persistTheme = useCallback((value: ThemeMode) => {
    window.localStorage.setItem(THEME_STORAGE_KEY, value);
    notifyThemeChange();
    if (userPreferences) {
      void userPreferences.savePreferences({
        ...userPreferences.preferences,
        display: {
          ...userPreferences.preferences.display,
          theme: value,
        },
      }).catch(() => undefined);
    }
  }, [userPreferences]);

  const contextValue = useMemo(
    () => ({
      theme,
      setTheme: persistTheme,
      toggleTheme: () => persistTheme(theme === "dark" ? "light" : "dark"),
    }),
    [persistTheme, theme],
  );

  return (
    <ThemeContext.Provider value={contextValue}>
      {children}
    </ThemeContext.Provider>
  );
}

export function CurrentUserProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<CurrentUser | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let mounted = true;
    const loadUser = async () => {
      try {
        const response = await fetch("/api/me", { cache: "no-store" });
        if (!response.ok) {
          throw new Error(`Current user unavailable (${response.status})`);
        }
        const payload = (await response.json()) as CurrentUserResponse;
        if (!mounted) return;
        setUser(payload.user);
        setError(null);
      } catch (nextError) {
        if (!mounted) return;
        setUser(null);
        setError(nextError instanceof Error ? nextError.message : "Current user unavailable");
      } finally {
        if (mounted) setLoading(false);
      }
    };
    void loadUser();
    return () => { mounted = false; };
  }, []);

  const contextValue = useMemo(
    () => ({
      actor: currentUserActor(user),
      error,
      loading,
      user,
    }),
    [error, loading, user],
  );

  return (
    <CurrentUserContext.Provider value={contextValue}>
      {children}
    </CurrentUserContext.Provider>
  );
}

export function UserPreferencesProvider({ children }: { children: React.ReactNode }) {
  const { apiKey } = useApiKey();
  const { actor, loading: userLoading } = useCurrentUser();
  const [preferences, setPreferencesState] = useState<UserPreferences>(defaultUserPreferences);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [persisted, setPersisted] = useState(false);
  const [updatedAt, setUpdatedAt] = useState<string | null>(null);

  useEffect(() => {
    const root = document.documentElement;
    root.dataset.density = preferences.display.density;
  }, [preferences.display.density]);

  const setPreferences = useCallback((value: UserPreferences) => {
    setPreferencesState(normalizeUserPreferences(value));
  }, []);

  const loadPreferences = useCallback(async () => {
    if (userLoading) {
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const response = await fetchCerebro<UserPreferencesResponse>("/user/preferences", apiKey);
      if (!response.ok) {
        throw new Error(`Preferences unavailable (${response.status})`);
      }
      const body = response.data ?? {};
      setPreferencesState(normalizeUserPreferences(body.preferences));
      setPersisted(Boolean(body.persisted));
      setUpdatedAt(body.updated_at ?? body.created_at ?? null);
    } catch (nextError) {
      setPreferencesState(defaultUserPreferences);
      setPersisted(false);
      setUpdatedAt(null);
      setError(nextError instanceof Error ? nextError.message : "Preferences unavailable");
    } finally {
      setLoading(false);
    }
  }, [apiKey, userLoading]);

  useEffect(() => {
    let mounted = true;
    const load = async () => {
      if (userLoading) {
        return;
      }
      setLoading(true);
      setError(null);
      const sharedPreferences = typeof window === "undefined" ? null : sharedUserPreferencesFromURL(window.location.href);
      if (sharedPreferences) {
        window.history.replaceState(null, "", sharedPreferences.cleanedPath);
        setPreferencesState(sharedPreferences.preferences);
        setPersisted(false);
        setUpdatedAt(null);
        setSaving(true);
        try {
          const response = await fetchCerebro<UserPreferencesResponse>("/user/preferences", apiKey, {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: userPreferencesRequestBody(sharedPreferences.preferences),
          });
          if (!response.ok) {
            throw new Error(`Preferences save failed (${response.status})`);
          }
          const body = response.data ?? {};
          if (!mounted) return;
          setPreferencesState(normalizeUserPreferences(body.preferences ?? sharedPreferences.preferences));
          setPersisted(Boolean(body.persisted ?? true));
          setUpdatedAt(body.updated_at ?? body.created_at ?? new Date().toISOString());
        } catch (nextError) {
          if (!mounted) return;
          setError(nextError instanceof Error ? nextError.message : "Preferences save failed");
        } finally {
          if (mounted) {
            setSaving(false);
            setLoading(false);
          }
        }
        return;
      }
      try {
        const response = await fetchCerebro<UserPreferencesResponse>("/user/preferences", apiKey);
        if (!response.ok) {
          throw new Error(`Preferences unavailable (${response.status})`);
        }
        const body = response.data ?? {};
        if (!mounted) return;
        setPreferencesState(normalizeUserPreferences(body.preferences));
        setPersisted(Boolean(body.persisted));
        setUpdatedAt(body.updated_at ?? body.created_at ?? null);
      } catch (nextError) {
        if (!mounted) return;
        setPreferencesState(defaultUserPreferences);
        setPersisted(false);
        setUpdatedAt(null);
        setError(nextError instanceof Error ? nextError.message : "Preferences unavailable");
      } finally {
        if (mounted) setLoading(false);
      }
    };
    void load();
    return () => { mounted = false; };
  }, [actor, apiKey, userLoading]);

  const savePreferences = useCallback(async (value: UserPreferences) => {
    const nextPreferences = normalizeUserPreferences(value);
    const previousPreferences = preferences;
    const previousPersisted = persisted;
    const previousUpdatedAt = updatedAt;
    setPreferencesState(nextPreferences);
    setSaving(true);
    setError(null);
    try {
      const response = await fetchCerebro<UserPreferencesResponse>("/user/preferences", apiKey, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: userPreferencesRequestBody(nextPreferences),
      });
      if (!response.ok) {
        throw new Error(`Preferences save failed (${response.status})`);
      }
      const body = response.data ?? {};
      setPreferencesState(normalizeUserPreferences(body.preferences ?? nextPreferences));
      setPersisted(Boolean(body.persisted ?? true));
      setUpdatedAt(body.updated_at ?? body.created_at ?? new Date().toISOString());
    } catch (nextError) {
      setPreferencesState(previousPreferences);
      setPersisted(previousPersisted);
      setUpdatedAt(previousUpdatedAt);
      setError(nextError instanceof Error ? nextError.message : "Preferences save failed");
      throw nextError;
    } finally {
      setSaving(false);
    }
  }, [apiKey, persisted, preferences, updatedAt]);

  const contextValue = useMemo<UserPreferencesContextValue>(
    () => ({
      error,
      loading,
      persisted,
      preferences,
      reloadPreferences: loadPreferences,
      savePreferences,
      saving,
      setPreferences,
      updatedAt,
    }),
    [error, loadPreferences, loading, persisted, preferences, savePreferences, saving, setPreferences, updatedAt],
  );

  return (
    <UserPreferencesContext.Provider value={contextValue}>
      {children}
    </UserPreferencesContext.Provider>
  );
}

export function useSidebar() {
  const context = useContext(SidebarContext);
  if (!context) throw new Error("useSidebar must be used within SidebarProvider");
  return context;
}

export function useApiKey() {
  const context = useContext(ApiKeyContext);
  if (!context) {
    throw new Error("useApiKey must be used within ApiKeyProvider");
  }
  return context;
}

export function useCommandPalette() {
  const context = useContext(CommandPaletteContext);
  if (!context) {
    throw new Error("useCommandPalette must be used within CommandPaletteProvider");
  }
  return context;
}

export function useTheme() {
  const context = useContext(ThemeContext);
  if (!context) {
    throw new Error("useTheme must be used within ThemeProvider");
  }
  return context;
}

export function useCurrentUser() {
  const context = useContext(CurrentUserContext);
  if (!context) {
    throw new Error("useCurrentUser must be used within CurrentUserProvider");
  }
  return context;
}

export function useUserPreferences() {
  const context = useContext(UserPreferencesContext);
  if (!context) {
    throw new Error("useUserPreferences must be used within UserPreferencesProvider");
  }
  return context;
}
