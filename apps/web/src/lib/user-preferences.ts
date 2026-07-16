export const HOME_SECTION_IDS = [
  "reviewNow",
  "programHealth",
] as const;

export type HomeSectionID = typeof HOME_SECTION_IDS[number];

export const HOME_SECTION_LABELS: Record<HomeSectionID, string> = {
  reviewNow: "Review queue",
  programHealth: "Program health",
};

export type DisplayDensity = "comfortable" | "compact";
export type ThemePreference = "light" | "dark";

export type UserPreferences = {
  homepage: {
    evidenceAutoLoad: boolean;
    sections: Record<HomeSectionID, boolean>;
  };
  display: {
    density: DisplayDensity;
    theme: ThemePreference;
  };
};

export const USER_PREFERENCES_SHARE_PARAM = "cerebro_home";

export const defaultHomeSections = HOME_SECTION_IDS.reduce(
  (sections, sectionID) => ({ ...sections, [sectionID]: true }),
  {} as Record<HomeSectionID, boolean>,
);

export const defaultUserPreferences: UserPreferences = {
  homepage: {
    evidenceAutoLoad: false,
    sections: defaultHomeSections,
  },
  display: {
    density: "comfortable",
    theme: "light",
  },
};

const isRecord = (value: unknown): value is Record<string, unknown> =>
  Boolean(value && typeof value === "object" && !Array.isArray(value));

const normalizeHomeSections = (value: unknown) => {
  const source = isRecord(value) ? value : {};
  return HOME_SECTION_IDS.reduce((sections, sectionID) => {
    const nextValue = source[sectionID];
    return {
      ...sections,
      [sectionID]: typeof nextValue === "boolean" ? nextValue : defaultHomeSections[sectionID],
    };
  }, {} as Record<HomeSectionID, boolean>);
};

const normalizeDensity = (value: unknown): DisplayDensity =>
  value === "compact" ? "compact" : "comfortable";

const normalizeTheme = (value: unknown): ThemePreference =>
  value === "dark" ? "dark" : "light";

export const normalizeUserPreferences = (value: unknown): UserPreferences => {
  const source = isRecord(value) ? value : {};
  const homepage = isRecord(source.homepage) ? source.homepage : {};
  const display = isRecord(source.display) ? source.display : {};

  return {
    homepage: {
      evidenceAutoLoad: typeof homepage.evidenceAutoLoad === "boolean"
        ? homepage.evidenceAutoLoad
        : defaultUserPreferences.homepage.evidenceAutoLoad,
      sections: normalizeHomeSections(homepage.sections),
    },
    display: {
      density: normalizeDensity(display.density),
      theme: normalizeTheme(display.theme),
    },
  };
};

export const userPreferencesRequestBody = (preferences: UserPreferences) =>
  JSON.stringify({ preferences: normalizeUserPreferences(preferences) });

export const userPreferencesShareValue = (preferences: UserPreferences) =>
  JSON.stringify({
    v: 1,
    preferences: normalizeUserPreferences(preferences),
  });

export const userPreferencesFromShareValue = (value: string | null | undefined): UserPreferences | null => {
  if (!value) return null;
  const parse = (candidate: string) => {
    const parsed = JSON.parse(candidate) as unknown;
    if (isRecord(parsed) && "preferences" in parsed) {
      return normalizeUserPreferences(parsed.preferences);
    }
    if (isRecord(parsed)) {
      return normalizeUserPreferences(parsed);
    }
    return null;
  };
  try {
    return parse(value);
  } catch {
    try {
      return parse(decodeURIComponent(value));
    } catch {
      return null;
    }
  }
};

export const userPreferencesShareURL = (href: string, preferences: UserPreferences) => {
  const url = new URL(href);
  url.pathname = "/";
  url.search = "";
  url.hash = "";
  url.searchParams.set(USER_PREFERENCES_SHARE_PARAM, userPreferencesShareValue(preferences));
  return url.toString();
};

export const sharedUserPreferencesFromURL = (href: string) => {
  const url = new URL(href);
  const preferences = userPreferencesFromShareValue(url.searchParams.get(USER_PREFERENCES_SHARE_PARAM));
  if (!preferences) return null;
  url.searchParams.delete(USER_PREFERENCES_SHARE_PARAM);
  return {
    preferences,
    cleanedPath: `${url.pathname}${url.search}${url.hash}`,
  };
};
