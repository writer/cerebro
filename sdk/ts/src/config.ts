export type SettingsLoader<T extends Record<string, any>> = () => T;

type AnySettings = Record<string, any>;

let globalLoader: SettingsLoader<AnySettings> = () => ({});
let cachedSettings: AnySettings | undefined;

/**
 * Configure the loader used by {@link getSettings} when a specific loader is not provided.
 */
export function configureSettingsLoader<T extends Record<string, any>>(loader: SettingsLoader<T>): void {
  globalLoader = loader as SettingsLoader<AnySettings>;
  cachedSettings = undefined;
}

/**
 * Return a cached settings instance produced by either the configured loader or the supplied loader.
 */
export function getSettings<T extends Record<string, any>>(loader?: SettingsLoader<T>): T {
  if (loader) {
    return loader();
  }

  if (!cachedSettings) {
    cachedSettings = globalLoader();
  }

  return cachedSettings as T;
}

/**
 * Refresh and return the cached settings instance. Optionally overrides the global loader.
 */
export function refreshSettings<T extends Record<string, any>>(factory?: SettingsLoader<T>): T {
  if (factory) {
    globalLoader = factory as SettingsLoader<AnySettings>;
  }

  cachedSettings = globalLoader();
  return cachedSettings as T;
}

export type SettingsProxyInstance<T extends Record<string, any>> = T & { snapshot(): T };

export type SettingsProxy<T extends Record<string, any>> = SettingsProxyInstance<T>;

export function createSettingsProxy<T extends Record<string, any>>(
  loader: SettingsLoader<T> = getSettings as SettingsLoader<T>,
): SettingsProxyInstance<T> {
  const target = {
    snapshot: () => loader(),
  } as { snapshot(): T };

  const handler: ProxyHandler<Record<string, unknown>> = {
    get: (value, prop) => {
      if (prop === "snapshot") {
        return value.snapshot;
      }
      const settings = loader();
      return (settings as AnySettings)[prop as keyof AnySettings];
    },
    has: (_, prop) => Reflect.has(loader(), prop),
    ownKeys: () => Reflect.ownKeys(loader()),
    getOwnPropertyDescriptor: (_, prop) => Object.getOwnPropertyDescriptor(loader(), prop),
  };

  return new Proxy(target, handler) as SettingsProxyInstance<T>;
}
