const rawAppVersion = process.env.NEXT_PUBLIC_CEREBRO_WEB_VERSION?.trim();

export const appVersion = rawAppVersion || "0.1.0";
export const appVersionLabel =
  appVersion.startsWith("v") || !/^\d+\.\d+\.\d+/.test(appVersion) ? appVersion : `v${appVersion}`;
