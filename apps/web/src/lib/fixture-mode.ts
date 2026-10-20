const truthy = (value: string | undefined) =>
  ["1", "true", "yes", "on"].includes((value ?? "").trim().toLowerCase());

export const isCerebroFixtureMode = () =>
  truthy(process.env.CEREBRO_WEB_FIXTURE_MODE) ||
  process.env.CEREBRO_API_BASE?.trim() === "fixture://local";
