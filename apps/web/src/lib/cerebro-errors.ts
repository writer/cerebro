export const isApiUnavailableError = (error: string | null | undefined) =>
  Boolean(error && /(?:\b50[234]\b|unable to reach|timed out|failed to fetch|fetch failed|networkerror|econnrefused)/i.test(error));

export const productErrorCopy = (
  error: string | null | undefined,
  fallback = "This view could not load.",
) => {
  const message = error?.trim();
  if (!message) return fallback;
  if (/no fixture is registered/i.test(message)) {
    return "The local fixture dataset does not include records for this view.";
  }
  if (/no fixture .* found/i.test(message)) {
    return "No matching fixture record was found for this view.";
  }
  if (/cerebro request failed/i.test(message)) {
    return fallback;
  }
  if (/openapi|resource/i.test(message)) {
    return "API resource metadata could not load.";
  }
  return message;
};
