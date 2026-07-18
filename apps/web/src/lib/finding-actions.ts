import type { CerebroResponse } from "./cerebro-client";

type FindingMutationOptions = {
  failurePrefix: string;
  onError: (message: string) => void;
  onSettled: () => void;
  onSuccess: () => void;
  request: () => Promise<Pick<CerebroResponse, "data" | "ok" | "status">>;
};

export const runFindingMutation = async ({
  failurePrefix,
  onError,
  onSettled,
  onSuccess,
  request,
}: FindingMutationOptions) => {
  try {
    const response = await request();
    if (!response.ok) {
      onError(typeof response.data === "string" ? response.data : `${failurePrefix} (${response.status})`);
      return false;
    }
    onSuccess();
    return true;
  } catch {
    onError("Finding update could not reach the API. Check your connection and retry.");
    return false;
  } finally {
    onSettled();
  }
};
