const PRODUCT_PACKAGE = "@writer/cerebro-slack-companion";
const REQUIRED_EXPORTS = [
  "handleEventsApiRequest",
  "handleSocketModeRequest",
  "MissionLedger",
  "SlackAdmissionController",
] as const;

export interface ProductReleaseReceipt {
  required: boolean;
  status: "disabled" | "verified";
  package: string;
  version?: string;
  commit?: string;
  exports?: readonly string[];
}

export type ProductReleaseModuleLoader = () => Promise<Record<string, unknown>>;

export async function verifyProductReleaseRuntime(
  env: NodeJS.ProcessEnv = process.env,
  loadModule: ProductReleaseModuleLoader = loadProductModule,
): Promise<ProductReleaseReceipt> {
  const required = env.CEREBRO_PRODUCT_RELEASE_REQUIRED?.trim().toLowerCase() === "true";
  if (!required) {
    return { required: false, status: "disabled", package: PRODUCT_PACKAGE };
  }

  const version = env.CEREBRO_PRODUCT_RELEASE_VERSION?.trim() ?? "";
  const commit = env.CEREBRO_PRODUCT_RELEASE_COMMIT?.trim().toLowerCase() ?? "";
  if (!/^v[0-9]+\.[0-9]+\.[0-9]+$/.test(version)) {
    throw new Error("Signed Cerebro product release version is missing or invalid.");
  }
  if (!/^[0-9a-f]{40}$/.test(commit)) {
    throw new Error("Signed Cerebro product release commit is missing or invalid.");
  }

  let loaded: Record<string, unknown>;
  try {
    loaded = await loadModule();
  } catch (error) {
    throw new Error(`Signed Cerebro product package ${PRODUCT_PACKAGE} could not be loaded.`, { cause: error });
  }
  const missing = REQUIRED_EXPORTS.filter((name) => typeof loaded[name] !== "function");
  if (missing.length > 0) {
    throw new Error(`Signed Cerebro product package is missing required exports: ${missing.join(", ")}.`);
  }

  return {
    required: true,
    status: "verified",
    package: PRODUCT_PACKAGE,
    version,
    commit,
    exports: REQUIRED_EXPORTS,
  };
}

async function loadProductModule(): Promise<Record<string, unknown>> {
  const moduleName = PRODUCT_PACKAGE;
  return import(moduleName) as Promise<Record<string, unknown>>;
}
