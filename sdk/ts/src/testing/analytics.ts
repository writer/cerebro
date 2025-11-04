import {
  IntegrationAccountSummary,
  IntegrationCoverageRecord,
  IntegrationScopeBreakdown,
  RuntimeEventAggregate,
  RuntimeHealthRecord,
  RuntimeHealthSummary,
  RuntimeMetadataSnapshot,
} from "../types.js";

export function buildRuntimeHealthRecord(
  runtime: string,
  options: {
    windowStart: Date;
    windowEnd: Date;
    events?: Record<string, RuntimeEventAggregate>;
    warnings?: Record<string, RuntimeEventAggregate>;
    metadata?: RuntimeMetadataSnapshot | null;
  },
): RuntimeHealthRecord {
  return {
    runtime,
    windowStart: options.windowStart,
    windowEnd: options.windowEnd,
    events: options.events ?? {},
    warnings: options.warnings ?? {},
    latestMetadata: options.metadata ?? null,
  };
}

export function buildIntegrationCoverageRecord(options: {
  integration: string;
  providers: string[];
  status: string;
  scopes: IntegrationScopeBreakdown;
  accounts: IntegrationAccountSummary;
  coverageRatio: number | null;
  lastSuccess: Date | null;
  evaluatedAt: Date;
}): IntegrationCoverageRecord {
  return {
    integration: options.integration,
    providers: [...options.providers],
    status: options.status,
    scopes: options.scopes,
    accounts: options.accounts,
    coverageRatio: options.coverageRatio,
    lastSuccess: options.lastSuccess,
    evaluatedAt: options.evaluatedAt,
  };
}

export class StubRuntimeHealthClient {
  constructor(
    private readonly records: RuntimeHealthRecord[],
    private readonly windowHours = 24,
    private readonly generatedAt: Date = new Date(),
  ) {}

  async getRuntimeHealth(): Promise<RuntimeHealthSummary> {
    return {
      windowHours: this.windowHours,
      generatedAt: this.generatedAt,
      runtimes: [...this.records],
    };
  }
}

export class StubIntegrationCoverageClient {
  constructor(private readonly records: IntegrationCoverageRecord[]) {}

  async getCoverage(): Promise<IntegrationCoverageRecord[]> {
    return [...this.records];
  }
}

export default {
  StubRuntimeHealthClient,
  StubIntegrationCoverageClient,
  buildRuntimeHealthRecord,
  buildIntegrationCoverageRecord,
};
