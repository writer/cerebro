export interface ActorMapping {
  actorId: string;
  displayName?: string;
}

export type ProactiveSlackChannelPolicy = "strict" | "quiet" | "watch" | "eager";

export interface AssistantBotHandoffPolicy {
  channelId: string;
  botUserIds: Set<string>;
  cooldownSeconds?: number;
  maxHandoffsPerThread?: number;
  windowSeconds?: number;
}

export interface CodeModeConfig {
  enabled: boolean;
  maxToolCalls: number;
  maxSideEffectCalls: number;
  timeoutMs: number;
  memoryLimitBytes: number;
  maxScriptBytes: number;
  maxOutputBytes: number;
}

export interface AppConfig {
  nodeEnv: string;
  port: number;
  slack: {
    botToken: string;
    signingSecret?: string;
    socketMode: boolean;
    appToken?: string;
    defaultChannelId?: string;
    allowedTeamIds: Set<string>;
    auditLogsToken?: string;
    findingWriteUserIds: Set<string>;
    sourceWriteUserIds: Set<string>;
    responseWriteUserIds: Set<string>;
    graphActionUserIds: Set<string>;
    autonomyApprovalUserIds: Set<string>;
    operatorUserIds: Set<string>;
    triageChannelIds: Set<string>;
    riskAttestationChannelIds: Set<string>;
    riskAttestationTimeoutMs: number;
    triageChannelPolicies: Map<string, ProactiveSlackChannelPolicy>;
    triageAutoReply: boolean;
    lifecycleNoticesEnabled: boolean;
    lifecycleChannelIds: Set<string>;
    researchMaxChannels: number;
    researchHistoryLimit: number;
    assistantBotUserIds: Set<string>;
    assistantBotCooldownSeconds: number;
    assistantBotMaxHandoffsPerThread: number;
    assistantBotHandoffWindowSeconds: number;
    assistantBotHandoffPolicies: AssistantBotHandoffPolicy[];
  };
  cerebro: {
    baseUrl: string;
    tenantId: string;
    requestTimeoutMs: number;
    webBaseUrl?: string;
    defaultRuntimeIds: string[];
    companionRuntimeId: string;
    assistantHelpMention?: string;
    apiKeys: {
      read: string;
      findings?: string;
      source?: string;
      runtimeResponse?: string;
      graphActions?: string;
    };
    slackUsers: Map<string, ActorMapping>;
  };
  evidenceCas: {
    baseUrl?: string;
    readToken?: string;
    readTokenInfisicalSecretName?: string;
    defaultBucket: string;
    timeoutMs: number;
  };
  infisical: {
    enabled: boolean;
    baseUrl: string;
    projectId?: string;
    projectSlug: string;
    environment: string;
    secretPath: string;
    identityId?: string;
    awsRegion: string;
    stsEndpoint?: string;
    timeoutMs: number;
    cacheTtlMs: number;
    allowSecretValues: boolean;
  };
  pantherMcp: {
    enabled: boolean;
    url?: string;
    authToken?: string;
    allowedTools: Set<string>;
    allowMutatingTools: boolean;
    timeoutMs: number;
  };
  triage: {
    enabled: boolean;
    threadStateTableName?: string;
    minConfidence: number;
    maxResearchSteps: number;
    timeoutMs: number;
    maxConcurrent: number;
    promptMaxChars: number;
    promptCompactionTargetChars: number;
    duplicateQuestionCooldownMs: number;
    workQueueEnabled: boolean;
    workQueueUrl?: string;
    workQueuePublisherIntervalMs: number;
    workQueuePublisherBatchSize: number;
    workQueueConsumerCount: number;
    workQueueVisibilityTimeoutSeconds: number;
    assistantRuntime: "pi" | "flue";
    pi: {
      enabled: boolean;
      provider: string;
      model: string;
      thinkingLevel: "off" | "minimal" | "low" | "medium" | "high" | "xhigh";
      executionModel: string;
      executionThinkingLevel: "off" | "minimal" | "low" | "medium" | "high" | "xhigh";
    };
  };
  learning: {
    enabled: boolean;
    tableName?: string;
    maxSearchResults: number;
    channelLearningEnabled: boolean;
    channelLearningExcludedChannelIds: Set<string>;
    channelLearningBatchSize: number;
    channelLearningFlushIntervalMs: number;
    dailyNotesEnabled: boolean;
    dailyNotesTimeZone: string;
    dailyNotesConsolidationHour: number;
    dailyNotesConsolidationMinute: number;
    dailyNotesNightStartHour: number;
    dailyNotesNightEndHour: number;
    dailyNotesCheckIntervalMs: number;
    dailyNotesRetentionDays: number;
    workingMemoryEnabled: boolean;
    workingMemoryDir?: string;
    workingMemoryCharLimit: number;
    teamMemoryCharLimit: number;
    learningDocsEnabled: boolean;
    learningDocsDir?: string;
    learningDocsCharLimit: number;
  };
  code: {
    enabled: boolean;
    workspaceDir: string;
    defaultRepo: string;
    repoPathPrefix: string;
    writeAllowedOrgs: Set<string>;
    branchPrefix: string;
    maxFileBytes: number;
    maxFiles: number;
    shellEnabled: boolean;
    shellTimeoutMs: number;
    shellMaxOutputBytes: number;
    shellMaxCommandBytes: number;
    githubToken?: string;
    githubApp?: {
      appId: string;
      installationId: string;
      privateKeyBase64: string;
    };
  };
  /** Optional for callers that construct legacy test or embedded configs. */
  codeMode?: CodeModeConfig;
  ticketing: {
    jira: {
      baseUrl?: string;
      authEmail?: string;
      apiToken?: string;
      apiTokenInfisicalSecretName?: string;
      defaultProjectKey?: string;
      defaultIssueType: string;
    };
    linear: {
      apiKey?: string;
      apiKeyInfisicalSecretName?: string;
      defaultTeamId?: string;
    };
    maxDescriptionChars: number;
    timeoutMs: number;
  };
  complianceContext: {
    enabled: boolean;
    repo: string;
    ref: string;
    localDir?: string;
    cacheTtlMs: number;
    fetchTimeoutMs: number;
    maxFileBytes: number;
    maxTotalBytes: number;
  };
  selfRepair: {
    enabled: boolean;
    createPr: boolean;
    threshold: number;
    lookbackHours: number;
    cooldownHours: number;
  };
  improvement: {
    enabled: boolean;
    tableName?: string;
    artifactBucket?: string;
    queueUrl?: string;
    promotionKeyId?: string;
    delegationKeyId?: string;
    delegationRolloutMode: "disabled" | "shadow" | "canary" | "active";
    delegationCanaryBasisPoints: number;
    delegationTtlSeconds: number;
    delegationPolicyVersion: string;
    delegationToolsetVersion: string;
    delegationMaxSourceCalls: number;
    delegationMaxRuntimeMs: number;
    signalThreshold: number;
    pollIntervalMs: number;
    staleRunHours: number;
  };
  autonomy: {
    goalsEnabled: boolean;
    goalsTableName?: string;
    legacyGoalsTableName?: string;
    maxListedGoals: number;
    runnerEnabled: boolean;
    runnerPollIntervalMs: number;
    runnerLeaseMs: number;
    runnerMaxGoalsPerTick: number;
    queueEnabled: boolean;
    queueUrl?: string;
    queuePublisherIntervalMs: number;
    queuePublisherBatchSize: number;
    queueReconcileIntervalMs: number;
    queueConsumerCount: number;
    queueVisibilityTimeoutSeconds: number;
  };
  schedules: {
    enabled: boolean;
    tableName?: string;
    pollIntervalMs: number;
    maxConcurrent: number;
    defaultChannelId?: string;
    defaultTimeZone: string;
  };
  telemetry: {
    enabled: boolean;
    metricsEnabled: boolean;
    serviceName: string;
    deploymentEnvironment: string;
    resourceAttributes?: string;
  };
  coordination: {
    version: string;
    commitSubject?: string;
    eventDedupeEnabled: boolean;
    eventDedupeTtlSeconds: number;
    lifecycleNoticeTtlSeconds: number;
    deploymentFenceEnabled: boolean;
    deploymentFenceCacheMs: number;
    ecsClusterName?: string;
    ecsServiceName?: string;
  };
  a2a: {
    enabled: boolean;
    instanceId: string;
    label: string;
    role: string;
    capabilities: string[];
    heartbeatIntervalMs: number;
    instanceTtlSeconds: number;
    inboxPollIntervalMs: number;
    drainTimeoutMs: number;
    ensembleEnabled: boolean;
    ensembleMaxPeers: number;
    ensembleTimeoutMs: number;
    workFleetEnabled: boolean;
    workFleetMaxPeers: number;
    workFleetTimeoutMs: number;
    modelMaxConcurrent: number;
    sourceMaxConcurrent: number;
    rateLeaseMs: number;
    rateWaitMs: number;
  };
}
