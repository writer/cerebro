package agentplatform

const (
	AgentServiceLifecycleSchemaVersion   = "cerebro.agent-service-lifecycle/v1"
	AgentServiceLifecycleContractVersion = "2026-07-16.cerebro-agent-service-lifecycle"
	AgentServiceLifecycleContractPath    = "/api/v1/agent-platform/service-lifecycle/contract"
)

// AgentServiceLifecycle returns the portable service lifecycle contract. The
// contract describes continuity behavior and leaves transport, orchestration,
// persistence implementation, and environment policy behind adapters.
func AgentServiceLifecycle() AgentServiceLifecycleContract {
	return AgentServiceLifecycleContract{
		SchemaVersion:   AgentServiceLifecycleSchemaVersion,
		ContractVersion: AgentServiceLifecycleContractVersion,
		Compatibility: SchemaCompatibility{
			CurrentVersion:     AgentServiceLifecycleSchemaVersion,
			ReadVersions:       []string{AgentServiceLifecycleSchemaVersion},
			WriteVersions:      []string{AgentServiceLifecycleSchemaVersion},
			RollingUpgradeRule: "A generation reads the current and immediately previous schema, writes only the current schema, and cannot own work when required capabilities are incompatible.",
			CapabilityDecisions: []CapabilityCompatibilityDecision{
				CapabilityCompatibilityDecisionSupported,
				CapabilityCompatibilityDecisionDegraded,
				CapabilityCompatibilityDecisionBlocked,
				CapabilityCompatibilityDecisionIncompatible,
			},
		},
		InstallationStates: []InstallationStateDefinition{
			{State: InstallationLifecycleStateAuthorizing, Meaning: "Authorization is being established; admission is disabled."},
			{State: InstallationLifecycleStateBinding, Meaning: "A stable service binding is being recorded; admission is disabled."},
			{State: InstallationLifecycleStateVerifying, Meaning: "Identity, persistence, delivery, and required capabilities are being verified; admission is disabled."},
			{State: InstallationLifecycleStateActive, AdmissionAllowed: true, Meaning: "The binding is verified and may admit work."},
			{State: InstallationLifecycleStateSuspended, Meaning: "Admission and background work are paused while durable state is retained."},
			{State: InstallationLifecycleStateRevoked, Meaning: "Authorization is no longer valid; admitted work and audit records remain governed by policy."},
			{State: InstallationLifecycleStateRetired, Meaning: "Admission is permanently disabled and retention obligations have been recorded."},
		},
		DeploymentStates: []DeploymentStateDefinition{
			{State: DeploymentGenerationStateProposed, Meaning: "A version and target have a reviewable plan."},
			{State: DeploymentGenerationStateProvisioning, Meaning: "The generation is being created and cannot own work."},
			{State: DeploymentGenerationStateValidating, Meaning: "Compatibility, continuity, and user-path checks are running."},
			{State: DeploymentGenerationStateActive, MayOwnRoutes: true, MayOwnLeases: true, Meaning: "The generation may own routes and leases."},
			{State: DeploymentGenerationStateFailed, Meaning: "Validation failed before activation or rollback completed."},
			{State: DeploymentGenerationStateRolledBack, Meaning: "A prior generation was restored."},
			{State: DeploymentGenerationStateSuperseded, Meaning: "A newer proposal replaced this generation."},
			{State: DeploymentGenerationStateRetired, Meaning: "The generation is fenced and cannot return to service."},
		},
		ServiceStates: []ServiceStateDefinition{
			{State: ServiceAvailabilityStateBooting, Admission: "through another ready admission edge only", ExistingWork: "none", Meaning: "The process is live but has not completed compatibility and dependency checks."},
			{State: ServiceAvailabilityStateWarming, Admission: "through another ready admission edge only", ExistingWork: "none", Meaning: "Required connections and capabilities are being prepared."},
			{State: ServiceAvailabilityStateReady, Admission: "allowed", NewLeases: true, ExistingWork: "runs normally", Meaning: "Required capabilities and durable ports are available."},
			{State: ServiceAvailabilityStateDegraded, Admission: "allowed by explicit policy", NewLeases: true, ExistingWork: "compatible work continues", Meaning: "A bounded capability is unavailable or capacity is constrained."},
			{State: ServiceAvailabilityStateDraining, Admission: "through another ready admission edge", ExistingWork: "finish or checkpoint by the drain deadline", Meaning: "The generation is leaving service and cannot take new leases."},
			{State: ServiceAvailabilityStateOffline, Admission: "queue or reject by binding policy", ExistingWork: "paused durably", Meaning: "No compatible executor is available."},
			{State: ServiceAvailabilityStateRecovering, Admission: "allowed", ExistingWork: "resumes in priority order", Meaning: "Receipts, leases, schedules, and deliveries are being reconciled."},
			{State: ServiceAvailabilityStateStopped, Admission: "disabled", ExistingWork: "retained or migrated by policy", Meaning: "This service instance is intentionally out of service."},
		},
		RunStates: []RunStateDefinition{
			{State: RunLifecycleStateReceived, Meaning: "Input is verified but has no durable acceptance receipt yet."},
			{State: RunLifecycleStateAdmitted, Meaning: "The durable receipt committed and transport acknowledgement is permitted."},
			{State: RunLifecycleStateRejected, Terminal: true, Meaning: "Admission did not commit and the service must not claim the input was saved."},
			{State: RunLifecycleStateQueued, Meaning: "The run is durable and waiting for a compatible lease."},
			{State: RunLifecycleStateLeased, Meaning: "One current generation owns a bounded execution lease."},
			{State: RunLifecycleStateRunning, Meaning: "The lease owner is executing from the latest durable checkpoint."},
			{State: RunLifecycleStateWaiting, Meaning: "Durable human input or approval is required."},
			{State: RunLifecycleStatePaused, Meaning: "Execution stopped at a recoverable boundary."},
			{State: RunLifecycleStateDelivering, Meaning: "Durable delivery parts are being reconciled."},
			{State: RunLifecycleStateCompleted, Terminal: true, Meaning: "Execution and every required delivery receipt are durable."},
			{State: RunLifecycleStateCancelled, Terminal: true, Meaning: "Cancellation committed according to effect and retention policy."},
			{State: RunLifecycleStateExpired, Terminal: true, Meaning: "A bounded wait or retention deadline elapsed."},
			{State: RunLifecycleStateBlocked, Terminal: true, Meaning: "Recovery policy is exhausted and an explicit next action is required."},
		},
		Transitions: lifecycleTransitions(),
		Ports: []PortContract{
			{ID: "lifecycle_event_log", Purpose: "Append monotonic transition events for audit, replay, and external continuity observation.", RequiredOperations: []string{"append", "read_subject", "read_after_sequence"}, ProductionDurabilityRequired: true},
			{ID: "admission_store", Purpose: "Atomically deduplicate input and commit a recoverable run receipt before acknowledgement.", RequiredOperations: []string{"admit", "get_by_idempotency_key", "get_run"}, ProductionDurabilityRequired: true},
			{ID: "run_queue", Purpose: "List and claim runnable work without process-local ownership.", RequiredOperations: []string{"enqueue", "claim", "release", "list_recoverable"}, ProductionDurabilityRequired: true},
			{ID: "lease_store", Purpose: "Acquire, renew, release, and fence one current generation per run.", RequiredOperations: []string{"acquire", "renew", "release", "advance_generation"}, ProductionDurabilityRequired: true},
			{ID: "checkpoint_store", Purpose: "Append ordered resumable execution checkpoints.", RequiredOperations: []string{"append", "latest", "list_by_run"}, ProductionDurabilityRequired: true},
			{ID: "effect_store", Purpose: "Record idempotent external effects and their verification state.", RequiredOperations: []string{"begin", "complete", "verify", "get_by_idempotency_key"}, ProductionDurabilityRequired: true},
			{ID: "delivery_outbox", Purpose: "Deliver stable message parts once and reconcile incomplete delivery.", RequiredOperations: []string{"plan", "claim_part", "complete_part", "list_incomplete"}, ProductionDurabilityRequired: true},
			{ID: "schedule_store", Purpose: "Create one durable occurrence per schedule revision and due time.", RequiredOperations: []string{"admit_occurrence", "claim_due", "record_misfire"}, ProductionDurabilityRequired: true},
			{ID: "route_registry", Purpose: "Resolve and atomically advance topology-neutral service routes and generations.", RequiredOperations: []string{"resolve", "compare_and_swap_generation", "record_migration"}, ProductionDurabilityRequired: true},
			{ID: "capability_provider", Purpose: "Advertise contract versions and capabilities before readiness or lease acquisition.", RequiredOperations: []string{"manifest", "decide_compatibility"}},
			{ID: "clock", Purpose: "Provide testable lease, visibility, drain, and retention deadlines.", RequiredOperations: []string{"now"}},
			{ID: "secret_resolver", Purpose: "Resolve scoped secret references without placing secret values in portable records.", RequiredOperations: []string{"resolve_reference"}},
		},
		Records: []RecordContract{
			{Kind: "LifecycleEvent", SchemaVersion: AgentServiceLifecycleSchemaVersion, SchemaRef: "agent-service-lifecycle.schema.json", IdentityFields: []string{"scope.subject_id", "sequence", "event_id"}, FencingFields: []string{"deployment.generation", "lease.fencing_token"}},
			{Kind: "AgentServiceBinding", SchemaVersion: "agent-service-binding/v1", SchemaRef: "#/$defs/AgentServiceBindingV1", IdentityFields: []string{"tenant_id", "binding_id"}, FencingFields: []string{"route_generation", "installation_generation"}},
			{Kind: "DeploymentGeneration", SchemaVersion: "deployment-generation/v1", SchemaRef: "#/$defs/DeploymentGenerationV1", IdentityFields: []string{"service_id", "generation"}, FencingFields: []string{"generation", "fencing_token"}},
			{Kind: "CapabilityManifest", SchemaVersion: "capability-manifest/v1", SchemaRef: "#/$defs/CapabilityManifestV1", IdentityFields: []string{"service_id", "generation", "digest"}, FencingFields: []string{"generation"}},
			{Kind: "RunReceipt", SchemaVersion: "run-receipt/v1", SchemaRef: "#/$defs/RunReceiptV1", IdentityFields: []string{"tenant_id", "run_id", "revision"}, FencingFields: []string{"revision"}},
			{Kind: "ScheduledOccurrence", SchemaVersion: "scheduled-occurrence/v1", SchemaRef: "#/$defs/ScheduledOccurrenceV1", IdentityFields: []string{"schedule_id", "due_at", "schedule_revision"}, FencingFields: []string{"generation", "lease_token"}},
			{Kind: "WorkLease", SchemaVersion: "work-lease/v1", SchemaRef: "#/$defs/WorkLeaseV1", IdentityFields: []string{"run_id", "lease_token"}, FencingFields: []string{"generation", "lease_token", "fencing_token"}},
			{Kind: "Checkpoint", SchemaVersion: "checkpoint/v1", SchemaRef: "#/$defs/CheckpointV1", IdentityFields: []string{"run_id", "sequence"}, FencingFields: []string{"run_revision", "generation"}},
			{Kind: "EffectReceipt", SchemaVersion: "effect-receipt/v1", SchemaRef: "#/$defs/EffectReceiptV1", IdentityFields: []string{"run_id", "idempotency_key"}, FencingFields: []string{}},
			{Kind: "DeliveryReceipt", SchemaVersion: "delivery-receipt/v1", SchemaRef: "#/$defs/DeliveryReceiptV1", IdentityFields: []string{"run_id", "delivery_id"}, FencingFields: []string{}},
			{Kind: "PresenceSnapshot", SchemaVersion: "presence-snapshot/v1", SchemaRef: "#/$defs/PresenceSnapshotV1", IdentityFields: []string{"binding_id", "route_generation"}, FencingFields: []string{"route_generation", "active_generation"}},
			{Kind: "ReleaseReceipt", SchemaVersion: "release-receipt/v2", SchemaRef: "#/$defs/ReleaseReceiptV2", IdentityFields: []string{"service_id", "release_id"}, FencingFields: []string{"generation"}},
			{Kind: "MigrationReceipt", SchemaVersion: "migration-receipt/v1", SchemaRef: "#/$defs/MigrationReceiptV1", IdentityFields: []string{"binding_id", "migration_id"}, FencingFields: []string{"source_generation", "target_generation", "route_generation"}},
		},
		HealthSurfaces: []HealthSurface{
			{Path: "/livez", Responsibility: "process liveness", SuccessCondition: "the process can serve a probe"},
			{Path: "/readyz", Responsibility: "assigned traffic readiness", SuccessCondition: "the component can accept its assigned responsibility"},
			{Path: "/presencez", Responsibility: "admission and delivery readiness", SuccessCondition: "the service binding can durably admit work and reconcile delivery"},
			{Path: "/capabilities", Responsibility: "capability compatibility", SuccessCondition: "available and unavailable capabilities include contract versions"},
			{Path: "/drainz", Responsibility: "bounded drain progress", SuccessCondition: "the generation reports active leases, queued checkpoints, and its drain deadline"},
		},
		Invariants: lifecycleInvariants(),
		LegacyAdapters: []LegacyAdapter{
			{ID: "release-receipt/v1", TargetSchema: "release-receipt/v2", RetirementCondition: "All producers and consumers use portable generation, compatibility, continuity, and verification fields."},
		},
	}
}

func lifecycleTransitions() []StateTransition {
	return []StateTransition{
		{Machine: "installation", From: "authorizing", To: "binding", Condition: "authorization committed"},
		{Machine: "installation", From: "binding", To: "verifying", Condition: "stable binding committed"},
		{Machine: "installation", From: "verifying", To: "active", Condition: "identity, durable ports, delivery, and required capabilities verified"},
		{Machine: "installation", From: "active", To: "suspended", Condition: "authorization, policy, or delivery prevents safe operation"},
		{Machine: "installation", From: "suspended", To: "verifying", Condition: "the cause is repaired and verification restarts"},
		{Machine: "installation", From: "active", To: "revoked", Condition: "authorization is revoked"},
		{Machine: "installation", From: "revoked", To: "verifying", Condition: "authorization is restored or rebound"},
		{Machine: "installation", From: "active", To: "retired", Condition: "retirement policy completed"},
		{Machine: "installation", From: "suspended", To: "retired", Condition: "retirement policy completed"},
		{Machine: "installation", From: "revoked", To: "retired", Condition: "retirement policy completed"},
		{Machine: "deployment", From: "proposed", To: "provisioning", Condition: "the reviewed plan is accepted"},
		{Machine: "deployment", From: "provisioning", To: "validating", Condition: "the generation can run compatibility and continuity probes"},
		{Machine: "deployment", From: "validating", To: "active", Condition: "readiness, compatibility, continuity, and user-path checks pass"},
		{Machine: "deployment", From: "validating", To: "failed", Condition: "a required check fails"},
		{Machine: "deployment", From: "active", To: "rolled_back", Condition: "a prior active generation is restored"},
		{Machine: "deployment", From: "proposed", To: "superseded", Condition: "a newer reviewed proposal replaces it"},
		{Machine: "deployment", From: "active", To: "retired", Condition: "routes and leases are fenced and reconciliation is complete"},
		{Machine: "service", From: "booting", To: "warming", Condition: "process initialization completes"},
		{Machine: "service", From: "warming", To: "ready", Condition: "required durable ports and capabilities pass readiness"},
		{Machine: "service", From: "ready", To: "degraded", Condition: "bounded capability or capacity is unavailable"},
		{Machine: "service", From: "degraded", To: "ready", Condition: "required readiness recovers"},
		{Machine: "service", From: "ready", To: "draining", Condition: "planned handoff begins"},
		{Machine: "service", From: "degraded", To: "draining", Condition: "planned or forced handoff begins"},
		{Machine: "service", From: "draining", To: "offline", Condition: "leases finish or checkpoint and the generation is fenced"},
		{Machine: "service", From: "offline", To: "recovering", Condition: "a compatible generation begins reconciliation"},
		{Machine: "service", From: "recovering", To: "ready", Condition: "required reconciliation and readiness checks pass"},
		{Machine: "service", From: "recovering", To: "degraded", Condition: "bounded recovery remains while compatible work can run"},
		{Machine: "service", From: "draining", To: "stopped", Condition: "this service instance is fenced and intentionally stopped"},
		{Machine: "run", From: "received", To: "admitted", Condition: "durable receipt commits"},
		{Machine: "run", From: "received", To: "rejected", Condition: "durable admission cannot commit"},
		{Machine: "run", From: "admitted", To: "queued", Condition: "the run is available for compatible dispatch"},
		{Machine: "run", From: "queued", To: "leased", Condition: "one current generation acquires the lease"},
		{Machine: "run", From: "leased", To: "running", Condition: "the owner starts from the latest durable checkpoint"},
		{Machine: "run", From: "running", To: "waiting", Condition: "bounded human input or approval is required"},
		{Machine: "run", From: "waiting", To: "queued", Condition: "the required input or approval commits"},
		{Machine: "run", From: "running", To: "paused", Condition: "lease loss, drain, cancellation boundary, or dependency outage checkpoints execution"},
		{Machine: "run", From: "paused", To: "queued", Condition: "reconciliation makes the run recoverable"},
		{Machine: "run", From: "running", To: "delivering", Condition: "execution output and effects are durable"},
		{Machine: "run", From: "delivering", To: "completed", Condition: "all required delivery parts and completion receipts are durable"},
		{Machine: "run", From: "delivering", To: "paused", Condition: "delivery is unavailable and incomplete parts remain durable"},
		{Machine: "run", From: "queued", To: "cancelled", Condition: "cancellation commits before execution"},
		{Machine: "run", From: "waiting", To: "expired", Condition: "the bounded wait expires"},
		{Machine: "run", From: "paused", To: "blocked", Condition: "bounded recovery policy is exhausted"},
	}
}

func lifecycleInvariants() []LifecycleInvariant {
	statements := []string{
		"ack-after-admission: Transport acknowledgement is permitted only after a recoverable run receipt commits.",
		"dedupe-is-not-admission: Input deduplication cannot suppress recovery when no run receipt exists.",
		"one-current-lease: A run has at most one current lease generation.",
		"generation-fencing: A stale generation cannot execute an external effect or delivery.",
		"idempotent-effects: Every external write has an idempotency key and durable effect receipt.",
		"idempotent-delivery: Every delivery part has a stable identity and durable outbox state.",
		"durable-completion: A run is complete only after required effects and delivery receipts are durable.",
		"state-derived-status: User and operator status is derived from durable records and has an expiry watchdog.",
		"quiet-healthy-rollout: Normal scaling and healthy rolling replacement create no user-visible interruption.",
		"honest-rejection: A response cannot claim work was saved when admission did not commit.",
		"bounded-recovery: Schedules and goals define bounded catch-up, skip, and coalescing behavior.",
		"rolling-schema-window: A new generation reads the current and immediately previous state schema during replacement.",
		"expand-migrate-contract: State changes use expand, migrate, observe, and contract phases.",
		"bounded-retained-input: Recovery input is encrypted, bounded, and removed by binding retention policy.",
		"scoped-secrets: Workers receive scoped capability credentials rather than a universal credential bundle.",
		"host-owned-claims: Status, approval, and completion claims are host-owned rather than model-authored.",
		"topology-neutral-identity: Service, binding, run, and subject identity do not encode deployment topology.",
		"portable-public-contract: Public lifecycle records contain no environment-specific infrastructure details.",
	}
	result := make([]LifecycleInvariant, 0, len(statements))
	for index, statement := range statements {
		result = append(result, LifecycleInvariant{ID: lifecycleInvariantID(index), Statement: statement})
	}
	return result
}

func lifecycleInvariantID(index int) string {
	ids := [...]string{
		"ack-after-admission",
		"dedupe-is-not-admission",
		"one-current-lease",
		"generation-fencing",
		"idempotent-effects",
		"idempotent-delivery",
		"durable-completion",
		"state-derived-status",
		"quiet-healthy-rollout",
		"honest-rejection",
		"bounded-recovery",
		"rolling-schema-window",
		"expand-migrate-contract",
		"bounded-retained-input",
		"scoped-secrets",
		"host-owned-claims",
		"topology-neutral-identity",
		"portable-public-contract",
	}
	return ids[index]
}
