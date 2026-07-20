package agentplatform

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestAgentServiceLifecycleConformsToPublicSchema(t *testing.T) {
	schemaPayload, err := os.ReadFile("../../schemas/agent-service-lifecycle-contract.schema.json")
	if err != nil {
		t.Fatalf("read lifecycle schema: %v", err)
	}
	var schemaDocument any
	if err := json.Unmarshal(schemaPayload, &schemaDocument); err != nil {
		t.Fatalf("decode lifecycle schema: %v", err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	if err := compiler.AddResource("agent-service-lifecycle-contract.schema.json", schemaDocument); err != nil {
		t.Fatalf("add lifecycle schema: %v", err)
	}
	compiled, err := compiler.Compile("agent-service-lifecycle-contract.schema.json")
	if err != nil {
		t.Fatalf("compile lifecycle schema: %v", err)
	}
	payload, err := json.Marshal(AgentServiceLifecycle())
	if err != nil {
		t.Fatalf("marshal lifecycle contract: %v", err)
	}
	var instance any
	if err := json.Unmarshal(payload, &instance); err != nil {
		t.Fatalf("decode lifecycle contract: %v", err)
	}
	if err := compiled.Validate(instance); err != nil {
		t.Fatalf("lifecycle contract does not conform: %v", err)
	}
}

func TestAgentServiceLifecycleDefinesContinuityRecordsAndPorts(t *testing.T) {
	contract := AgentServiceLifecycle()
	if contract.SchemaVersion != AgentServiceLifecycleSchemaVersion || contract.ContractVersion != AgentServiceLifecycleContractVersion {
		t.Fatalf("lifecycle versions = %q %q", contract.SchemaVersion, contract.ContractVersion)
	}
	for _, portID := range []string{"lifecycle_event_log", "admission_store", "run_queue", "lease_store", "checkpoint_store", "effect_store", "delivery_outbox", "schedule_store", "route_registry", "capability_provider", "clock", "secret_resolver"} {
		if !hasLifecyclePort(contract, portID) {
			t.Fatalf("lifecycle contract missing port %q", portID)
		}
	}
	for _, kind := range []string{"LifecycleEvent", "AgentServiceBinding", "DeploymentGeneration", "CapabilityManifest", "RunReceipt", "ScheduledOccurrence", "WorkLease", "Checkpoint", "EffectReceipt", "DeliveryReceipt", "PresenceSnapshot", "ReleaseReceipt", "MigrationReceipt"} {
		if !hasLifecycleRecord(contract, kind) {
			t.Fatalf("lifecycle contract missing record %q", kind)
		}
	}
	if len(contract.Compatibility.ReadVersions) != 1 || len(contract.Compatibility.WriteVersions) != 1 {
		t.Fatalf("compatibility window = %+v", contract.Compatibility)
	}
}

func TestAgentServiceLifecycleTransitionsReferenceDeclaredStates(t *testing.T) {
	contract := AgentServiceLifecycle()
	states := map[string]map[string]bool{
		"installation": {},
		"deployment":   {},
		"service":      {},
		"run":          {},
	}
	for _, value := range contract.InstallationStates {
		states["installation"][string(value.State)] = true
	}
	for _, value := range contract.DeploymentStates {
		states["deployment"][string(value.State)] = true
	}
	for _, value := range contract.ServiceStates {
		states["service"][string(value.State)] = true
	}
	for _, value := range contract.RunStates {
		states["run"][string(value.State)] = true
	}
	for _, transition := range contract.Transitions {
		declared, ok := states[transition.Machine]
		if !ok {
			t.Fatalf("transition references unknown machine %q", transition.Machine)
		}
		if !declared[transition.From] || !declared[transition.To] {
			t.Fatalf("transition references undeclared state: %+v", transition)
		}
	}
	for _, terminal := range []string{"rejected", "completed", "cancelled", "expired", "blocked"} {
		if !runStateIsTerminal(contract, terminal) {
			t.Fatalf("run state %q must be terminal", terminal)
		}
	}
}

func TestAgentServiceLifecycleSchemaRejectsCrossMachineTransition(t *testing.T) {
	contract := AgentServiceLifecycle()
	for index := range contract.Transitions {
		if contract.Transitions[index].Machine == "service" {
			contract.Transitions[index].From = "running"
			break
		}
	}
	if err := validateLifecycleContractValue(t, "", contract); err == nil {
		t.Fatal("lifecycle contract accepted a run state in a service transition")
	}
}

func TestLifecycleRecordSchemasEnforceCrashRecoveryFields(t *testing.T) {
	baseTime := "2026-07-16T16:00:00Z"
	run := map[string]any{
		"schema_version": "run-receipt/v1", "receipt_id": "receipt-1", "tenant_id": "tenant-1", "binding_id": "binding-1", "run_id": "run-1",
		"run_kind": "interactive", "subject_ref": "subject:1", "input_digest": "digest", "idempotency_key": "run-1", "state": "received", "revision": 1,
		"required_capabilities": []any{}, "retention_policy_ref": "retention:default", "received_at": baseTime, "admitted_at": baseTime, "updated_at": baseTime,
	}
	if err := validateLifecycleContractValue(t, "RunReceiptV1", run); err == nil {
		t.Fatal("RunReceiptV1 accepted a pre-admission state")
	}

	occurrence := map[string]any{
		"schema_version": "scheduled-occurrence/v1", "occurrence_id": "occurrence-1", "schedule_id": "schedule-1", "schedule_revision": 1,
		"due_at": baseTime, "run_id": "run-1", "idempotency_key": "schedule-1:1", "misfire_policy": "coalesce_once", "state": "leased",
		"generation": 1, "lease_token": "lease-1", "created_at": baseTime, "updated_at": baseTime,
	}
	if err := validateLifecycleContractValue(t, "ScheduledOccurrenceV1", occurrence); err == nil {
		t.Fatal("ScheduledOccurrenceV1 accepted a leased occurrence without owner, fencing, and expiry fields")
	}

	effect := map[string]any{
		"schema_version": "effect-receipt/v1", "effect_id": "effect-1", "run_id": "run-1", "step_id": "step-1", "generation": 1,
		"lease_token": "lease-1", "fencing_token": 1, "idempotency_key": "effect-1", "target_ref": "target:1", "request_digest": "digest",
		"state": "executing", "approval_required": false, "verification_state": "pending", "recorded_at": baseTime,
	}
	if err := validateLifecycleContractValue(t, "EffectReceiptV1", effect); err != nil {
		t.Fatalf("EffectReceiptV1 rejected an executing effect without a result: %v", err)
	}
	effect["state"] = "succeeded"
	if err := validateLifecycleContractValue(t, "EffectReceiptV1", effect); err == nil {
		t.Fatal("EffectReceiptV1 accepted a succeeded effect without result fields")
	}

	part := map[string]any{
		"part_id": "part-1", "sequence": 1, "idempotency_key": "delivery-1:part-1", "payload_ref": "payload:1", "payload_digest": "digest", "state": "pending",
	}
	if err := validateLifecycleContractValue(t, "DeliveryPartV1", part); err != nil {
		t.Fatalf("DeliveryPartV1 rejected a pending part without a destination receipt: %v", err)
	}
	part["state"] = "delivered"
	if err := validateLifecycleContractValue(t, "DeliveryPartV1", part); err == nil {
		t.Fatal("DeliveryPartV1 accepted a delivered part without a destination receipt")
	}
}

func TestAgentServiceLifecycleSnapshotIsDefensivelyBuilt(t *testing.T) {
	first := AgentServiceLifecycle()
	first.Compatibility.ReadVersions[0] = "mutated"
	first.Ports[0].RequiredOperations[0] = "mutated"
	first.Records[0].IdentityFields[0] = "mutated"
	first.Invariants[0].Statement = "mutated"
	second := AgentServiceLifecycle()
	if second.Compatibility.ReadVersions[0] == "mutated" || second.Ports[0].RequiredOperations[0] == "mutated" || second.Records[0].IdentityFields[0] == "mutated" || second.Invariants[0].Statement == "mutated" {
		t.Fatalf("lifecycle snapshot shares mutable state: %+v", second)
	}
}

func TestAgentServiceLifecycleSchemaIsTransportAndTopologyNeutral(t *testing.T) {
	payload, err := os.ReadFile("../../schemas/agent-service-lifecycle-contract.schema.json")
	if err != nil {
		t.Fatalf("read lifecycle schema: %v", err)
	}
	lower := bytes.ToLower(payload)
	for _, forbidden := range []string{"slack", "socket mode", "kubernetes", "cloud account", "private dns"} {
		if bytes.Contains(lower, []byte(forbidden)) {
			t.Fatalf("public lifecycle schema contains transport or topology term %q", forbidden)
		}
	}
	if !strings.Contains(string(payload), "topology") {
		t.Fatal("public lifecycle schema must state its topology-neutral boundary")
	}
}

func hasLifecyclePort(contract AgentServiceLifecycleContract, id string) bool {
	for _, port := range contract.Ports {
		if port.ID == id && len(port.RequiredOperations) > 0 {
			return true
		}
	}
	return false
}

func hasLifecycleRecord(contract AgentServiceLifecycleContract, kind string) bool {
	for _, record := range contract.Records {
		if record.Kind == kind && record.SchemaVersion != "" && record.SchemaRef != "" && len(record.IdentityFields) > 0 {
			return true
		}
	}
	return false
}

func runStateIsTerminal(contract AgentServiceLifecycleContract, state string) bool {
	for _, candidate := range contract.RunStates {
		if string(candidate.State) == state {
			return candidate.Terminal
		}
	}
	return false
}

func validateLifecycleContractValue(t *testing.T, definition string, value any) error {
	t.Helper()
	payload, err := os.ReadFile("../../schemas/agent-service-lifecycle-contract.schema.json")
	if err != nil {
		t.Fatalf("read lifecycle contract schema: %v", err)
	}
	var document any
	if err := json.Unmarshal(payload, &document); err != nil {
		t.Fatalf("decode lifecycle contract schema: %v", err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	if err := compiler.AddResource("agent-service-lifecycle-contract.schema.json", document); err != nil {
		t.Fatalf("add lifecycle contract schema: %v", err)
	}
	location := "agent-service-lifecycle-contract.schema.json"
	if definition != "" {
		location += "#/$defs/" + definition
	}
	compiled, err := compiler.Compile(location)
	if err != nil {
		t.Fatalf("compile lifecycle contract schema %s: %v", definition, err)
	}
	payload, err = json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal lifecycle value: %v", err)
	}
	var instance any
	if err := json.Unmarshal(payload, &instance); err != nil {
		t.Fatalf("decode lifecycle value: %v", err)
	}
	return compiled.Validate(instance)
}
