package graphactions

import (
	"reflect"
	"testing"
)

func TestKnownActionContractHelpersExposeCatalogMetadata(t *testing.T) {
	if got, want := KnownActionIDs(), []string{
		ActionIdentityOktaSuspendUser,
		ActionIdentityOktaUnsuspendUser,
		ActionEndpointCerebroRevokeDevice,
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("KnownActionIDs() = %#v, want %#v", got, want)
	}
	if got, want := KnownProviderIDs(), []string{
		ProviderAccessApprovals,
		ProviderCerebroDeviceAuth,
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("KnownProviderIDs() = %#v, want %#v", got, want)
	}
	if got, want := KnownTargetKinds(), []string{
		TargetKindCerebroDevice,
		TargetKindOktaUser,
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("KnownTargetKinds() = %#v, want %#v", got, want)
	}

	metadata := KnownActionMetadata()
	if len(metadata) != len(KnownActionSpecs()) {
		t.Fatalf("KnownActionMetadata() len = %d, want %d", len(metadata), len(KnownActionSpecs()))
	}
	byID := map[string]ActionMetadata{}
	for _, action := range metadata {
		byID[action.ID] = action
	}
	for _, spec := range KnownActionSpecs() {
		if got, want := byID[spec.ID], spec.Metadata(); got != want {
			t.Fatalf("metadata for %q = %#v, want %#v", spec.ID, got, want)
		}
	}
	device := byID[ActionEndpointCerebroRevokeDevice]
	if device.Provider != ProviderCerebroDeviceAuth || device.TargetKind != TargetKindCerebroDevice || !device.Destructive {
		t.Fatalf("device action metadata = %#v, want first-party destructive device action", device)
	}
}

func TestKnownActionContractHelpersReturnCopies(t *testing.T) {
	ids := KnownActionIDs()
	ids[0] = "mutated"
	if got := KnownActionIDs()[0]; got == "mutated" {
		t.Fatalf("KnownActionIDs() returned mutable backing storage")
	}
	providers := KnownProviderIDs()
	providers[0] = "mutated"
	if got := KnownProviderIDs()[0]; got == "mutated" {
		t.Fatalf("KnownProviderIDs() returned mutable backing storage")
	}
	targetKinds := KnownTargetKinds()
	targetKinds[0] = "mutated"
	if got := KnownTargetKinds()[0]; got == "mutated" {
		t.Fatalf("KnownTargetKinds() returned mutable backing storage")
	}
	metadata := KnownActionMetadata()
	metadata[0].ID = "mutated"
	if got := KnownActionMetadata()[0].ID; got == "mutated" {
		t.Fatalf("KnownActionMetadata() returned mutable backing storage")
	}
}

func TestActionMetadataContractDoesNotExposeExecutableHooks(t *testing.T) {
	typ := reflect.TypeOf(ActionMetadata{})
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if field.Type.Kind() == reflect.Func {
			t.Fatalf("ActionMetadata field %s exposes a function", field.Name)
		}
	}
}

func TestActionStatusContract(t *testing.T) {
	if got, want := KnownActionStatuses(), []string{
		ActionStatusPending,
		ActionStatusQueued,
		ActionStatusRunning,
		ActionStatusSucceeded,
		ActionStatusFailed,
		ActionStatusCancelled,
		ActionStatusNeedsAttention,
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("KnownActionStatuses() = %#v, want %#v", got, want)
	}
	statuses := KnownActionStatuses()
	statuses[0] = "mutated"
	if got := KnownActionStatuses()[0]; got == "mutated" {
		t.Fatalf("KnownActionStatuses() returned mutable backing storage")
	}

	for _, status := range []string{
		" " + ActionStatusPending + " ",
		ActionStatusQueued,
		"RUNNING",
		ActionStatusSucceeded,
		ActionStatusFailed,
		ActionStatusCancelled,
		ActionStatusNeedsAttention,
	} {
		if !ActionStatusKnown(status) {
			t.Fatalf("ActionStatusKnown(%q) = false, want true", status)
		}
	}
	for _, status := range []string{
		ActionStatusSucceeded,
		ActionStatusFailed,
		ActionStatusCancelled,
		ActionStatusNeedsAttention,
	} {
		if !ActionStatusTerminal(status) {
			t.Fatalf("ActionStatusTerminal(%q) = false, want true", status)
		}
	}
	for _, status := range []string{ActionStatusPending, ActionStatusQueued, ActionStatusRunning} {
		if ActionStatusTerminal(status) {
			t.Fatalf("ActionStatusTerminal(%q) = true, want false", status)
		}
	}
	if ActionStatusKnown("unknown") {
		t.Fatalf("ActionStatusKnown(unknown) = true, want false")
	}
}
