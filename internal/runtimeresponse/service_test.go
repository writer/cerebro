package runtimeresponse

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/ports"
)

type recordingRuntimeBlocklistStore struct {
	putEntries   []ports.RuntimeBlocklistEntry
	listFilters  []ports.RuntimeBlocklistFilter
	listEntries  []*ports.RuntimeBlocklistEntry
	revokeTenant string
	revokeID     string
	revokedEntry *ports.RuntimeBlocklistEntry
	revokeErr    error
}

func (s *recordingRuntimeBlocklistStore) Ping(context.Context) error {
	return nil
}

func (s *recordingRuntimeBlocklistStore) PutRuntimeBlocklistEntry(_ context.Context, entry ports.RuntimeBlocklistEntry) (*ports.RuntimeBlocklistEntry, error) {
	s.putEntries = append(s.putEntries, entry)
	return &s.putEntries[len(s.putEntries)-1], nil
}

func (s *recordingRuntimeBlocklistStore) ListRuntimeBlocklistEntries(_ context.Context, filter ports.RuntimeBlocklistFilter) ([]*ports.RuntimeBlocklistEntry, error) {
	s.listFilters = append(s.listFilters, filter)
	return s.listEntries, nil
}

func (s *recordingRuntimeBlocklistStore) RevokeRuntimeBlocklistEntry(_ context.Context, tenantID string, id string) (*ports.RuntimeBlocklistEntry, error) {
	s.revokeTenant = tenantID
	s.revokeID = id
	if s.revokeErr != nil {
		return nil, s.revokeErr
	}
	if s.revokedEntry != nil {
		return s.revokedEntry, nil
	}
	return nil, ports.ErrRuntimeBlocklistEntryNotFound
}

func TestExecuteRequiresTrustedScopeBeforeMutation(t *testing.T) {
	store := &recordingRuntimeBlocklistStore{}
	service := New(store)

	_, err := service.Execute(context.Background(), ExecuteRequest{
		TenantID: "writer",
		Action:   ActionBlockIP,
		Target:   "192.0.2.1",
	})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Execute() error = %v, want ErrInvalidRequest", err)
	}
	if len(store.putEntries) != 0 {
		t.Fatalf("Execute() wrote %d blocklist entries without trusted scope", len(store.putEntries))
	}
}

func TestExecutePersistsTrustedIPBlock(t *testing.T) {
	store := &recordingRuntimeBlocklistStore{}
	service := New(store)

	entry, err := service.Execute(context.Background(), ExecuteRequest{
		TenantID:     " writer ",
		Action:       " " + ActionBlockIP + " ",
		Target:       " 192.0.2.1 ",
		Reason:       " suspicious traffic ",
		Source:       " finding ",
		SourceJobID:  " job-1 ",
		TrustedScope: true,
		Attributes:   map[string]string{"rule_id": "rule-1"},
	})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if len(store.putEntries) != 1 {
		t.Fatalf("PutRuntimeBlocklistEntry calls = %d, want 1", len(store.putEntries))
	}
	if entry.ID == "" || !strings.HasPrefix(entry.ID, "rr-") {
		t.Fatalf("entry ID = %q, want rr-*", entry.ID)
	}
	if entry.TenantID != "writer" || entry.Type != "ip" || entry.Value != "192.0.2.1" {
		t.Fatalf("entry = %#v, want normalized writer ip 192.0.2.1", entry)
	}
	if entry.Reason != "suspicious traffic" || entry.Source != "finding" || entry.SourceJobID != "job-1" {
		t.Fatalf("entry metadata was not trimmed: %#v", entry)
	}
}

func TestExecutePersistsTrustedDomainBlock(t *testing.T) {
	store := &recordingRuntimeBlocklistStore{}
	service := New(store)

	entry, err := service.Execute(context.Background(), ExecuteRequest{
		TenantID:     "writer",
		Action:       ActionBlockDomain,
		Target:       " Example.COM. ",
		TrustedScope: true,
	})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if entry.Type != "domain" || entry.Value != "example.com" {
		t.Fatalf("entry = %#v, want normalized domain example.com", entry)
	}
}

func TestExecuteRejectsInvalidRequestsBeforeMutation(t *testing.T) {
	tests := []struct {
		name    string
		request ExecuteRequest
		wantErr error
	}{
		{
			name: "missing tenant",
			request: ExecuteRequest{
				Action:       ActionBlockIP,
				Target:       "192.0.2.1",
				TrustedScope: true,
			},
			wantErr: ErrInvalidRequest,
		},
		{
			name: "missing target",
			request: ExecuteRequest{
				TenantID:     "writer",
				Action:       ActionBlockIP,
				TrustedScope: true,
			},
			wantErr: ErrInvalidRequest,
		},
		{
			name: "invalid ip",
			request: ExecuteRequest{
				TenantID:     "writer",
				Action:       ActionBlockIP,
				Target:       "not-an-ip",
				TrustedScope: true,
			},
			wantErr: ErrInvalidRequest,
		},
		{
			name: "invalid domain",
			request: ExecuteRequest{
				TenantID:     "writer",
				Action:       ActionBlockDomain,
				Target:       "example..com",
				TrustedScope: true,
			},
			wantErr: ErrInvalidRequest,
		},
		{
			name: "unsupported action",
			request: ExecuteRequest{
				TenantID:     "writer",
				Action:       "scale_down",
				Target:       "runtime-1",
				TrustedScope: true,
			},
			wantErr: ErrUnsupportedAction,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &recordingRuntimeBlocklistStore{}
			service := New(store)
			_, err := service.Execute(context.Background(), tt.request)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Execute() error = %v, want %v", err, tt.wantErr)
			}
			if len(store.putEntries) != 0 {
				t.Fatalf("Execute() wrote %d blocklist entries for invalid request", len(store.putEntries))
			}
		})
	}
}

func TestCapabilitiesRequireTrustedScope(t *testing.T) {
	capabilities := New(&recordingRuntimeBlocklistStore{}).Capabilities()
	if len(capabilities) == 0 {
		t.Fatal("Capabilities() returned no capabilities")
	}
	for _, capability := range capabilities {
		if !capability.RequiresScope {
			t.Fatalf("capability %s does not require trusted scope", capability.Action)
		}
	}
}

func TestListDelegatesFilterToStore(t *testing.T) {
	entry := &ports.RuntimeBlocklistEntry{ID: "rr-1", TenantID: "writer", Type: "ip", Value: "192.0.2.1"}
	store := &recordingRuntimeBlocklistStore{listEntries: []*ports.RuntimeBlocklistEntry{entry}}
	service := New(store)

	got, err := service.List(context.Background(), ports.RuntimeBlocklistFilter{
		TenantID:       "writer",
		Type:           "ip",
		IncludeRevoked: true,
		Limit:          25,
	})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(got) != 1 || got[0] != entry {
		t.Fatalf("List() entries = %#v, want stored entry", got)
	}
	if len(store.listFilters) != 1 {
		t.Fatalf("ListRuntimeBlocklistEntries calls = %d, want 1", len(store.listFilters))
	}
	filter := store.listFilters[0]
	if filter.TenantID != "writer" || filter.Type != "ip" || !filter.IncludeRevoked || filter.Limit != 25 {
		t.Fatalf("List() filter = %#v", filter)
	}
}

func TestRevokeDelegatesTenantAndIDToStore(t *testing.T) {
	revoked := &ports.RuntimeBlocklistEntry{ID: "rr-1", TenantID: "writer", Type: "domain", Value: "example.com"}
	store := &recordingRuntimeBlocklistStore{revokedEntry: revoked}
	service := New(store)

	got, err := service.Revoke(context.Background(), "writer", "rr-1")
	if err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	if got != revoked {
		t.Fatalf("Revoke() entry = %#v, want revoked entry", got)
	}
	if store.revokeTenant != "writer" || store.revokeID != "rr-1" {
		t.Fatalf("RevokeRuntimeBlocklistEntry called with tenant=%q id=%q", store.revokeTenant, store.revokeID)
	}
}

func TestListAndRevokeRequireStore(t *testing.T) {
	service := New(nil)
	if _, err := service.List(context.Background(), ports.RuntimeBlocklistFilter{}); !errors.Is(err, ErrRuntimeUnavailable) {
		t.Fatalf("List(nil store) error = %v, want ErrRuntimeUnavailable", err)
	}
	if _, err := service.Revoke(context.Background(), "writer", "rr-1"); !errors.Is(err, ErrRuntimeUnavailable) {
		t.Fatalf("Revoke(nil store) error = %v, want ErrRuntimeUnavailable", err)
	}
}
