package runtimeresponse

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/ports"
)

type recordingRuntimeBlocklistStore struct {
	putEntries []ports.RuntimeBlocklistEntry
}

func (s *recordingRuntimeBlocklistStore) Ping(context.Context) error {
	return nil
}

func (s *recordingRuntimeBlocklistStore) PutRuntimeBlocklistEntry(_ context.Context, entry ports.RuntimeBlocklistEntry) (*ports.RuntimeBlocklistEntry, error) {
	s.putEntries = append(s.putEntries, entry)
	return &s.putEntries[len(s.putEntries)-1], nil
}

func (s *recordingRuntimeBlocklistStore) ListRuntimeBlocklistEntries(context.Context, ports.RuntimeBlocklistFilter) ([]*ports.RuntimeBlocklistEntry, error) {
	return nil, nil
}

func (s *recordingRuntimeBlocklistStore) RevokeRuntimeBlocklistEntry(context.Context, string, string) (*ports.RuntimeBlocklistEntry, error) {
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
