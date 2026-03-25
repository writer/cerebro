package postgres

import (
	"testing"
)

func TestNewFindingRepository(t *testing.T) {
	client := NewPostgresClient(nil, "raw", "cerebro")
	repo := NewFindingRepository(client)
	if repo == nil {
		t.Fatal("NewFindingRepository returned nil")
	}
	if repo.schema != "cerebro" {
		t.Errorf("schema = %q, want %q", repo.schema, "cerebro")
	}
}

func TestNewTicketRepository(t *testing.T) {
	client := NewPostgresClient(nil, "raw", "cerebro")
	repo := NewTicketRepository(client)
	if repo == nil {
		t.Fatal("NewTicketRepository returned nil")
	}
	if repo.schema != "cerebro" {
		t.Errorf("schema = %q, want %q", repo.schema, "cerebro")
	}
}

func TestNewAuditRepository(t *testing.T) {
	client := NewPostgresClient(nil, "raw", "cerebro")
	repo := NewAuditRepository(client)
	if repo == nil {
		t.Fatal("NewAuditRepository returned nil")
	}
	if repo.schema != "cerebro" {
		t.Errorf("schema = %q, want %q", repo.schema, "cerebro")
	}
}

func TestNewPolicyHistoryRepository(t *testing.T) {
	client := NewPostgresClient(nil, "raw", "cerebro")
	repo := NewPolicyHistoryRepository(client)
	if repo == nil {
		t.Fatal("NewPolicyHistoryRepository returned nil")
	}
	if repo.schema != "cerebro" {
		t.Errorf("schema = %q, want %q", repo.schema, "cerebro")
	}
}

func TestNewRiskEngineStateRepository(t *testing.T) {
	client := NewPostgresClient(nil, "raw", "cerebro")
	repo := NewRiskEngineStateRepository(client)
	if repo == nil {
		t.Fatal("NewRiskEngineStateRepository returned nil")
	}
	if repo.schema != "cerebro" {
		t.Errorf("schema = %q, want %q", repo.schema, "cerebro")
	}
}

func TestNewRetentionRepository(t *testing.T) {
	client := NewPostgresClient(nil, "raw", "cerebro")
	repo := NewRetentionRepository(client)
	if repo == nil {
		t.Fatal("NewRetentionRepository returned nil")
	}
	if repo.schema != "cerebro" {
		t.Errorf("schema = %q, want %q", repo.schema, "cerebro")
	}
}

func TestPolicyHistoryUpsertValidation(t *testing.T) {
	client := NewPostgresClient(nil, "raw", "cerebro")
	repo := NewPolicyHistoryRepository(client)

	// nil record
	if err := repo.Upsert(nil, nil); err == nil {
		t.Error("expected error for nil record")
	}

	// empty policy ID
	if err := repo.Upsert(nil, &PolicyHistoryRecord{PolicyID: "", Version: 1}); err == nil {
		t.Error("expected error for empty policy ID")
	}

	// zero version
	if err := repo.Upsert(nil, &PolicyHistoryRecord{PolicyID: "p1", Version: 0}); err == nil {
		t.Error("expected error for zero version")
	}
}

func TestNormalizeJSONB(t *testing.T) {
	tests := []struct {
		name  string
		input interface{}
		want  string
		isNil bool
	}{
		{"nil", nil, "", true},
		{"empty bytes", []byte(""), "", true},
		{"whitespace bytes", []byte("  "), "", true},
		{"valid bytes", []byte(`{"key":"val"}`), `{"key":"val"}`, false},
		{"empty string", "", "", true},
		{"valid string", `{"key":"val"}`, `{"key":"val"}`, false},
		{"integer", 42, "42", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeJSONB(tt.input)
			if tt.isNil {
				if got != nil {
					t.Errorf("normalizeJSONB(%v) = %q, want nil", tt.input, got)
				}
			} else {
				if string(got) != tt.want {
					t.Errorf("normalizeJSONB(%v) = %q, want %q", tt.input, got, tt.want)
				}
			}
		})
	}
}

func TestRetentionDeleteBeforeValidation(t *testing.T) {
	// nil repository
	var r *RetentionRepository
	_, err := r.deleteBefore(nil, "audit_log", "timestamp", fixedTime())
	if err == nil {
		t.Error("expected error for nil repository")
	}
}
