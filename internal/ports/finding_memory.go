package ports

import (
	"context"
	"time"
)

type FindingMemoryRecord struct {
	ID           string
	TenantID     string
	Type         string
	SourceURN    string
	FindingID    string
	RuleID       string
	Fingerprint  string
	Summary      string
	EvidenceRefs []string
	SubjectURNs  []string
	Embedding    []float64
	Confidence   float64
	ObservedAt   time.Time
	ExpiresAt    time.Time
	Metadata     map[string]string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type ListFindingMemoryRequest struct {
	TenantID   string
	Type       string
	FindingID  string
	SubjectURN string
	Limit      uint32
}

type SimilarFindingMemoryRequest struct {
	TenantID  string
	Type      string
	Embedding []float64
	Limit     uint32
}

type ScoredFindingMemoryRecord struct {
	Record *FindingMemoryRecord
	Score  float64
}

type FindingMemoryStore interface {
	StateStore
	UpsertFindingMemory(context.Context, *FindingMemoryRecord) (*FindingMemoryRecord, error)
	ListFindingMemory(context.Context, ListFindingMemoryRequest) ([]*FindingMemoryRecord, error)
	SimilarFindingMemory(context.Context, SimilarFindingMemoryRequest) ([]ScoredFindingMemoryRecord, error)
}
