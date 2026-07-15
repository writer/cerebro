package ports

import (
	"context"
	"errors"
	"time"
)

var (
	ErrDecisionPacketNotFound  = errors.New("decision packet receipt not found")
	ErrDecisionPacketImmutable = errors.New("decision packet receipt is immutable")
)

type DecisionPacketReceipt struct {
	TenantID       string
	PacketID       string
	SchemaVersion  string
	Workflow       string
	ScopeURN       string
	DecisionState  string
	Confidence     string
	PacketDigest   string
	EvidenceDigest string
	CoverageDigest string
	PacketJSON     []byte
	CreatedAt      time.Time
	ExpiresAt      *time.Time
}

type DecisionPacketReceiptStore interface {
	PutDecisionPacketReceipt(context.Context, *DecisionPacketReceipt) error
	GetDecisionPacketReceipt(context.Context, string, string) (*DecisionPacketReceipt, error)
}
