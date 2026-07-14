package ports

import (
	"context"
	"errors"
	"time"
)

// ErrGRCAuditPacketNotFound indicates that an immutable audit packet does not exist.
var ErrGRCAuditPacketNotFound = errors.New("GRC audit packet not found")

// GRCAuditPacketReceipt is the state-store envelope for one immutable packet.
// Payload contains the complete, versioned packet response. Readers must
// authorize TenantID before decoding or returning Payload.
type GRCAuditPacketReceipt struct {
	ID        string
	TenantID  string
	FindingID string
	Digest    string
	Payload   []byte
	CreatedAt time.Time
}

// GRCAuditPacketStore owns immutable audit packet receipts in current state.
type GRCAuditPacketStore interface {
	StateStore
	PutGRCAuditPacket(context.Context, *GRCAuditPacketReceipt) error
	GetGRCAuditPacket(context.Context, string) (*GRCAuditPacketReceipt, error)
}
