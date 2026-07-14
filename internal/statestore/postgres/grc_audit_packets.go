package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/writer/cerebro/internal/ports"
)

var ensureGRCAuditPacketStatements = []string{`
CREATE TABLE IF NOT EXISTS grc_audit_packets (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  finding_id TEXT NOT NULL,
  digest TEXT NOT NULL,
  packet_json JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL
)`, `
CREATE INDEX IF NOT EXISTS grc_audit_packets_tenant_created_idx
ON grc_audit_packets (tenant_id, created_at DESC)`}

type grcAuditPacketExecer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

// insertGRCAuditPacket is called only by the audit event projector. It has no
// conflict-update path: a replay can rebuild a receipt but never rewrite it.
func insertGRCAuditPacket(ctx context.Context, execer grcAuditPacketExecer, receipt *ports.GRCAuditPacketReceipt) error {
	if receipt == nil {
		return errors.New("GRC audit packet receipt is required")
	}
	if strings.TrimSpace(receipt.ID) == "" || strings.TrimSpace(receipt.TenantID) == "" || strings.TrimSpace(receipt.FindingID) == "" || strings.TrimSpace(receipt.Digest) == "" || len(receipt.Payload) == 0 || receipt.CreatedAt.IsZero() {
		return errors.New("GRC audit packet receipt is incomplete")
	}
	if execer == nil {
		return errors.New("GRC audit packet projection store is required")
	}
	if _, err := execer.ExecContext(ctx, `
INSERT INTO grc_audit_packets (id, tenant_id, finding_id, digest, packet_json, created_at)
VALUES ($1, $2, $3, $4, $5::jsonb, $6)`, receipt.ID, receipt.TenantID, receipt.FindingID, receipt.Digest, string(receipt.Payload), receipt.CreatedAt.UTC()); err != nil {
		return fmt.Errorf("insert GRC audit packet %q: %w", receipt.ID, err)
	}
	return nil
}

// GetGRCAuditPacket loads one immutable packet receipt without resolving any
// current finding, evidence, runtime, or graph records.
func (s *Store) GetGRCAuditPacket(ctx context.Context, packetID string) (*ports.GRCAuditPacketReceipt, error) {
	id := strings.TrimSpace(packetID)
	if id == "" {
		return nil, errors.New("GRC audit packet id is required")
	}
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureGRCAuditPacketTable(ctx); err != nil {
		return nil, err
	}
	receipt := &ports.GRCAuditPacketReceipt{}
	var payload string
	if err := s.db.QueryRowContext(ctx, `
SELECT id, tenant_id, finding_id, digest, packet_json::text, created_at
FROM grc_audit_packets
WHERE id = $1`, id).Scan(&receipt.ID, &receipt.TenantID, &receipt.FindingID, &receipt.Digest, &payload, &receipt.CreatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: %s", ports.ErrGRCAuditPacketNotFound, id)
		}
		return nil, fmt.Errorf("query GRC audit packet %q: %w", id, err)
	}
	receipt.Payload = []byte(payload)
	return receipt, nil
}

func (s *Store) ensureGRCAuditPacketTable(ctx context.Context) error {
	return s.ensureStatements(ctx, &s.grc.auditPackets, "grc_audit_packets", ensureGRCAuditPacketStatements)
}
