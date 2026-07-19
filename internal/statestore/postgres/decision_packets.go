package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/writer/cerebro/internal/ports"
)

var ensureDecisionPacketStatements = []string{`
CREATE TABLE IF NOT EXISTS decision_packet_receipts (
  tenant_id TEXT NOT NULL,
  packet_id TEXT NOT NULL,
  schema_version TEXT NOT NULL,
  workflow TEXT NOT NULL,
  scope_urn TEXT NOT NULL DEFAULT '',
  decision_state TEXT NOT NULL,
  confidence_level TEXT NOT NULL,
  packet_digest TEXT NOT NULL,
  evidence_digest TEXT NOT NULL,
  coverage_digest TEXT NOT NULL,
  packet_json JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  expires_at TIMESTAMPTZ,
  PRIMARY KEY (tenant_id, packet_id)
)`, `
CREATE INDEX IF NOT EXISTS decision_packet_receipts_expiry_idx
ON decision_packet_receipts (tenant_id, expires_at)
WHERE expires_at IS NOT NULL`}

func (s *Store) PutDecisionPacketReceipt(ctx context.Context, receipt *ports.DecisionPacketReceipt) error {
	if err := validateDecisionPacketReceipt(receipt); err != nil {
		return err
	}
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	if err := s.ensureDecisionPacketTable(ctx); err != nil {
		return err
	}
	var expiresAt any
	if receipt.ExpiresAt != nil {
		expiresAt = receipt.ExpiresAt.UTC()
	}
	result, err := s.db.ExecContext(ctx, `
INSERT INTO decision_packet_receipts (
  tenant_id, packet_id, schema_version, workflow, scope_urn, decision_state,
  confidence_level, packet_digest, evidence_digest, coverage_digest,
  packet_json, created_at, expires_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12,$13)
ON CONFLICT (tenant_id, packet_id) DO NOTHING`,
		receipt.TenantID, receipt.PacketID, receipt.SchemaVersion, receipt.Workflow,
		receipt.ScopeURN, receipt.DecisionState, receipt.Confidence, receipt.PacketDigest,
		receipt.EvidenceDigest, receipt.CoverageDigest, string(receipt.PacketJSON),
		receipt.CreatedAt.UTC(), expiresAt)
	if err != nil {
		return fmt.Errorf("insert decision packet receipt: %w", err)
	}
	if rows, _ := result.RowsAffected(); rows > 0 {
		return nil
	}
	var existingDigest string
	if err := s.db.QueryRowContext(ctx, `
SELECT packet_digest FROM decision_packet_receipts
WHERE tenant_id = $1 AND packet_id = $2`, receipt.TenantID, receipt.PacketID).Scan(&existingDigest); err != nil {
		return fmt.Errorf("read existing decision packet receipt: %w", err)
	}
	if existingDigest != receipt.PacketDigest {
		return ports.ErrDecisionPacketImmutable
	}
	return nil
}

func (s *Store) GetDecisionPacketReceipt(ctx context.Context, tenantID, packetID string) (*ports.DecisionPacketReceipt, error) {
	tenantID = strings.TrimSpace(tenantID)
	packetID = strings.TrimSpace(packetID)
	if tenantID == "" || packetID == "" {
		return nil, errors.New("tenant id and decision packet id are required")
	}
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureDecisionPacketTable(ctx); err != nil {
		return nil, err
	}
	receipt := &ports.DecisionPacketReceipt{TenantID: tenantID, PacketID: packetID}
	var packetJSON string
	var expiresAt sql.NullTime
	if err := s.db.QueryRowContext(ctx, `
SELECT schema_version, workflow, scope_urn, decision_state, confidence_level,
       packet_digest, evidence_digest, coverage_digest, packet_json::text,
       created_at, expires_at
FROM decision_packet_receipts
WHERE tenant_id = $1 AND packet_id = $2`, tenantID, packetID).Scan(
		&receipt.SchemaVersion, &receipt.Workflow, &receipt.ScopeURN,
		&receipt.DecisionState, &receipt.Confidence, &receipt.PacketDigest,
		&receipt.EvidenceDigest, &receipt.CoverageDigest, &packetJSON,
		&receipt.CreatedAt, &expiresAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ports.ErrDecisionPacketNotFound
		}
		return nil, fmt.Errorf("query decision packet receipt: %w", err)
	}
	receipt.PacketJSON = []byte(packetJSON)
	if expiresAt.Valid {
		value := expiresAt.Time.UTC()
		receipt.ExpiresAt = &value
	}
	return receipt, nil
}

func (s *Store) ensureDecisionPacketTable(ctx context.Context) error {
	return s.ensureStatements(ctx, &s.grc.decisionPackets, "decision_packet_receipts", ensureDecisionPacketStatements)
}

func validateDecisionPacketReceipt(receipt *ports.DecisionPacketReceipt) error {
	if receipt == nil || strings.TrimSpace(receipt.TenantID) == "" || strings.TrimSpace(receipt.PacketID) == "" ||
		strings.TrimSpace(receipt.SchemaVersion) == "" || strings.TrimSpace(receipt.Workflow) == "" ||
		strings.TrimSpace(receipt.DecisionState) == "" || strings.TrimSpace(receipt.Confidence) == "" ||
		strings.TrimSpace(receipt.PacketDigest) == "" || strings.TrimSpace(receipt.EvidenceDigest) == "" ||
		strings.TrimSpace(receipt.CoverageDigest) == "" || len(receipt.PacketJSON) == 0 || receipt.CreatedAt.IsZero() {
		return errors.New("decision packet receipt is incomplete")
	}
	return nil
}
