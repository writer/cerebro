package findings_test

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/statestore/postgres"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// TestCloudflareZoneProtectionPausedPostgresReopenLifecycle exercises the
// Cloudflare zone-protection-paused durable finding lifecycle against a real
// Postgres state store so the open -> resolved -> reopened transitions are
// validated against persisted storage semantics rather than only in-memory
// candidate emission. Remediation (unpausing the zone) resolves the persisted
// finding through the production counter-event close path, and a later
// recurrence (the same zone paused again) reopens the same finding fingerprint
// and row id via the real UpsertFinding reopen path without minting a duplicate
// generation row.
//
// Run with: CEREBRO_POSTGRES_DSN=... go test ./internal/findings/... -run TestCloudflareZoneProtectionPausedPostgresReopenLifecycle -count=1
func TestCloudflareZoneProtectionPausedPostgresReopenLifecycle(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("CEREBRO_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set CEREBRO_POSTGRES_DSN to run the postgres-backed Cloudflare reopen lifecycle integration test")
	}

	ctx := context.Background()
	store, err := postgres.Open(config.StateStoreConfig{
		Driver:      config.StateStoreDriverPostgres,
		PostgresDSN: dsn,
	})
	if err != nil {
		t.Fatalf("open postgres store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	rawDB, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open raw db: %v", err)
	}
	t.Cleanup(func() { _ = rawDB.Close() })

	nonce := time.Now().UTC().UnixNano()
	tenantID := fmt.Sprintf("tenant-cloudflare-reopen-e2e-%d", nonce)
	runtimeID := fmt.Sprintf("runtime-cloudflare-reopen-e2e-%d", nonce)
	zoneID := fmt.Sprintf("zone-cloudflare-reopen-e2e-%d", nonce)
	ruleID := "cloudflare-zone-protection-paused"

	openedAt := time.Now().UTC().Add(-3 * time.Hour).Truncate(time.Microsecond)
	restoredAt := openedAt.Add(time.Hour)
	recurredAt := restoredAt.Add(time.Hour)

	t.Cleanup(func() {
		bg := context.Background()
		_, _ = rawDB.ExecContext(bg, `DELETE FROM finding_evidence WHERE runtime_id = $1`, runtimeID)
		_, _ = rawDB.ExecContext(bg, `DELETE FROM finding_evaluation_runs WHERE runtime_id = $1`, runtimeID)
		_, _ = rawDB.ExecContext(bg, `DELETE FROM findings WHERE tenant_id = $1`, tenantID)
	})

	runtimeStore := &stubRuntimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			runtimeID: {
				Id:       runtimeID,
				SourceId: "cloudflare",
				TenantId: tenantID,
				Config:   map[string]string{"family": "zone"},
			},
		},
	}
	replayer := &stubReplayer{}
	service := findings.NewWithRegistry(runtimeStore, replayer, store, store, store, store, findings.Builtin())

	// 1. Active edge-protection pause opens a durable finding persisted in Postgres.
	replayer.events = []*cerebrov1.EventEnvelope{
		cloudflareZoneReopenE2EEvent("cf-zone-paused-open", tenantID, runtimeID, zoneID, "true", openedAt),
	}
	openResult, err := service.EvaluateSourceRuntimeRules(ctx, findings.EvaluateRulesRequest{
		RuntimeID: runtimeID,
		RuleIDs:   []string{ruleID},
	})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntimeRules(open): %v", err)
	}
	if openResult == nil || len(openResult.Evaluations) != 1 || len(openResult.Evaluations[0].Findings) != 1 {
		t.Fatalf("open result = %#v, want one cloudflare paused-zone finding", openResult)
	}
	opened := openResult.Evaluations[0].Findings[0]
	if got := strings.TrimSpace(opened.Status); got != "open" {
		t.Fatalf("opened status = %q, want open", got)
	}
	if got := strings.TrimSpace(opened.TenantID); got != tenantID {
		t.Fatalf("opened tenant_id = %q, want %q", got, tenantID)
	}
	openFingerprint := strings.TrimSpace(opened.Fingerprint)
	if openFingerprint == "" {
		t.Fatal("opened finding has empty fingerprint")
	}

	persistedOpen, err := store.GetFinding(ctx, opened.ID)
	if err != nil {
		t.Fatalf("GetFinding(%q) after open: %v", opened.ID, err)
	}
	if got := strings.TrimSpace(persistedOpen.Status); got != "open" {
		t.Fatalf("persisted opened status = %q, want open", got)
	}

	// 2. Remediation (zone unpaused) resolves the persisted finding through the
	//    real counter-event close path. The unpaused event itself must not open
	//    a new finding.
	replayer.events = []*cerebrov1.EventEnvelope{
		cloudflareZoneReopenE2EEvent("cf-zone-unpaused", tenantID, runtimeID, zoneID, "false", restoredAt),
	}
	resolveResult, err := service.EvaluateSourceRuntimeRules(ctx, findings.EvaluateRulesRequest{
		RuntimeID: runtimeID,
		RuleIDs:   []string{ruleID},
	})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntimeRules(resolve): %v", err)
	}
	if resolveResult == nil || len(resolveResult.Evaluations) != 1 {
		t.Fatalf("resolve result = %#v, want one evaluation", resolveResult)
	}
	for _, finding := range resolveResult.Evaluations[0].Findings {
		if finding == nil {
			continue
		}
		if got := strings.TrimSpace(finding.Status); got == "open" {
			t.Fatalf("resolve evaluation re-opened finding %q with status open, want no active reopen on unpaused zone", strings.TrimSpace(finding.ID))
		}
	}

	resolved, err := store.GetFinding(ctx, opened.ID)
	if err != nil {
		t.Fatalf("GetFinding(%q) after remediation: %v", opened.ID, err)
	}
	if got := strings.TrimSpace(resolved.Status); got != "resolved" {
		t.Fatalf("remediated status = %q, want resolved", got)
	}
	if got := strings.TrimSpace(resolved.StatusReason); got != "closed_by_counter_event" {
		t.Fatalf("remediated status_reason = %q, want closed_by_counter_event", got)
	}
	if resolved.Tombstoned {
		t.Fatalf("remediated finding tombstoned = true, want false")
	}

	// 3. Recurrence (the same zone paused again) reopens the persisted finding on
	//    the same fingerprint and row id instead of emitting a fresh in-memory
	//    candidate or minting a duplicate generation row.
	replayer.events = []*cerebrov1.EventEnvelope{
		cloudflareZoneReopenE2EEvent("cf-zone-paused-recur", tenantID, runtimeID, zoneID, "true", recurredAt),
	}
	reopenResult, err := service.EvaluateSourceRuntimeRules(ctx, findings.EvaluateRulesRequest{
		RuntimeID: runtimeID,
		RuleIDs:   []string{ruleID},
	})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntimeRules(reopen): %v", err)
	}
	if reopenResult == nil || len(reopenResult.Evaluations) != 1 || len(reopenResult.Evaluations[0].Findings) != 1 {
		t.Fatalf("reopen result = %#v, want one reopened cloudflare finding", reopenResult)
	}
	reopenedFromResult := reopenResult.Evaluations[0].Findings[0]
	if got := strings.TrimSpace(reopenedFromResult.ID); got != strings.TrimSpace(opened.ID) {
		t.Fatalf("reopened finding id = %q, want original id %q from real upsert reopen path", got, opened.ID)
	}
	if got := strings.TrimSpace(reopenedFromResult.Fingerprint); got != openFingerprint {
		t.Fatalf("reopened fingerprint = %q, want stable %q", got, openFingerprint)
	}

	reopened, err := store.GetFinding(ctx, opened.ID)
	if err != nil {
		t.Fatalf("GetFinding(%q) after recurrence: %v", opened.ID, err)
	}
	if got := strings.TrimSpace(reopened.Status); got != "open" {
		t.Fatalf("reopened status = %q, want open", got)
	}
	if got := strings.TrimSpace(reopened.StatusReason); got != "" {
		t.Fatalf("reopened status_reason = %q, want empty", got)
	}
	if reopened.Tombstoned {
		t.Fatalf("reopened finding tombstoned = true, want false")
	}
	if strings.Contains(reopened.ID, "#g") {
		t.Fatalf("reopened finding id = %q, want original non-generation row for durable counter-event reopen", reopened.ID)
	}

	var activeRows int
	if err := rawDB.QueryRowContext(ctx, `SELECT count(*) FROM findings WHERE tenant_id = $1 AND rule_id = $2 AND fingerprint = $3 AND tombstoned = FALSE`, tenantID, ruleID, openFingerprint).Scan(&activeRows); err != nil {
		t.Fatalf("count active reopened rows: %v", err)
	}
	if activeRows != 1 {
		t.Fatalf("active rows for reopened cloudflare fingerprint = %d, want 1 (no duplicate churn)", activeRows)
	}
}

func cloudflareZoneReopenE2EEvent(id string, tenantID string, runtimeID string, zoneID string, paused string, occurredAt time.Time) *cerebrov1.EventEnvelope {
	return &cerebrov1.EventEnvelope{
		Id:         id,
		TenantId:   tenantID,
		SourceId:   "cloudflare",
		Kind:       "cloudflare.zone",
		OccurredAt: timestamppb.New(occurredAt.UTC()),
		SchemaRef:  "cloudflare/zone/v1",
		Attributes: map[string]string{
			"family":                            "zone",
			"zone_id":                           zoneID,
			"account_id":                        fmt.Sprintf("acct-%s", zoneID),
			"name":                              "reopen-e2e.example.com",
			"status":                            "active",
			"paused":                            paused,
			ports.EventAttributeSourceRuntimeID: runtimeID,
		},
	}
}
