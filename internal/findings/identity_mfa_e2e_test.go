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

func TestIdentityMFACloseAnchor_NoCloseOnBlankPosture(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("CEREBRO_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set CEREBRO_POSTGRES_DSN to run the identity MFA close-anchor integration test")
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
	tenantID := fmt.Sprintf("example-identity-mfa-%d", nonce)
	runtimeID := fmt.Sprintf("runtime-identity-mfa-%d", nonce)
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = rawDB.ExecContext(bg, `DELETE FROM finding_evidence WHERE runtime_id = $1`, runtimeID)
		_, _ = rawDB.ExecContext(bg, `DELETE FROM finding_evaluation_runs WHERE runtime_id = $1`, runtimeID)
		_, _ = rawDB.ExecContext(bg, `DELETE FROM findings WHERE tenant_id = $1`, tenantID)
	})

	runtime := &cerebrov1.SourceRuntime{
		Id:       runtimeID,
		SourceId: "okta",
		TenantId: tenantID,
		Config:   map[string]string{"family": "user"},
	}
	replayer := &stubReplayer{}
	service := findings.NewWithRegistry(
		&stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{runtimeID: runtime}},
		replayer,
		store,
		store,
		store,
		store,
		findings.Builtin(),
	)

	baseAttrs := map[string]string{
		"domain":      "writer.okta.com",
		"email":       "admin@example.com",
		"is_admin":    "true",
		"login":       "admin@example.com",
		"user_id":     fmt.Sprintf("00u-admin-%d", nonce),
		"user_status": "ACTIVE",
	}
	openAttrs := cloneMFAE2EAttributes(baseAttrs)
	openAttrs["mfa_enrolled"] = "false"
	openAttrs["mfa_factor_count"] = "0"
	open := identityMFAE2EEvent("identity-mfa-open", tenantID, runtimeID, openAttrs, time.Now().UTC().Add(-time.Minute))
	replayer.events = []*cerebrov1.EventEnvelope{open}
	openResult, err := service.EvaluateSourceRuntimeRules(ctx, findings.EvaluateRulesRequest{
		RuntimeID: runtimeID,
		RuleIDs:   []string{"identity-privileged-account-without-mfa"},
	})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntimeRules(open): %v", err)
	}
	if openResult == nil || len(openResult.Evaluations) != 1 || len(openResult.Evaluations[0].Findings) != 1 {
		t.Fatalf("open result = %#v, want one privileged-no-mfa finding", openResult)
	}
	opened := openResult.Evaluations[0].Findings[0]
	if got := strings.TrimSpace(opened.Status); got != "open" {
		t.Fatalf("opened status = %q, want open", got)
	}

	blankAttrs := cloneMFAE2EAttributes(baseAttrs)
	blankAttrs["mfa_enrolled"] = ""
	blankAttrs["mfa_factor_count"] = ""
	blank := identityMFAE2EEvent("identity-mfa-blank-posture", tenantID, runtimeID, blankAttrs, time.Now().UTC())
	replayer.events = []*cerebrov1.EventEnvelope{blank}
	blankResult, err := service.EvaluateSourceRuntimeRules(ctx, findings.EvaluateRulesRequest{
		RuntimeID: runtimeID,
		RuleIDs:   []string{"identity-privileged-account-without-mfa"},
	})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntimeRules(blank posture): %v", err)
	}
	if blankResult == nil || len(blankResult.Evaluations) != 1 {
		t.Fatalf("blank posture result = %#v, want one evaluation", blankResult)
	}
	if got := len(blankResult.Evaluations[0].Findings); got != 0 {
		t.Fatalf("blank posture emitted %d findings, want 0 because unknown MFA is not an opening signal", got)
	}

	after, err := store.GetFinding(ctx, opened.ID)
	if err != nil {
		t.Fatalf("GetFinding(%q) after blank posture: %v", opened.ID, err)
	}
	if got := strings.TrimSpace(after.Status); got != "open" {
		t.Fatalf("finding status after blank MFA posture = %q, want open (transient Okta factor outage must not close it)", got)
	}
}

func identityMFAE2EEvent(id string, tenantID string, runtimeID string, attributes map[string]string, occurredAt time.Time) *cerebrov1.EventEnvelope {
	attrs := cloneMFAE2EAttributes(attributes)
	attrs[ports.EventAttributeSourceRuntimeID] = runtimeID
	return &cerebrov1.EventEnvelope{
		Id:         id,
		TenantId:   tenantID,
		SourceId:   "okta",
		Kind:       "okta.user",
		OccurredAt: timestamppb.New(occurredAt.UTC()),
		Attributes: attrs,
	}
}

func cloneMFAE2EAttributes(attributes map[string]string) map[string]string {
	cloned := make(map[string]string, len(attributes))
	for key, value := range attributes {
		cloned[key] = value
	}
	return cloned
}
