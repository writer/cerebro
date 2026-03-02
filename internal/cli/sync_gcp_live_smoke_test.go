package cli

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func TestLiveGCPImpersonationDelegateChainSmoke(t *testing.T) {
	if strings.TrimSpace(os.Getenv("CEREBRO_LIVE_GCP_AUTH_SMOKE")) != "1" {
		t.Skip("set CEREBRO_LIVE_GCP_AUTH_SMOKE=1 to run live GCP auth smoke test")
	}

	projectID := strings.TrimSpace(os.Getenv("CEREBRO_GCP_SMOKE_PROJECT"))
	if projectID == "" {
		t.Skip("set CEREBRO_GCP_SMOKE_PROJECT for live GCP auth smoke test")
	}

	sourceCredentialsFile := strings.TrimSpace(os.Getenv("CEREBRO_GCP_SMOKE_SOURCE_CREDENTIALS_FILE"))
	if sourceCredentialsFile == "" {
		t.Skip("set CEREBRO_GCP_SMOKE_SOURCE_CREDENTIALS_FILE for live GCP auth smoke test")
	}

	impersonateServiceAccount := strings.TrimSpace(os.Getenv("CEREBRO_GCP_SMOKE_IMPERSONATE_SERVICE_ACCOUNT"))
	if impersonateServiceAccount == "" {
		t.Skip("set CEREBRO_GCP_SMOKE_IMPERSONATE_SERVICE_ACCOUNT for live GCP auth smoke test")
	}

	delegates := parseDelimitedEnvValues(os.Getenv("CEREBRO_GCP_SMOKE_IMPERSONATE_DELEGATES"))
	if len(delegates) == 0 {
		t.Skip("set CEREBRO_GCP_SMOKE_IMPERSONATE_DELEGATES to validate delegate-chain impersonation")
	}

	orgID := strings.TrimSpace(os.Getenv("CEREBRO_GCP_SMOKE_ORG"))

	spec := scheduledSyncSpec{
		GCPCredentialsFile:           sourceCredentialsFile,
		GCPImpersonateServiceAccount: impersonateServiceAccount,
		GCPImpersonateDelegates:      delegates,
		GCPImpersonateTokenLifetime:  "1200",
	}

	authCfg, err := applyScheduledGCPAuth(spec)
	if err != nil {
		t.Fatalf("apply scheduled GCP auth: %v", err)
	}
	t.Cleanup(func() {
		if authCfg != nil && authCfg.Cleanup != nil {
			authCfg.Cleanup()
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	schedule := &SyncSchedule{Name: "live-gcp-auth-smoke", Provider: "gcp"}
	if err := preflightScheduledGCPAuth(ctx, schedule, spec, authCfg); err != nil {
		t.Fatalf("gcp auth preflight failed: %v", err)
	}

	if err := preflightGCPProjectAccess(ctx, gcpProjectPreflightSpec{
		ProjectID:      projectID,
		RunNativeSync:  true,
		ClientOptions:  authCfg.ClientOptions,
		SecurityFilter: nil,
	}); err != nil {
		t.Fatalf("cloud asset project preflight failed: %v", err)
	}

	if orgID != "" {
		if err := preflightGCPProjectAccess(ctx, gcpProjectPreflightSpec{
			OrgID:          orgID,
			RunNativeSync:  false,
			RunSecurity:    true,
			SecurityFilter: []string{"gcp_scc_findings"},
			ClientOptions:  authCfg.ClientOptions,
		}); err != nil {
			t.Fatalf("scc preflight failed: %v", err)
		}
	}
}

func parseDelimitedEnvValues(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		switch r {
		case ',', '|', ';':
			return true
		default:
			return false
		}
	})
	return uniqueNonEmpty(parts)
}
