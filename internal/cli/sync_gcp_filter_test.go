package cli

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestResolveGCPTableFilters(t *testing.T) {
	tests := []struct {
		name            string
		tableFilter     []string
		securityEnabled bool
		wantNative      []string
		wantSecurity    []string
		wantRunNative   bool
		wantRunSecurity bool
		wantErr         string
	}{
		{
			name:            "no filter security disabled",
			tableFilter:     nil,
			securityEnabled: false,
			wantRunNative:   true,
			wantRunSecurity: false,
		},
		{
			name:            "no filter security enabled",
			tableFilter:     nil,
			securityEnabled: true,
			wantRunNative:   true,
			wantRunSecurity: true,
		},
		{
			name:            "native filter only",
			tableFilter:     []string{"gcp_compute_instances"},
			securityEnabled: false,
			wantNative:      []string{"gcp_compute_instances"},
			wantRunNative:   true,
			wantRunSecurity: false,
		},
		{
			name:            "security filter only with security enabled",
			tableFilter:     []string{"SCC_FINDINGS"},
			securityEnabled: true,
			wantSecurity:    []string{"scc_findings"},
			wantRunNative:   false,
			wantRunSecurity: true,
		},
		{
			name:            "security filter only with security disabled",
			tableFilter:     []string{"gcp_scc_findings"},
			securityEnabled: false,
			wantSecurity:    []string{"gcp_scc_findings"},
			wantRunNative:   false,
			wantRunSecurity: false,
			wantErr:         "rerun with --security",
		},
		{
			name:            "mixed filter security disabled",
			tableFilter:     []string{"gcp_compute_instances", "artifact_images"},
			securityEnabled: false,
			wantNative:      []string{"gcp_compute_instances"},
			wantSecurity:    []string{"artifact_images"},
			wantRunNative:   true,
			wantRunSecurity: false,
		},
		{
			name:            "mixed filter security enabled",
			tableFilter:     []string{"gcp_compute_instances", "artifact_images"},
			securityEnabled: true,
			wantNative:      []string{"gcp_compute_instances"},
			wantSecurity:    []string{"artifact_images"},
			wantRunNative:   true,
			wantRunSecurity: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			native, security, runNative, runSecurity, err := resolveGCPTableFilters(tt.tableFilter, tt.securityEnabled)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if strings.Join(native, ",") != strings.Join(tt.wantNative, ",") {
				t.Fatalf("unexpected native filter: got %v want %v", native, tt.wantNative)
			}
			if strings.Join(security, ",") != strings.Join(tt.wantSecurity, ",") {
				t.Fatalf("unexpected security filter: got %v want %v", security, tt.wantSecurity)
			}
			if runNative != tt.wantRunNative {
				t.Fatalf("unexpected runNative: got %v want %v", runNative, tt.wantRunNative)
			}
			if runSecurity != tt.wantRunSecurity {
				t.Fatalf("unexpected runSecurity: got %v want %v", runSecurity, tt.wantRunSecurity)
			}
		})
	}
}

func TestRunGCPSync_SecurityOnlyFilterRequiresSecurityFlag(t *testing.T) {
	originalTable := syncTable
	originalSecurity := syncSecurity
	originalValidate := syncValidate
	t.Cleanup(func() {
		syncTable = originalTable
		syncSecurity = originalSecurity
		syncValidate = originalValidate
	})

	syncTable = "gcp_scc_findings"
	syncSecurity = false
	syncValidate = false

	err := runGCPSync(context.Background(), time.Now(), "proj-1")
	if err == nil || !strings.Contains(err.Error(), "rerun with --security") {
		t.Fatalf("expected security flag guidance error, got %v", err)
	}
}

func TestRunGCPMultiProjectSync_SecurityOnlyFilterRequiresSecurityFlag(t *testing.T) {
	originalTable := syncTable
	originalSecurity := syncSecurity
	originalValidate := syncValidate
	t.Cleanup(func() {
		syncTable = originalTable
		syncSecurity = originalSecurity
		syncValidate = originalValidate
	})

	syncTable = "gcp_scc_findings"
	syncSecurity = false
	syncValidate = false

	err := runGCPMultiProjectSync(context.Background(), time.Now(), []string{"proj-1"})
	if err == nil || !strings.Contains(err.Error(), "rerun with --security") {
		t.Fatalf("expected security flag guidance error, got %v", err)
	}
}

func TestRunGCPAssetAPISync_SecurityOnlyFilterRequiresSecurityFlag(t *testing.T) {
	originalTable := syncTable
	originalSecurity := syncSecurity
	originalValidate := syncValidate
	t.Cleanup(func() {
		syncTable = originalTable
		syncSecurity = originalSecurity
		syncValidate = originalValidate
	})

	syncTable = "gcp_scc_findings"
	syncSecurity = false
	syncValidate = false

	err := runGCPAssetAPISync(context.Background(), time.Now(), []string{"proj-1"})
	if err == nil || !strings.Contains(err.Error(), "rerun with --security") {
		t.Fatalf("expected security flag guidance error, got %v", err)
	}
}

func TestRunGCPOrgSync_SecurityOnlySkipsProjectDiscovery(t *testing.T) {
	originalTable := syncTable
	originalSecurity := syncSecurity
	originalValidate := syncValidate
	originalUseAssetAPI := syncUseAssetAPI
	originalListOrgProjects := listOrganizationProjectsFn
	t.Cleanup(func() {
		syncTable = originalTable
		syncSecurity = originalSecurity
		syncValidate = originalValidate
		syncUseAssetAPI = originalUseAssetAPI
		listOrganizationProjectsFn = originalListOrgProjects
	})

	t.Setenv("SNOWFLAKE_ACCOUNT", "")
	t.Setenv("SNOWFLAKE_USER", "")
	t.Setenv("SNOWFLAKE_PRIVATE_KEY", "")

	syncTable = "gcp_scc_findings"
	syncSecurity = true
	syncValidate = false
	syncUseAssetAPI = true

	called := false
	listOrganizationProjectsFn = func(context.Context, string) ([]string, error) {
		called = true
		return nil, errors.New("project listing should be skipped")
	}

	err := runGCPOrgSync(context.Background(), time.Now(), "1234567890")
	if called {
		t.Fatalf("expected organization project discovery to be skipped")
	}
	if err == nil || !strings.Contains(err.Error(), "snowflake not configured") {
		t.Fatalf("expected snowflake configuration error, got %v", err)
	}
}

func TestRunGCPOrgSync_ProjectDiscoveryRequired(t *testing.T) {
	originalTable := syncTable
	originalSecurity := syncSecurity
	originalValidate := syncValidate
	originalUseAssetAPI := syncUseAssetAPI
	originalListOrgProjects := listOrganizationProjectsFn
	t.Cleanup(func() {
		syncTable = originalTable
		syncSecurity = originalSecurity
		syncValidate = originalValidate
		syncUseAssetAPI = originalUseAssetAPI
		listOrganizationProjectsFn = originalListOrgProjects
	})

	syncTable = "gcp_compute_instances"
	syncSecurity = true
	syncValidate = false
	syncUseAssetAPI = false

	called := false
	listOrganizationProjectsFn = func(context.Context, string) ([]string, error) {
		called = true
		return nil, errors.New("listing failed")
	}

	err := runGCPOrgSync(context.Background(), time.Now(), "1234567890")
	if !called {
		t.Fatalf("expected organization project discovery to run")
	}
	if err == nil || !strings.Contains(err.Error(), "list organization projects: listing failed") {
		t.Fatalf("expected organization project discovery error, got %v", err)
	}
}

func TestRunGCPSync_ValidateSecurityOnlyFilterSkipsSnowflake(t *testing.T) {
	originalTable := syncTable
	originalSecurity := syncSecurity
	originalValidate := syncValidate
	t.Cleanup(func() {
		syncTable = originalTable
		syncSecurity = originalSecurity
		syncValidate = originalValidate
	})

	t.Setenv("SNOWFLAKE_ACCOUNT", "")
	t.Setenv("SNOWFLAKE_USER", "")
	t.Setenv("SNOWFLAKE_PRIVATE_KEY", "")

	syncTable = "gcp_scc_findings"
	syncSecurity = true
	syncValidate = true

	err := runGCPSync(context.Background(), time.Now(), "proj-1")
	if err == nil || !strings.Contains(err.Error(), "validation for GCP security-only table filters is not supported") {
		t.Fatalf("expected validation guidance error, got %v", err)
	}
}

func TestRunGCPMultiProjectSync_ValidateSecurityOnlyFilterSkipsSnowflake(t *testing.T) {
	originalTable := syncTable
	originalSecurity := syncSecurity
	originalValidate := syncValidate
	t.Cleanup(func() {
		syncTable = originalTable
		syncSecurity = originalSecurity
		syncValidate = originalValidate
	})

	t.Setenv("SNOWFLAKE_ACCOUNT", "")
	t.Setenv("SNOWFLAKE_USER", "")
	t.Setenv("SNOWFLAKE_PRIVATE_KEY", "")

	syncTable = "gcp_scc_findings"
	syncSecurity = true
	syncValidate = true

	err := runGCPMultiProjectSync(context.Background(), time.Now(), []string{"proj-1"})
	if err == nil || !strings.Contains(err.Error(), "validation for GCP security-only table filters is not supported") {
		t.Fatalf("expected validation guidance error, got %v", err)
	}
}

func TestRunGCPAssetAPISync_ValidateSecurityOnlyFilterSkipsSnowflake(t *testing.T) {
	originalTable := syncTable
	originalSecurity := syncSecurity
	originalValidate := syncValidate
	t.Cleanup(func() {
		syncTable = originalTable
		syncSecurity = originalSecurity
		syncValidate = originalValidate
	})

	t.Setenv("SNOWFLAKE_ACCOUNT", "")
	t.Setenv("SNOWFLAKE_USER", "")
	t.Setenv("SNOWFLAKE_PRIVATE_KEY", "")

	syncTable = "gcp_scc_findings"
	syncSecurity = true
	syncValidate = true

	err := runGCPAssetAPISync(context.Background(), time.Now(), []string{"proj-1"})
	if err == nil || !strings.Contains(err.Error(), "validation for GCP security-only table filters is not supported") {
		t.Fatalf("expected validation guidance error, got %v", err)
	}
}
