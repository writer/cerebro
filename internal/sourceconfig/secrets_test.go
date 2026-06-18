package sourceconfig

import "testing"

func TestSensitiveKeyDetectsCommonSecretNames(t *testing.T) {
	for _, key := range []string{"token", "api_key", "client-secret", "private.key", "password"} {
		if !SensitiveKey(key) {
			t.Fatalf("SensitiveKey(%q) = false, want true", key)
		}
	}
	if SensitiveKey("owner") {
		t.Fatal("SensitiveKey(owner) = true, want false")
	}
}

func TestLiteralEnvPrefixKeyDetectsQueryLikeKeys(t *testing.T) {
	for _, key := range []string{"filter", "phrase", "q", "search"} {
		if !LiteralEnvPrefixKey(key) {
			t.Fatalf("LiteralEnvPrefixKey(%q) = false, want true", key)
		}
	}
	if LiteralEnvPrefixKey("token") {
		t.Fatal("LiteralEnvPrefixKey(token) = true, want false")
	}
}

func TestValidateAWSCredentialSourceRejectsHostFallback(t *testing.T) {
	for _, tt := range []struct {
		name            string
		profile         string
		accessKeyID     string
		secretAccessKey string
		sessionToken    string
		roleARN         string
	}{
		{name: "empty"},
		{name: "shared profile", profile: "prod"},
		{name: "partial static credentials", accessKeyID: "AKIA_TEST"},
		{name: "session token only", sessionToken: "token"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateAWSCredentialSource(tt.profile, tt.accessKeyID, tt.secretAccessKey, tt.sessionToken, tt.roleARN); err == nil {
				t.Fatal("ValidateAWSCredentialSource() error = nil, want non-nil")
			}
		})
	}
}

func TestValidateAWSCredentialSourceAllowsExplicitCredentialsOrDelegation(t *testing.T) {
	for _, tt := range []struct {
		name            string
		accessKeyID     string
		secretAccessKey string
		roleARN         string
	}{
		{name: "static credentials", accessKeyID: "AKIA_TEST", secretAccessKey: "secret"},
		{name: "allowlisted role", roleARN: "arn:aws:iam::123456789012:role/cerebro-org-scan-role"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateAWSCredentialSource("", tt.accessKeyID, tt.secretAccessKey, "", tt.roleARN); err != nil {
				t.Fatalf("ValidateAWSCredentialSource() error = %v", err)
			}
		})
	}
}

func TestValidateAWSAssumeRoleBindingRejectsUnsafeBindings(t *testing.T) {
	allowed := "arn:aws:iam::123456789012:role/cerebro-org-scan-role"
	for _, tt := range []struct {
		name      string
		accountID string
		tenantID  string
		roleARN   string
		allowlist string
	}{
		{name: "unallowlisted role", accountID: "123456789012", tenantID: "writer", roleARN: "arn:aws:iam::123456789012:role/OtherRole", allowlist: "writer=" + allowed},
		{name: "account mismatch", accountID: "123456789012", tenantID: "writer", roleARN: "arn:aws:iam::210987654321:role/cerebro-org-scan-role", allowlist: "writer=" + allowed},
		{name: "invalid role arn", accountID: "123456789012", tenantID: "writer", roleARN: "legacy", allowlist: "writer=" + allowed},
		{name: "tenant mismatch", accountID: "123456789012", tenantID: "writer", roleARN: allowed, allowlist: "other=" + allowed},
		{name: "bare allowlist entry", accountID: "123456789012", tenantID: "writer", roleARN: allowed, allowlist: allowed},
		{name: "missing runtime tenant", accountID: "123456789012", roleARN: allowed, allowlist: "writer=" + allowed},
		{name: "empty tenant allowlist entry", accountID: "123456789012", tenantID: "writer", roleARN: allowed, allowlist: "=" + allowed},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateAWSAssumeRoleBinding(tt.accountID, tt.tenantID, tt.roleARN, tt.allowlist); err == nil {
				t.Fatal("ValidateAWSAssumeRoleBinding() error = nil, want non-nil")
			}
		})
	}
}

func TestValidateAWSAssumeRoleBindingAllowsTrustedRuntime(t *testing.T) {
	roleARN := "arn:aws:iam::123456789012:role/cerebro-org-scan-role"
	if err := ValidateAWSAssumeRoleBinding("123456789012", "writer", roleARN, "writer="+roleARN); err != nil {
		t.Fatalf("ValidateAWSAssumeRoleBinding() error = %v", err)
	}
}

func TestValidateGCPTokenOrWIFAllowsStaticToken(t *testing.T) {
	if err := ValidateGCPTokenOrWIF("static-token", "", "", "", ""); err != nil {
		t.Fatalf("ValidateGCPTokenOrWIF() error = %v", err)
	}
}

func TestValidateGCPWIFBindingRejectsUntrustedRuntime(t *testing.T) {
	audience := "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/aws"
	serviceAccount := "scanner@writer-iam.iam.gserviceaccount.com"
	for _, tt := range []struct {
		name           string
		tenantID       string
		audience       string
		serviceAccount string
		allowlist      string
	}{
		{name: "missing runtime tenant", audience: audience, serviceAccount: serviceAccount, allowlist: "writer=" + audience + "|" + serviceAccount},
		{name: "missing trusted binding", tenantID: "writer", audience: audience, serviceAccount: serviceAccount},
		{name: "service account mismatch", tenantID: "writer", audience: audience, serviceAccount: serviceAccount, allowlist: "writer=" + audience + "|other@writer-iam.iam.gserviceaccount.com"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateGCPWIFBinding(tt.tenantID, tt.audience, tt.serviceAccount, tt.allowlist); err == nil {
				t.Fatal("ValidateGCPWIFBinding() error = nil, want non-nil")
			}
		})
	}
}

func TestValidateGCPWIFBindingAllowsTrustedRuntime(t *testing.T) {
	audience := "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/aws"
	serviceAccount := "scanner@writer-iam.iam.gserviceaccount.com"
	if err := ValidateGCPWIFBinding("writer", audience, serviceAccount, "writer="+audience+"|"+serviceAccount); err != nil {
		t.Fatalf("ValidateGCPWIFBinding() error = %v", err)
	}
}
