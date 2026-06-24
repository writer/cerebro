package googleworkspace

import (
	"testing"

	"github.com/writer/cerebro/sources/internal/googleworkspaceauth"
)

func TestValidateAuthSettingsRejectsMissingCredentials(t *testing.T) {
	if err := googleworkspaceauth.Validate(googleworkspaceauth.Settings{}); err == nil {
		t.Fatal("validateAuthSettings() error = nil, want auth error")
	}
}

func TestValidateAuthSettingsAllowsStaticToken(t *testing.T) {
	if err := googleworkspaceauth.Validate(googleworkspaceauth.Settings{Token: "static"}); err != nil {
		t.Fatalf("validateAuthSettings() error = %v", err)
	}
}

func TestValidateAuthSettingsAllowsServiceAccountDelegation(t *testing.T) {
	if err := googleworkspaceauth.Validate(googleworkspaceauth.Settings{
		ServiceAccountEmail: "cerebro@writer.iam.gserviceaccount.com",
		PrivateKey:          "fake-key",
		DelegatedAdminEmail: "admin@writer.com",
	}); err != nil {
		t.Fatalf("validateAuthSettings() error = %v", err)
	}
}

func TestValidateAuthSettingsAllowsOAuthRefresh(t *testing.T) {
	if err := googleworkspaceauth.Validate(googleworkspaceauth.Settings{
		ClientID:     "client",
		ClientSecret: "secret",
		RefreshToken: "refresh",
	}); err != nil {
		t.Fatalf("validateAuthSettings() error = %v", err)
	}
}

func TestServiceAccountAuthConfigured(t *testing.T) {
	if err := googleworkspaceauth.Validate(googleworkspaceauth.Settings{
		ServiceAccountEmail: "sa@test",
		PrivateKey:          "key",
		DelegatedAdminEmail: "admin@test",
	}); err != nil {
		t.Fatalf("Validate(service account) error = %v", err)
	}
	if err := googleworkspaceauth.Validate(googleworkspaceauth.Settings{ServiceAccountEmail: "sa@test"}); err == nil {
		t.Fatal("Validate(partial service account) error = nil, want error")
	}
}
