//go:build liveauth

package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"golang.org/x/oauth2/google"
)

func TestLiveAWSAuthOverrides_GetCallerIdentity(t *testing.T) {
	if strings.TrimSpace(os.Getenv("CEREBRO_LIVE_AWS")) != "1" {
		t.Skip("set CEREBRO_LIVE_AWS=1 to run live AWS auth test")
	}

	originalProfile := syncAWSProfile
	originalConfigFile := syncAWSConfigFile
	originalSharedCredsFile := syncAWSSharedCredsFile
	originalCredentialProc := syncAWSCredentialProc
	originalWebIDToken := syncAWSWebIDTokenFile
	originalWebIDRole := syncAWSWebIDRoleARN
	originalRoleARN := syncAWSRoleARN
	originalRoleSession := syncAWSRoleSession
	originalRoleExternalID := syncAWSRoleExternalID
	originalRoleMFASerial := syncAWSRoleMFASerial
	originalRoleMFAToken := syncAWSRoleMFAToken
	t.Cleanup(func() {
		syncAWSProfile = originalProfile
		syncAWSConfigFile = originalConfigFile
		syncAWSSharedCredsFile = originalSharedCredsFile
		syncAWSCredentialProc = originalCredentialProc
		syncAWSWebIDTokenFile = originalWebIDToken
		syncAWSWebIDRoleARN = originalWebIDRole
		syncAWSRoleARN = originalRoleARN
		syncAWSRoleSession = originalRoleSession
		syncAWSRoleExternalID = originalRoleExternalID
		syncAWSRoleMFASerial = originalRoleMFASerial
		syncAWSRoleMFAToken = originalRoleMFAToken
	})

	syncAWSProfile = strings.TrimSpace(os.Getenv("CEREBRO_TEST_AWS_PROFILE"))
	syncAWSConfigFile = strings.TrimSpace(os.Getenv("CEREBRO_TEST_AWS_CONFIG_FILE"))
	syncAWSSharedCredsFile = strings.TrimSpace(os.Getenv("CEREBRO_TEST_AWS_SHARED_CREDENTIALS_FILE"))
	syncAWSCredentialProc = strings.TrimSpace(os.Getenv("CEREBRO_TEST_AWS_CREDENTIAL_PROCESS"))
	syncAWSWebIDTokenFile = strings.TrimSpace(os.Getenv("CEREBRO_TEST_AWS_WEB_IDENTITY_TOKEN_FILE"))
	syncAWSWebIDRoleARN = strings.TrimSpace(os.Getenv("CEREBRO_TEST_AWS_WEB_IDENTITY_ROLE_ARN"))
	syncAWSRoleARN = strings.TrimSpace(os.Getenv("CEREBRO_TEST_AWS_ROLE_ARN"))
	syncAWSRoleSession = strings.TrimSpace(os.Getenv("CEREBRO_TEST_AWS_ROLE_SESSION_NAME"))
	if syncAWSRoleSession == "" {
		syncAWSRoleSession = "cerebro-live-auth"
	}
	syncAWSRoleExternalID = strings.TrimSpace(os.Getenv("CEREBRO_TEST_AWS_ROLE_EXTERNAL_ID"))
	syncAWSRoleMFASerial = strings.TrimSpace(os.Getenv("CEREBRO_TEST_AWS_ROLE_MFA_SERIAL"))
	syncAWSRoleMFAToken = strings.TrimSpace(os.Getenv("CEREBRO_TEST_AWS_ROLE_MFA_TOKEN"))

	if syncAWSConfigFile == "" {
		defaultConfig := filepath.Join(os.Getenv("HOME"), ".aws", "config")
		if _, err := os.Stat(defaultConfig); err == nil {
			syncAWSConfigFile = defaultConfig
		}
	}

	cleanup, err := applyAWSAuthOverrides()
	if err != nil {
		t.Fatalf("applyAWSAuthOverrides: %v", err)
	}
	t.Cleanup(cleanup)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cfg, err := loadAWSConfig(ctx, syncAWSProfile)
	if err != nil {
		t.Fatalf("loadAWSConfig: %v", err)
	}

	cfg, err = applyAWSAssumeRoleOverride(ctx, cfg)
	if err != nil {
		t.Fatalf("applyAWSAssumeRoleOverride: %v", err)
	}

	out, err := sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		t.Fatalf("GetCallerIdentity: %v", err)
	}
	if aws.ToString(out.Account) == "" {
		t.Fatal("GetCallerIdentity returned empty account")
	}
	if aws.ToString(out.Arn) == "" {
		t.Fatal("GetCallerIdentity returned empty ARN")
	}
}

func TestLiveGCPAuthOverrides_FetchAccessToken(t *testing.T) {
	if strings.TrimSpace(os.Getenv("CEREBRO_LIVE_GCP")) != "1" {
		t.Skip("set CEREBRO_LIVE_GCP=1 to run live GCP auth test")
	}

	originalCredsFile := syncGCPCredentialsFile
	originalImpersonateSA := syncGCPImpersonateSA
	originalImpersonateDelegates := syncGCPImpersonateDel
	t.Cleanup(func() {
		syncGCPCredentialsFile = originalCredsFile
		syncGCPImpersonateSA = originalImpersonateSA
		syncGCPImpersonateDel = originalImpersonateDelegates
	})

	syncGCPCredentialsFile = strings.TrimSpace(os.Getenv("CEREBRO_TEST_GCP_CREDENTIALS_FILE"))
	syncGCPImpersonateSA = strings.TrimSpace(os.Getenv("CEREBRO_TEST_GCP_IMPERSONATE_SERVICE_ACCOUNT"))
	syncGCPImpersonateDel = strings.TrimSpace(os.Getenv("CEREBRO_TEST_GCP_IMPERSONATE_DELEGATES"))

	if syncGCPCredentialsFile == "" {
		adcPath := filepath.Join(os.Getenv("HOME"), ".config", "gcloud", "application_default_credentials.json")
		if _, err := os.Stat(adcPath); err == nil {
			syncGCPCredentialsFile = adcPath
		}
	}

	cleanup, err := applyGCPAuthOverrides()
	if err != nil {
		t.Fatalf("applyGCPAuthOverrides: %v", err)
	}
	t.Cleanup(cleanup)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	creds, err := google.FindDefaultCredentials(ctx, "https://www.googleapis.com/auth/cloud-platform")
	if err != nil {
		t.Fatalf("FindDefaultCredentials: %v", err)
	}

	token, err := creds.TokenSource.Token()
	if err != nil {
		t.Fatalf("TokenSource.Token: %v", err)
	}
	if strings.TrimSpace(token.AccessToken) == "" {
		t.Fatal("received empty GCP access token")
	}
}
