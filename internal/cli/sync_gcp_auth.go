package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strings"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
)

// GCPAuthConfig holds all inputs needed to resolve GCP credentials.
// Fields can be populated from CLI flags (direct sync) or env vars (scheduled sync).
type GCPAuthConfig struct {
	CredentialsFile          string
	ImpersonateSA            string
	ImpersonateDelegates     string
	ImpersonateTokenLifetime string
	WIFAudience              string
}

// GCPAuthConfigFromEnv builds a GCPAuthConfig from environment variables.
func GCPAuthConfigFromEnv() GCPAuthConfig {
	return GCPAuthConfig{
		CredentialsFile:          firstNonEmptyEnv("CEREBRO_GCP_CREDENTIALS_FILE"),
		ImpersonateSA:            firstNonEmptyEnv("CEREBRO_GCP_IMPERSONATE_SERVICE_ACCOUNT"),
		ImpersonateDelegates:     firstNonEmptyEnv("CEREBRO_GCP_IMPERSONATE_DELEGATES"),
		ImpersonateTokenLifetime: firstNonEmptyEnv("CEREBRO_GCP_IMPERSONATE_TOKEN_LIFETIME_SECONDS"),
		WIFAudience:              firstNonEmptyEnv("CEREBRO_GCP_WIF_AUDIENCE"),
	}
}

// GCPAuthConfigFromFlags builds a GCPAuthConfig from CLI flag values, falling
// back to env vars for WIF-specific settings that have no CLI flag.
func GCPAuthConfigFromFlags() GCPAuthConfig {
	return GCPAuthConfig{
		CredentialsFile:          syncGCPCredentialsFile,
		ImpersonateSA:            syncGCPImpersonateSA,
		ImpersonateDelegates:     syncGCPImpersonateDel,
		ImpersonateTokenLifetime: syncGCPImpersonateTTL,
		WIFAudience:              firstNonEmptyEnv("CEREBRO_GCP_WIF_AUDIENCE"),
	}
}

// ApplyGCPAuth configures GCP credentials for the process via
// GOOGLE_APPLICATION_CREDENTIALS and returns a cleanup function.
//
// Resolution order:
//  1. Explicit credentials file only (no impersonation, no WIF).
//  2. Credentials file + impersonation SA -> impersonated_service_account temp file.
//  3. WIF audience set (no credentials file) -> external_account temp file.
//     If running on AWS (e.g. ECS) with no explicit key/secret, the AWS default
//     credential chain is materialised into env vars so the Google
//     external_account flow can sign STS requests.
//  4. No overrides -> noop (ADC passthrough).
func ApplyGCPAuth(ctx context.Context, cfg GCPAuthConfig) (cleanup func(), err error) {
	envSnapshots := make(map[string]envSnapshot)
	var tempFiles []string

	cleanup = func() {
		for _, f := range tempFiles {
			_ = os.Remove(f)
		}
		restoreEnvSnapshot(envSnapshots)
	}

	credentialsFile := strings.TrimSpace(cfg.CredentialsFile)
	impersonateSA := strings.TrimSpace(cfg.ImpersonateSA)
	delegates := parseCommaSeparatedValues(cfg.ImpersonateDelegates)
	tokenLifetimeSeconds, err := parseBoundedPositiveIntDirective(cfg.ImpersonateTokenLifetime, "--gcp-impersonate-token-lifetime-seconds", 600, 43200)
	if err != nil {
		return cleanup, err
	}
	wifAudience := strings.TrimSpace(cfg.WIFAudience)

	if impersonateSA == "" {
		if len(delegates) > 0 {
			return cleanup, fmt.Errorf("--gcp-impersonate-delegates requires --gcp-impersonate-service-account")
		}
		if tokenLifetimeSeconds > 0 {
			return cleanup, fmt.Errorf("--gcp-impersonate-token-lifetime-seconds requires --gcp-impersonate-service-account")
		}
	}

	// ------ case 1/2: explicit credentials file ------
	if credentialsFile != "" {
		if err := validateReadableFile(credentialsFile, "gcp credentials file"); err != nil {
			return cleanup, err
		}

		if impersonateSA == "" {
			if err := setEnvWithSnapshot(envSnapshots, "GOOGLE_APPLICATION_CREDENTIALS", credentialsFile); err != nil {
				return cleanup, fmt.Errorf("set GOOGLE_APPLICATION_CREDENTIALS: %w", err)
			}
			return cleanup, nil
		}

		// Impersonation with explicit source credentials.
		tmpPath, err := writeImpersonationCredentials(credentialsFile, impersonateSA, delegates, tokenLifetimeSeconds)
		if err != nil {
			return cleanup, err
		}
		tempFiles = append(tempFiles, tmpPath)
		if err := setEnvWithSnapshot(envSnapshots, "GOOGLE_APPLICATION_CREDENTIALS", tmpPath); err != nil {
			return cleanup, fmt.Errorf("set GOOGLE_APPLICATION_CREDENTIALS: %w", err)
		}
		return cleanup, nil
	}

	// ------ case 3: WIF mode (no explicit credentials file) ------
	if wifAudience != "" {
		if impersonateSA == "" {
			impersonateSA = firstNonEmptyEnv("CEREBRO_GCP_IMPERSONATE_SERVICE_ACCOUNT")
		}

		if err := ensureAWSEnvCredentials(ctx, envSnapshots); err != nil {
			return cleanup, fmt.Errorf("materialise AWS credentials for WIF: %w", err)
		}

		tmpPath, err := writeWIFExternalAccountCredentials(wifAudience, impersonateSA, delegates)
		if err != nil {
			return cleanup, err
		}
		tempFiles = append(tempFiles, tmpPath)
		if err := setEnvWithSnapshot(envSnapshots, "GOOGLE_APPLICATION_CREDENTIALS", tmpPath); err != nil {
			return cleanup, fmt.Errorf("set GOOGLE_APPLICATION_CREDENTIALS: %w", err)
		}
		return cleanup, nil
	}

	// ------ case 2b: impersonation via ADC (no credentials file, no WIF) ------
	if impersonateSA != "" {
		sourcePath, err := resolveGCPSourceCredentialsPath("")
		if err != nil {
			return cleanup, err
		}
		tmpPath, err := writeImpersonationCredentials(sourcePath, impersonateSA, delegates, tokenLifetimeSeconds)
		if err != nil {
			return cleanup, err
		}
		tempFiles = append(tempFiles, tmpPath)
		if err := setEnvWithSnapshot(envSnapshots, "GOOGLE_APPLICATION_CREDENTIALS", tmpPath); err != nil {
			return cleanup, fmt.Errorf("set GOOGLE_APPLICATION_CREDENTIALS: %w", err)
		}
		return cleanup, nil
	}

	// ------ case 4: noop ------
	return cleanup, nil
}

// ensureAWSEnvCredentials checks whether AWS_ACCESS_KEY_ID and
// AWS_SECRET_ACCESS_KEY are already present. If not, it loads credentials from
// the AWS default provider chain (instance role, ECS task role, etc.) and
// sets them as env vars (snapshotted for cleanup).
func ensureAWSEnvCredentials(ctx context.Context, snapshots map[string]envSnapshot) error {
	if os.Getenv("AWS_ACCESS_KEY_ID") != "" && os.Getenv("AWS_SECRET_ACCESS_KEY") != "" {
		return nil
	}

	slog.Info("WIF: resolving AWS credentials from default provider chain for STS signing")
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return fmt.Errorf("load AWS default config: %w", err)
	}

	creds, err := awsCfg.Credentials.Retrieve(ctx)
	if err != nil {
		return fmt.Errorf("retrieve AWS credentials: %w", err)
	}

	if err := setEnvWithSnapshot(snapshots, "AWS_ACCESS_KEY_ID", creds.AccessKeyID); err != nil {
		return err
	}
	if err := setEnvWithSnapshot(snapshots, "AWS_SECRET_ACCESS_KEY", creds.SecretAccessKey); err != nil {
		return err
	}
	if creds.SessionToken != "" {
		if err := setEnvWithSnapshot(snapshots, "AWS_SESSION_TOKEN", creds.SessionToken); err != nil {
			return err
		}
	}
	if awsCfg.Region != "" {
		if err := setEnvWithSnapshot(snapshots, "AWS_REGION", awsCfg.Region); err != nil {
			return err
		}
	}

	return nil
}

// writeWIFExternalAccountCredentials creates a temporary external_account JSON
// that the Google auth library reads to perform AWS-based WIF token exchange.
func writeWIFExternalAccountCredentials(audience, impersonateSA string, delegates []string) (string, error) {
	payload := map[string]interface{}{
		"type":               "external_account",
		"audience":           audience,
		"subject_token_type": "urn:ietf:params:aws:token-type:aws4_request",
		"token_url":          "https://sts.googleapis.com/v1/token",
		"credential_source": map[string]interface{}{
			"environment_id":                 "aws1",
			"region_url":                     "http://169.254.169.254/latest/meta-data/placement/availability-zone",
			"url":                            "http://169.254.169.254/latest/meta-data/iam/security-credentials",
			"regional_cred_verification_url": "https://sts.{region}.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15",
		},
	}

	if impersonateSA != "" {
		payload["service_account_impersonation_url"] = fmt.Sprintf(
			"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateAccessToken",
			url.PathEscape(impersonateSA),
		)
	}
	if len(delegates) > 0 {
		payload["service_account_impersonation"] = map[string]interface{}{
			"delegates": delegates,
		}
	}

	return writeTempCredentialsJSON(payload, "cerebro-gcp-wif-*.json")
}

// writeImpersonationCredentials creates a temporary impersonated_service_account
// JSON wrapping the given source credentials file.
func writeImpersonationCredentials(sourcePath, impersonateSA string, delegates []string, tokenLifetimeSeconds int) (string, error) {
	// #nosec G304 -- path is resolved from CLI credentials configuration
	sourceData, err := os.ReadFile(sourcePath)
	if err != nil {
		return "", fmt.Errorf("read GCP source credentials %q: %w", sourcePath, err)
	}

	var sourceCreds map[string]interface{}
	if err := json.Unmarshal(sourceData, &sourceCreds); err != nil {
		return "", fmt.Errorf("parse GCP source credentials %q: %w", sourcePath, err)
	}
	if len(sourceCreds) == 0 {
		return "", fmt.Errorf("GCP source credentials %q are empty", sourcePath)
	}

	impersonationURL := fmt.Sprintf(
		"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateAccessToken",
		url.PathEscape(impersonateSA),
	)
	payload := map[string]interface{}{
		"type":                              "impersonated_service_account",
		"service_account_impersonation_url": impersonationURL,
		"source_credentials":                sourceCreds,
	}
	if tokenLifetimeSeconds > 0 {
		payload["token_lifetime_seconds"] = tokenLifetimeSeconds
	}
	if len(delegates) > 0 {
		payload["delegates"] = delegates
	}

	return writeTempCredentialsJSON(payload, "cerebro-gcp-impersonated-*.json")
}

func writeTempCredentialsJSON(payload map[string]interface{}, pattern string) (string, error) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal GCP credentials: %w", err)
	}

	tmpFile, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", fmt.Errorf("create temporary GCP credentials file: %w", err)
	}
	path := tmpFile.Name()

	if _, err := tmpFile.Write(encoded); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(path)
		return "", fmt.Errorf("write temporary GCP credentials file: %w", err)
	}
	if err := tmpFile.Chmod(0o600); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(path)
		return "", fmt.Errorf("set permissions on temporary GCP credentials file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("close temporary GCP credentials file: %w", err)
	}

	return path, nil
}
