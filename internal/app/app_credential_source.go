package app

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/secretsource"
)

type credentialSourceSettings struct {
	Kind           string
	FileDir        string
	VaultAddress   string
	VaultToken     string
	VaultNamespace string
	VaultPath      string
	VaultKVVersion int
}

func loadCredentialSourceSettings() credentialSourceSettings {
	return credentialSourceSettings{
		Kind:           strings.ToLower(strings.TrimSpace(bootstrapConfigValue("CEREBRO_CREDENTIAL_SOURCE", secretsource.KindEnv))),
		FileDir:        bootstrapConfigValue("CEREBRO_CREDENTIAL_FILE_DIR", ""),
		VaultAddress:   bootstrapConfigValue("CEREBRO_CREDENTIAL_VAULT_ADDRESS", ""),
		VaultToken:     bootstrapConfigValue("CEREBRO_CREDENTIAL_VAULT_TOKEN", ""),
		VaultNamespace: bootstrapConfigValue("CEREBRO_CREDENTIAL_VAULT_NAMESPACE", ""),
		VaultPath:      bootstrapConfigValue("CEREBRO_CREDENTIAL_VAULT_PATH", ""),
		VaultKVVersion: bootstrapConfigInt("CEREBRO_CREDENTIAL_VAULT_KV_VERSION", 2),
	}
}

func newCredentialConfigSource(settings credentialSourceSettings) (secretsource.Source, error) {
	if settings.Kind == "" {
		settings.Kind = secretsource.KindEnv
	}
	if err := validateCredentialSourceSettings(settings); err != nil {
		return nil, err
	}
	return secretsource.New(secretsource.Config{
		Kind:           settings.Kind,
		FileDir:        settings.FileDir,
		VaultAddress:   settings.VaultAddress,
		VaultToken:     settings.VaultToken,
		VaultNamespace: settings.VaultNamespace,
		VaultPath:      settings.VaultPath,
		VaultKVVersion: settings.VaultKVVersion,
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	})
}

func validateCredentialSourceSettings(settings credentialSourceSettings) error {
	if strings.EqualFold(strings.TrimSpace(settings.Kind), secretsource.KindVault) && !credentialVaultAddressAllowed(settings.VaultAddress) {
		return fmt.Errorf("CEREBRO_CREDENTIAL_VAULT_ADDRESS must use https unless it targets localhost or a loopback address")
	}
	return nil
}

func credentialVaultAddressAllowed(raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return true
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(parsed.Scheme)) {
	case "https":
		return parsed.Hostname() != ""
	case "http":
		host := strings.TrimSpace(parsed.Hostname())
		if host == "localhost" {
			return true
		}
		ip := net.ParseIP(host)
		return ip != nil && ip.IsLoopback()
	default:
		return false
	}
}
