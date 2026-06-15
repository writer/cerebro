package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

const defaultDeviceAuthRefreshTTL = 7 * 24 * time.Hour

func loadDeviceAuthConfig() (DeviceAuthConfig, error) {
	enabled, err := parseBoolEnv("CEREBRO_DEVICE_AUTH_ENABLED")
	if err != nil {
		return DeviceAuthConfig{}, err
	}
	cfg := DeviceAuthConfig{
		Enabled:    enabled,
		Issuer:     strings.TrimSpace(os.Getenv("CEREBRO_DEVICE_AUTH_ISSUER")),
		Audience:   strings.TrimSpace(os.Getenv("CEREBRO_DEVICE_AUTH_AUDIENCE")),
		CurrentKID: strings.TrimSpace(os.Getenv("CEREBRO_DEVICE_AUTH_CURRENT_KID")),
	}
	if cfg.Issuer == "" {
		cfg.Issuer = "cerebro"
	}
	if cfg.Audience == "" {
		cfg.Audience = "cerebro-device"
	}
	if cfg.AccessTTL, err = parseDurationEnv("CEREBRO_DEVICE_AUTH_ACCESS_TTL", 10*time.Minute); err != nil {
		return DeviceAuthConfig{}, err
	}
	if cfg.RefreshTTL, err = parseDurationEnv("CEREBRO_DEVICE_AUTH_REFRESH_TTL", defaultDeviceAuthRefreshTTL); err != nil {
		return DeviceAuthConfig{}, err
	}
	if cfg.BootstrapTokenTTL, err = parseDurationEnv("CEREBRO_DEVICE_AUTH_BOOTSTRAP_TOKEN_TTL", 24*time.Hour); err != nil {
		return DeviceAuthConfig{}, err
	}
	if cfg.IdempotencyTTL, err = parseDurationEnv("CEREBRO_DEVICE_AUTH_IDEMPOTENCY_TTL", 24*time.Hour); err != nil {
		return DeviceAuthConfig{}, err
	}
	if cfg.ClockSkew, err = parseDurationEnv("CEREBRO_DEVICE_AUTH_CLOCK_SKEW", time.Minute); err != nil {
		return DeviceAuthConfig{}, err
	}
	if cfg.EnrollPerIPRatePerSecond, err = parseFloatEnv("CEREBRO_DEVICE_AUTH_ENROLL_RPS", 0.2); err != nil {
		return DeviceAuthConfig{}, err
	}
	enrollBurst, err := parseIntEnv("CEREBRO_DEVICE_AUTH_ENROLL_BURST", 3)
	if err != nil {
		return DeviceAuthConfig{}, err
	}
	cfg.EnrollPerIPBurst = enrollBurst
	if cfg.TokenPerDeviceRatePerSecond, err = parseFloatEnv("CEREBRO_DEVICE_AUTH_TOKEN_RPS", 1); err != nil {
		return DeviceAuthConfig{}, err
	}
	tokenBurst, err := parseIntEnv("CEREBRO_DEVICE_AUTH_TOKEN_BURST", 5)
	if err != nil {
		return DeviceAuthConfig{}, err
	}
	cfg.TokenPerDeviceBurst = tokenBurst
	if cfg.DPoPProofTTL, err = parseDurationEnv("CEREBRO_DEVICE_AUTH_DPOP_PROOF_TTL", 60*time.Second); err != nil {
		return DeviceAuthConfig{}, err
	}
	if cfg.ReplicaCount, err = loadDeviceAuthReplicaCount(); err != nil {
		return DeviceAuthConfig{}, err
	}
	if cfg.RiskElevatedThreshold, err = parseIntEnv("CEREBRO_DEVICE_AUTH_RISK_ELEVATED", 30); err != nil {
		return DeviceAuthConfig{}, err
	}
	if cfg.RiskHighThreshold, err = parseIntEnv("CEREBRO_DEVICE_AUTH_RISK_HIGH", 70); err != nil {
		return DeviceAuthConfig{}, err
	}
	required, err := parseBoolEnv("CEREBRO_DEVICE_AUTH_ATTESTATION_REQUIRED")
	if err != nil {
		return DeviceAuthConfig{}, err
	}
	cfg.Attestation = DeviceAuthAttestationConfig{
		Required: required,
		Apple: DeviceAuthAppleConfig{
			TeamID:    strings.TrimSpace(os.Getenv("CEREBRO_DEVICE_AUTH_APPLE_TEAM_ID")),
			BundleIDs: parseCommaList(os.Getenv("CEREBRO_DEVICE_AUTH_APPLE_BUNDLE_IDS")),
		},
	}
	if cfg.Attestation.Required && !deviceAuthHasAttestationVerifier(cfg.Attestation) {
		return DeviceAuthConfig{}, fmt.Errorf("CEREBRO_DEVICE_AUTH_ATTESTATION_REQUIRED=true requires a configured attestation verifier backend")
	}
	if cfg.Enabled && cfg.ReplicaCount > 1 {
		return DeviceAuthConfig{}, fmt.Errorf("CEREBRO_DEVICE_AUTH_REPLICA_COUNT=%d is unsupported with in-process DPoP replay protection; configure one replica or wire shared DPoP replay state", cfg.ReplicaCount)
	}
	signingKeysRaw, err := readConfigValue("CEREBRO_DEVICE_AUTH_SIGNING_KEYS_JSON")
	if err != nil {
		return DeviceAuthConfig{}, err
	}
	keys, err := parseDeviceAuthSigningKeys(signingKeysRaw)
	if err != nil {
		return DeviceAuthConfig{}, err
	}
	cfg.SigningKeys = keys
	if !cfg.Enabled && cfg.CurrentKID == "" && len(keys) > 0 {
		cfg.CurrentKID = keys[0].KID
	}
	if cfg.Enabled {
		if len(cfg.SigningKeys) == 0 {
			return DeviceAuthConfig{}, fmt.Errorf("CEREBRO_DEVICE_AUTH_SIGNING_KEYS_JSON is required when CEREBRO_DEVICE_AUTH_ENABLED=true")
		}
		if cfg.CurrentKID == "" {
			return DeviceAuthConfig{}, fmt.Errorf("CEREBRO_DEVICE_AUTH_CURRENT_KID is required when CEREBRO_DEVICE_AUTH_ENABLED=true")
		}
		if !deviceAuthHasKID(cfg.SigningKeys, cfg.CurrentKID) {
			return DeviceAuthConfig{}, fmt.Errorf("CEREBRO_DEVICE_AUTH_CURRENT_KID %q is not present in CEREBRO_DEVICE_AUTH_SIGNING_KEYS_JSON", cfg.CurrentKID)
		}
	}
	return cfg, nil
}

func loadDeviceAuthReplicaCount() (int, error) {
	deviceAuthReplicas, err := parseIntEnv("CEREBRO_DEVICE_AUTH_REPLICA_COUNT", 1)
	if err != nil {
		return 0, err
	}
	if deviceAuthReplicas <= 0 {
		return 0, fmt.Errorf("CEREBRO_DEVICE_AUTH_REPLICA_COUNT must be greater than zero")
	}
	replicas, err := parseIntEnv("CEREBRO_REPLICA_COUNT", 1)
	if err != nil {
		return 0, err
	}
	if replicas <= 0 {
		return 0, fmt.Errorf("CEREBRO_REPLICA_COUNT must be greater than zero")
	}
	if replicas > deviceAuthReplicas {
		return replicas, nil
	}
	return deviceAuthReplicas, nil
}

func parseDeviceAuthSigningKeys(raw string) ([]DeviceAuthSigningKey, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	var keys []DeviceAuthSigningKey
	if err := json.Unmarshal([]byte(raw), &keys); err != nil {
		return nil, fmt.Errorf("parse CEREBRO_DEVICE_AUTH_SIGNING_KEYS_JSON: %w", err)
	}
	for index := range keys {
		keys[index].KID = strings.TrimSpace(keys[index].KID)
		keys[index].PublicPEM = strings.TrimSpace(keys[index].PublicPEM)
		keys[index].PrivatePEM = strings.TrimSpace(keys[index].PrivatePEM)
		if keys[index].KID == "" {
			return nil, fmt.Errorf("CEREBRO_DEVICE_AUTH_SIGNING_KEYS_JSON[%d] requires kid", index)
		}
		if keys[index].PublicPEM == "" {
			return nil, fmt.Errorf("CEREBRO_DEVICE_AUTH_SIGNING_KEYS_JSON[%d] requires public_pem", index)
		}
	}
	return keys, nil
}

func deviceAuthHasKID(keys []DeviceAuthSigningKey, kid string) bool {
	for _, key := range keys {
		if key.KID == kid {
			return true
		}
	}
	return false
}

func deviceAuthHasAttestationVerifier(cfg DeviceAuthAttestationConfig) bool {
	return cfg.Apple.TeamID != "" && len(cfg.Apple.BundleIDs) > 0
}

func parseCommaList(raw string) []string {
	parts := strings.Split(strings.TrimSpace(raw), ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func parseDurationEnv(name string, defaultValue time.Duration) (time.Duration, error) {
	raw, ok := os.LookupEnv(name)
	if !ok || strings.TrimSpace(raw) == "" {
		return defaultValue, nil
	}
	value, err := time.ParseDuration(strings.TrimSpace(raw))
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", name, err)
	}
	if value <= 0 {
		return 0, fmt.Errorf("%s must be greater than zero", name)
	}
	return value, nil
}
