package googleworkspaceauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"

	"github.com/writer/cerebro/internal/sourcecdk"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/jwt"
)

const googleOAuthEndpoint = "https://oauth2.googleapis.com/" + "token"

var (
	workspaceReadScopes = []string{
		"https://www.googleapis.com/auth/admin.directory.user.readonly",
		"https://www.googleapis.com/auth/admin.directory.group.readonly",
		"https://www.googleapis.com/auth/admin.directory.group.member.readonly",
		"https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly",
		"https://www.googleapis.com/auth/admin.reports.audit.readonly",
	}
	tokenSources sync.Map
)

type Settings struct {
	Token               string
	ServiceAccountEmail string
	PrivateKey          string
	DelegatedAdminEmail string
	ClientID            string
	ClientSecret        string
	RefreshToken        string
}

func NewSettings(token, serviceAccountEmail, privateKey, delegatedAdminEmail, clientID, clientSecret, refreshToken string) Settings {
	return Settings{
		Token:               strings.TrimSpace(token),
		ServiceAccountEmail: strings.TrimSpace(serviceAccountEmail),
		PrivateKey:          strings.TrimSpace(privateKey),
		DelegatedAdminEmail: strings.TrimSpace(delegatedAdminEmail),
		ClientID:            strings.TrimSpace(clientID),
		ClientSecret:        strings.TrimSpace(clientSecret),
		RefreshToken:        strings.TrimSpace(refreshToken),
	}
}

func FromConfig(cfg sourcecdk.Config) Settings {
	return NewSettings(
		sourcecdk.ConfigValue(cfg, "token"),
		sourcecdk.ConfigValue(cfg, "service_account_email"),
		firstNonEmpty(sourcecdk.ConfigValue(cfg, "private_key"), sourcecdk.ConfigValue(cfg, "service_account_private_key")),
		firstNonEmpty(sourcecdk.ConfigValue(cfg, "delegated_admin_email"), sourcecdk.ConfigValue(cfg, "subject_email")),
		sourcecdk.ConfigValue(cfg, "client_id"),
		sourcecdk.ConfigValue(cfg, "client_secret"),
		sourcecdk.ConfigValue(cfg, "refresh_token"),
	)
}

func Validate(settings Settings) error {
	if strings.TrimSpace(settings.Token) != "" {
		return nil
	}
	if serviceAccountAuthConfigured(settings) || oauthRefreshAuthConfigured(settings) {
		return nil
	}
	return fmt.Errorf("google_workspace requires token, service account delegation (service_account_email, private_key, delegated_admin_email), or OAuth (client_id, client_secret, refresh_token)")
}

func BearerToken(settings Settings) (string, error) {
	if strings.TrimSpace(settings.Token) != "" {
		return strings.TrimSpace(settings.Token), nil
	}
	cacheKey := authCacheKey(settings)
	if cacheKey == "" {
		return "", fmt.Errorf("google_workspace auth is not configured")
	}
	source, err := cachedBearerTokenSource(cacheKey, settings)
	if err != nil {
		return "", err
	}
	token, err := source.Token()
	if err != nil {
		return "", fmt.Errorf("fetch google_workspace access token: %w", err)
	}
	if token == nil || strings.TrimSpace(token.AccessToken) == "" {
		return "", fmt.Errorf("fetch google_workspace access token: empty access token")
	}
	return strings.TrimSpace(token.AccessToken), nil
}

func serviceAccountAuthConfigured(settings Settings) bool {
	return strings.TrimSpace(settings.ServiceAccountEmail) != "" &&
		strings.TrimSpace(settings.PrivateKey) != "" &&
		strings.TrimSpace(settings.DelegatedAdminEmail) != ""
}

func oauthRefreshAuthConfigured(settings Settings) bool {
	return strings.TrimSpace(settings.ClientID) != "" &&
		strings.TrimSpace(settings.ClientSecret) != "" &&
		strings.TrimSpace(settings.RefreshToken) != ""
}

func tokenSource(ctx context.Context, settings Settings) (oauth2.TokenSource, error) {
	if serviceAccountAuthConfigured(settings) {
		return serviceAccountTokenSource(ctx, settings)
	}
	if oauthRefreshAuthConfigured(settings) {
		return oauthRefreshTokenSource(ctx, settings), nil
	}
	return nil, fmt.Errorf("google_workspace auth is not configured")
}

func cachedBearerTokenSource(cacheKey string, settings Settings) (oauth2.TokenSource, error) {
	return cachedTokenSource(cacheKey, func() (oauth2.TokenSource, error) {
		return tokenSource(context.Background(), settings)
	})
}

func cachedTokenSource(cacheKey string, factory func() (oauth2.TokenSource, error)) (oauth2.TokenSource, error) {
	if cached, ok := tokenSources.Load(cacheKey); ok {
		return cached.(oauth2.TokenSource), nil
	}
	source, err := factory()
	if err != nil {
		return nil, err
	}
	reuse := oauth2.ReuseTokenSource(nil, source)
	actual, _ := tokenSources.LoadOrStore(cacheKey, reuse)
	return actual.(oauth2.TokenSource), nil
}

func serviceAccountTokenSource(ctx context.Context, settings Settings) (oauth2.TokenSource, error) {
	privateKey := []byte(strings.TrimSpace(settings.PrivateKey))
	cfg := &jwt.Config{
		Email:      strings.TrimSpace(settings.ServiceAccountEmail),
		PrivateKey: privateKey,
		Scopes:     workspaceReadScopes,
		TokenURL:   googleOAuthEndpoint,
		Subject:    strings.TrimSpace(settings.DelegatedAdminEmail),
	}
	if cfg.Email == "" || len(privateKey) == 0 || cfg.Subject == "" {
		return nil, fmt.Errorf("google_workspace service account auth requires service_account_email, private_key, and delegated_admin_email")
	}
	return cfg.TokenSource(ctx), nil
}

func oauthRefreshTokenSource(ctx context.Context, settings Settings) oauth2.TokenSource {
	cfg := &oauth2.Config{
		ClientID:     strings.TrimSpace(settings.ClientID),
		ClientSecret: strings.TrimSpace(settings.ClientSecret),
		Endpoint:     google.Endpoint,
		Scopes:       workspaceReadScopes,
	}
	return cfg.TokenSource(ctx, &oauth2.Token{RefreshToken: strings.TrimSpace(settings.RefreshToken)})
}

func authCacheKey(settings Settings) string {
	switch {
	case serviceAccountAuthConfigured(settings):
		return "sa:" + authCacheDigest(settings.ServiceAccountEmail, settings.DelegatedAdminEmail, settings.PrivateKey)
	case oauthRefreshAuthConfigured(settings):
		return "oauth:" + authCacheDigest(settings.ClientID, settings.ClientSecret, settings.RefreshToken)
	default:
		return ""
	}
}

func authCacheDigest(values ...string) string {
	hash := sha256.New()
	for _, value := range values {
		hash.Write([]byte(strings.TrimSpace(value)))
		hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}
