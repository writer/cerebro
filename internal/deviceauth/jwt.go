package deviceauth

import (
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// DeviceClaims holds JWT claims for device-issued access tokens.
type DeviceClaims struct {
	jwt.RegisteredClaims
	DeviceID     string   `json:"device_id"`
	HardwareUUID string   `json:"hardware_uuid,omitempty"`
	OrgID        string   `json:"org_id"`
	Kind         string   `json:"kind"`
	Scopes       []string `json:"scopes,omitempty"`
}

// DeviceJWTIssuer creates and validates device JWTs using HMAC-SHA256.
type DeviceJWTIssuer struct {
	signingKey []byte
	issuer     string
	audience   string
}

// NewDeviceJWTIssuer creates a new issuer. The signingKey must be kept secret
// and should come from environment configuration, never hard-coded.
func NewDeviceJWTIssuer(signingKey []byte, issuer, audience string) (*DeviceJWTIssuer, error) {
	if len(signingKey) == 0 {
		return nil, fmt.Errorf("device jwt signing key is required")
	}
	if strings.TrimSpace(issuer) == "" {
		issuer = "cerebro"
	}
	if strings.TrimSpace(audience) == "" {
		audience = "cerebro-device"
	}
	return &DeviceJWTIssuer{
		signingKey: signingKey,
		issuer:     issuer,
		audience:   audience,
	}, nil
}

// IssueAccessToken creates a short-lived (5 minute) HS256 JWT for a device.
func (j *DeviceJWTIssuer) IssueAccessToken(device DeviceRecord, scopes []string) (string, error) {
	now := time.Now().UTC()
	claims := DeviceClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    j.issuer,
			Audience:  jwt.ClaimStrings{j.audience},
			Subject:   "device:" + device.DeviceID,
			ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ID:        uuid.NewString(),
		},
		DeviceID:     device.DeviceID,
		HardwareUUID: device.HardwareUUID,
		OrgID:        device.OrgID,
		Kind:         "device_access",
		Scopes:       cloneScopes(scopes),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(j.signingKey)
	if err != nil {
		return "", fmt.Errorf("sign device access token: %w", err)
	}
	return signed, nil
}

// IssueRefreshToken creates a long-lived (30 day) refresh token and its
// corresponding store record. The raw token is returned to the caller while
// only its SHA-256 hash is stored.
func (j *DeviceJWTIssuer) IssueRefreshToken(device DeviceRecord, familyID string) (string, RefreshTokenRecord, error) {
	rawToken, err := generateSecureToken(32)
	if err != nil {
		return "", RefreshTokenRecord{}, fmt.Errorf("generate refresh token: %w", err)
	}
	if strings.TrimSpace(familyID) == "" {
		familyID = "fam-" + uuid.NewString()
	}

	now := time.Now().UTC()
	record := RefreshTokenRecord{
		TokenHash:  tokenHash(rawToken),
		DeviceID:   device.DeviceID,
		FamilyID:   familyID,
		Generation: 0,
		CreatedAt:  now,
		ExpiresAt:  now.Add(30 * 24 * time.Hour),
		Consumed:   false,
	}
	return rawToken, record, nil
}

// ValidateAccessToken parses and validates a device access JWT, checking
// signature, expiry, issuer, and audience.
func (j *DeviceJWTIssuer) ValidateAccessToken(tokenStr string) (*DeviceClaims, error) {
	claims := &DeviceClaims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return j.signingKey, nil
	},
		jwt.WithIssuer(j.issuer),
		jwt.WithAudience(j.audience),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, fmt.Errorf("validate device access token: %w", err)
	}
	if !token.Valid {
		return nil, fmt.Errorf("invalid device access token")
	}
	if claims.Kind != "device_access" {
		return nil, fmt.Errorf("invalid token kind: %s", claims.Kind)
	}
	return claims, nil
}
