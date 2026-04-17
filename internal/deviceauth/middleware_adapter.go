package deviceauth

// MiddlewareAdapter wraps DeviceJWTIssuer to satisfy the api.DeviceJWTValidator
// interface without creating an import cycle.
type MiddlewareAdapter struct {
	Issuer *DeviceJWTIssuer
}

// ValidateAccessToken validates a device JWT and returns the extracted claims
// as flat values compatible with the auth middleware.
func (a *MiddlewareAdapter) ValidateAccessToken(tokenStr string) (deviceID, hardwareUUID, orgID string, scopes []string, err error) {
	claims, err := a.Issuer.ValidateAccessToken(tokenStr)
	if err != nil {
		return "", "", "", nil, err
	}
	return claims.DeviceID, claims.HardwareUUID, claims.OrgID, claims.Scopes, nil
}
