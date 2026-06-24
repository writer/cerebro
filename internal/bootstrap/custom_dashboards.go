package bootstrap

import (
	"context"
	"strings"
)

func customDashboardActorID(ctx context.Context) string {
	if auth, ok := ctx.Value(authContextKey{}).(authContext); ok {
		for _, value := range []string{auth.principal.Name, auth.principal.ClientID, auth.principal.DeviceID, auth.principal.CredentialID} {
			if trimmed := strings.TrimSpace(value); trimmed != "" {
				return trimmed
			}
		}
	}
	return "anonymous"
}
