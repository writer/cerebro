package mcpoauth

import "context"

type OIDCProvider interface {
	AuthorizationEndpoint(context.Context) (string, error)
	ExchangeCode(context.Context, string, string) (Identity, error)
}

type Identity struct {
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
	Groups        []string
}
