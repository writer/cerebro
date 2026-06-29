package mcpoauth

import "context"

type OIDCProvider interface {
	AuthorizationEndpoint(context.Context) (string, error)
	ExchangeCode(context.Context, string, string) (Identity, error)
}

type Identity struct {
	Subject string
	Email   string
	Name    string
	Groups  []string
}
