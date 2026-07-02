package mcpoauth

import (
	"context"
	"strings"
)

type OIDCProvider interface {
	AuthorizationEndpoint(context.Context) (string, error)
	ExchangeCode(context.Context, string, string) (Identity, error)
}

type VerifiedEmail struct {
	value string
}

func NewVerifiedEmail(email string, verified bool) (VerifiedEmail, bool) {
	email = strings.TrimSpace(email)
	if !verified || email == "" {
		return VerifiedEmail{}, false
	}
	return VerifiedEmail{value: email}, true
}

func (email VerifiedEmail) String() string {
	return email.value
}

type Identity struct {
	subject string
	email   VerifiedEmail
	name    string
	groups  []string
}

func NewIdentity(subject string, email VerifiedEmail, name string, groups []string) Identity {
	return Identity{
		subject: strings.TrimSpace(subject),
		email:   email,
		name:    strings.TrimSpace(name),
		groups:  normalizeStrings(groups),
	}
}

func (identity Identity) PrincipalSubject() string {
	return identity.subject
}

func (identity Identity) VerifiedEmail() (string, bool) {
	email := identity.email.String()
	if email == "" {
		return "", false
	}
	return email, true
}

func (identity Identity) ContactEmail() string {
	return identity.email.String()
}

func (identity Identity) DisplayName() string {
	return identity.name
}

func (identity Identity) Groups() []string {
	return cloneStrings(identity.groups)
}
