package mcpoauth

type Identity struct {
	email         string
	Email         string
	EmailVerified bool
	subject       string
}

type VerifiedEmail struct {
	value string
}

func NewVerifiedEmail(email string, verified bool) (VerifiedEmail, bool) {
	if !verified || email == "" {
		return VerifiedEmail{}, false
	}
	return VerifiedEmail{value: email}, true
}

func (identity Identity) VerifiedEmail() (string, bool) {
	if identity.email == "" {
		return "", false
	}
	return identity.email, true
}

func (identity Identity) ContactEmail() string {
	return identity.email
}

func (identity Identity) PrincipalSubject() string {
	return identity.subject
}

func subject(identity Identity) string {
	return identity.PrincipalSubject()
}

func contact(identity Identity) string {
	return identity.ContactEmail()
}

func directUnexportedEmail(identity Identity) string {
	return identity.email // want "direct mcpoauth.Identity email field read bypasses verified-email authority boundary"
}

func directExportedEmail(identity Identity) string {
	return identity.Email // want "direct mcpoauth.Identity email field read bypasses verified-email authority boundary"
}

func directEmailVerified(identity Identity) bool {
	return identity.EmailVerified // want "direct mcpoauth.Identity email field read bypasses verified-email authority boundary"
}

func directVerifiedEmailLiteral(email string) VerifiedEmail {
	return VerifiedEmail{value: email} // want "direct mcpoauth.VerifiedEmail construction bypasses email verification"
}
