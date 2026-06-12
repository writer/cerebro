// Package deviceauth implements the SeCheck agent device-identity surface for
// the Cerebro bootstrap service.
//
// The package is intentionally narrow:
//
//   - [JWTIssuer] mints short-lived EdDSA (Ed25519) access tokens with a kid
//     header so the verifier can rotate signing keys without invalidating
//     in-flight tokens.
//   - [JWTVerifier] validates tokens against a [KeySet] and the configured
//     audience, issuer, and clock-skew budget.
//   - [Store] is the abstract persistence boundary. The Postgres driver lives
//     in internal/statestore/postgres so the package itself stays
//     dependency-light and unit-testable.
//
// The token format is a compact JWT (RFC 7519) signed with Ed25519 (RFC 8037).
// Cerebro chose Ed25519 over RS256 for smaller tokens, faster verify, and
// because the AWS KMS asymmetric sign API supports it directly.
//
// All token material is hashed at rest. Bootstrap tokens and refresh tokens
// are opaque random byte strings; only their SHA-256 digests are persisted.
//
// See docs/AUTH_TENANCY.md and docs/ENDPOINT_SECURITY_PLATFORM_INTEGRATION.md
// for the public auth and endpoint telemetry boundaries.
package deviceauth
