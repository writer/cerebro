// Package attestation verifies the device-bound proofs presented at SeCheck
// agent enrollment time. It is the hardware-backed layer on top of
// device-auth enrollment.
//
// Two backends are provided:
//
//   - Apple App Attest (apple.go): macOS / iOS Secure Enclave-backed
//     attestation following Apple's "Validating Apps That Connect to Your
//     Server" guidance. Apple's deterministic-CBOR attestation object is
//     decoded inline (no third-party CBOR dep), the certificate chain is
//     validated against the embedded Apple App Attestation Root CA, and the
//     nonce extension (1.2.840.113635.100.8.2) is checked against
//     SHA256(authData || clientDataHash) per Apple's protocol.
//
//   - Windows TPM 2.0 (tpm.go): EK certificate chain verification against
//     vendor TPM CA roots configured at startup, plus AIK quote signature
//     validation. Vendor roots are not embedded (they ship from the relevant
//     TPM vendors and rotate); the verifier accepts a *x509.CertPool injected
//     by the bootstrap binary.
//
// The [Verifier] interface lets the deviceauth.Service stay platform-agnostic.
// The dispatch [Registry] picks the verifier based on the os_type field of
// the enroll request.
package attestation
