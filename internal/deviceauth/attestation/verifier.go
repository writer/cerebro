package attestation

import (
	"context"
	"errors"
	"strings"
)

// Result is the outcome of a successful attestation verification.
type Result struct {
	// AssuranceLevel is "hardware" when the device-bound key was produced
	// by a hardware root of trust (Secure Enclave, TPM 2.0). It is
	// "software" when the agent is running on an unattested host (Linux
	// today; Phase-3 may add software fallback policy).
	AssuranceLevel string
	// PublicKey is the DER-encoded SubjectPublicKeyInfo of the device-bound
	// key. The Service binds this to the refresh-token row so subsequent
	// refreshes can require a DPoP proof signed by the same key (RFC 9449).
	PublicKey []byte
	// KeyID is a stable identifier for the device-bound key. For App Attest
	// this is the credId from authData; for TPM it is SHA-256 of the EK
	// public key.
	KeyID string
	// Vendor identifies the attestation backend that produced the result
	// ("apple-appattest" or "tpm-2.0").
	Vendor string
	// Diagnostics carries verifier-specific provenance fields the audit log
	// can persist (cert subject, EK manufacturer, etc.). Values are
	// considered non-secret.
	Diagnostics map[string]string
}

// Input is the per-attestation context the Service supplies to the verifier.
type Input struct {
	// HardwareUUID is the UUID the agent claimed in its enroll request. The
	// verifier uses this only as a nonce-binding input; trust comes from
	// the attestation cert chain.
	HardwareUUID string
	// ClientDataHash is the SHA-256 of the request the agent signed. For
	// App Attest this is the bootstrap-token hash bound into the receipt.
	ClientDataHash [32]byte
	// Format is the value of the os_type field from the enroll request
	// ("darwin", "windows", "linux"). The dispatch [Registry] uses this.
	Format string
	// Statement is the raw, base64-encoded attestation statement the agent
	// posted (the CBOR attestationObject for App Attest; the AIK quote +
	// EK chain bundle for TPM).
	Statement string
}

// Verifier verifies a single attestation backend.
type Verifier interface {
	// Format returns the unique short name of the attestation format
	// ("apple-appattest", "tpm-2.0"). The Registry dispatches on this.
	Format() string
	// Verify validates the supplied attestation and returns a Result on
	// success or a typed error on failure. Implementations MUST be safe
	// to call concurrently.
	Verify(ctx context.Context, in Input) (*Result, error)
}

// Registry dispatches attestation verification by format.
type Registry struct {
	verifiers map[string]Verifier
	required  bool
}

// NewRegistry builds a registry. When required is true, an enroll request
// missing an attestation statement fails with ErrAttestationRequired; when
// false, the absence of attestation just produces a software-assurance
// Result with no public key (the Service will not bind a DPoP key).
func NewRegistry(required bool, verifiers ...Verifier) *Registry {
	r := &Registry{verifiers: make(map[string]Verifier, len(verifiers)), required: required}
	for _, v := range verifiers {
		if v == nil {
			continue
		}
		r.verifiers[strings.ToLower(v.Format())] = v
	}
	return r
}

// Required reports whether the registry has been configured to require
// attestation on enroll.
func (r *Registry) Required() bool { return r.required }

// Verify dispatches to the verifier whose Format matches the format detected
// from in.Format / in.Statement. When in.Statement is empty and the registry
// is not required, it returns a software-assurance result so the caller can
// proceed without a device-bound key.
func (r *Registry) Verify(ctx context.Context, in Input) (*Result, error) {
	if strings.TrimSpace(in.Statement) == "" {
		if r.required {
			return nil, ErrAttestationRequired
		}
		return &Result{AssuranceLevel: "software", Vendor: "none", Diagnostics: map[string]string{"reason": "no statement provided"}}, nil
	}
	format := detectFormat(in)
	v, ok := r.verifiers[format]
	if !ok {
		return nil, ErrUnsupportedFormat
	}
	res, err := v.Verify(ctx, in)
	if err != nil {
		return nil, err
	}
	if res != nil && res.Vendor == "" {
		res.Vendor = format
	}
	return res, nil
}

// detectFormat picks an attestation backend based on the os_type field. We
// could also peek at the leading CBOR/ASN.1 bytes to disambiguate, but the
// agent always knows its own platform and gives us the hint cheaply.
func detectFormat(in Input) string {
	switch strings.ToLower(in.Format) {
	case "darwin", "ios", "macos", "apple":
		return FormatAppleAppAttest
	case "windows", "win32":
		return FormatTPM2
	default:
		return strings.ToLower(in.Format)
	}
}

// Format constants.
const (
	FormatAppleAppAttest = "apple-appattest"
	FormatTPM2           = "tpm-2.0"
)

// Typed errors.
var (
	ErrAttestationRequired = errors.New("attestation: attestation is required for enrollment")
	ErrUnsupportedFormat   = errors.New("attestation: unsupported attestation format")
	ErrInvalidStatement    = errors.New("attestation: attestation statement is malformed")
	ErrChainInvalid        = errors.New("attestation: certificate chain is invalid")
	ErrNonceMismatch       = errors.New("attestation: nonce extension does not match expected client data")
	ErrKeyIDMismatch       = errors.New("attestation: derived key id does not match credId")
	ErrUnsupportedVendor   = errors.New("attestation: tpm vendor not in trust pool")
)
