package deviceauth

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
)

// JWKSDocument is the JSON shape served at /.well-known/device-jwks.json.
// The format matches RFC 7517 §4 with the OKP/Ed25519 conventions of RFC
// 8037: kty=OKP, crv=Ed25519, x is the base64url-encoded public key.
type JWKSDocument struct {
	Keys []JWK `json:"keys"`
}

// JWK is one entry in [JWKSDocument].
type JWK struct {
	KTY string `json:"kty"`
	CRV string `json:"crv"`
	KID string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	X   string `json:"x"`
}

// EncodeJWKS converts a [KeySet] into a publishable JWKS document.
func EncodeJWKS(keys *KeySet) JWKSDocument {
	if keys == nil {
		return JWKSDocument{}
	}
	out := JWKSDocument{Keys: make([]JWK, 0, len(keys.Keys))}
	for _, key := range keys.Keys {
		if len(key.Public) != ed25519.PublicKeySize {
			continue
		}
		out.Keys = append(out.Keys, JWK{
			KTY: "OKP",
			CRV: "Ed25519",
			KID: key.KID,
			Use: "sig",
			Alg: "EdDSA",
			X:   base64.RawURLEncoding.EncodeToString(key.Public),
		})
	}
	return out
}

// MarshalJSON prevents accidental serialization of SigningKey.Private by
// exposing KeySet through the same public JWKS document as the HTTP endpoint.
func (ks *KeySet) MarshalJSON() ([]byte, error) {
	return json.Marshal(EncodeJWKS(ks))
}
