use std::collections::BTreeMap;

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use base64::{Engine as _, engine::general_purpose};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::StoreError;

const SEALED_ALGORITHM: &str = "AES-256-GCM";
const MAX_SEALED_BYTES: usize = 1024 * 1024;
const MAX_CREDENTIAL_FIELDS: usize = 64;
const MAX_CREDENTIAL_FIELD_BYTES: usize = 128;
const MAX_CREDENTIAL_VALUE_BYTES: usize = 256 * 1024;

/// The compatibility vault key, normalized exactly like the Go runtime.
///
/// This type deliberately does not implement `Debug` or `Clone`, and its key
/// bytes are cleared when dropped.
pub(crate) struct ConnectorVaultKey {
    bytes: [u8; 32],
    key_id: String,
}

impl ConnectorVaultKey {
    pub(crate) fn parse(raw: &str) -> Result<Self, StoreError> {
        let raw = raw.trim();
        if raw.is_empty() {
            return Err(vault_error("connector credential vault key is required"));
        }
        let bytes = decode_exact_key(raw).unwrap_or_else(|| Sha256::digest(raw.as_bytes()).into());
        let digest = Sha256::digest(raw.as_bytes());
        let key_id = format!(
            "connector-vault-{}",
            digest[..8]
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        );
        Ok(Self { bytes, key_id })
    }

    pub(crate) fn open(
        &self,
        record: &CredentialVaultRecord,
    ) -> Result<CredentialFields, StoreError> {
        if record.key_id.trim() != self.key_id {
            return Err(vault_error("connector credential vault key is unavailable"));
        }
        if record.sealed.len() > MAX_SEALED_BYTES {
            return Err(vault_error("connector credential envelope is too large"));
        }
        let envelope: SealedCredential = serde_json::from_slice(&record.sealed)
            .map_err(|_| vault_error("connector credential envelope is invalid"))?;
        if envelope.algorithm != SEALED_ALGORITHM {
            return Err(vault_error(
                "connector credential envelope algorithm is unsupported",
            ));
        }
        let nonce = decode_bounded_base64(&envelope.nonce, 12, 12)?;
        let mut ciphertext = Zeroizing::new(decode_bounded_base64(
            &envelope.ciphertext,
            AES_256_GCM.tag_len(),
            MAX_SEALED_BYTES,
        )?);
        let unbound = UnboundKey::new(&AES_256_GCM, &self.bytes)
            .map_err(|_| vault_error("connector credential vault key is invalid"))?;
        let key = LessSafeKey::new(unbound);
        let nonce = Nonce::try_assume_unique_for_key(&nonce)
            .map_err(|_| vault_error("connector credential nonce is invalid"))?;
        let aad = credential_aad(record);
        let plaintext = key
            .open_in_place(nonce, Aad::from(aad), &mut ciphertext[..])
            .map_err(|_| vault_error("connector credential envelope authentication failed"))?;
        decode_fields(plaintext)
    }
}

impl Drop for ConnectorVaultKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

pub(crate) struct CredentialVaultRecord {
    pub(crate) id: String,
    pub(crate) tenant_id: String,
    pub(crate) source_id: String,
    pub(crate) runtime_id: String,
    pub(crate) key_id: String,
    pub(crate) sealed: Vec<u8>,
}

/// Decrypted fields clear their owned secret values when the resolution cache
/// leaves scope.
pub(crate) struct CredentialFields(BTreeMap<String, String>);

impl CredentialFields {
    pub(crate) fn get(&self, field: &str) -> Option<&str> {
        self.0.get(field).map(String::as_str)
    }
}

impl Drop for CredentialFields {
    fn drop(&mut self) {
        for value in self.0.values_mut() {
            value.zeroize();
        }
    }
}

#[derive(Deserialize)]
struct SealedCredential {
    algorithm: String,
    nonce: String,
    ciphertext: String,
}

#[derive(Deserialize)]
struct CredentialPlaintext {
    fields: BTreeMap<String, String>,
}

fn decode_exact_key(raw: &str) -> Option<[u8; 32]> {
    for engine in [
        &general_purpose::STANDARD,
        &general_purpose::STANDARD_NO_PAD,
    ] {
        if let Ok(decoded) = engine.decode(raw)
            && let Ok(key) = <[u8; 32]>::try_from(decoded.as_slice())
        {
            return Some(key);
        }
    }
    None
}

fn decode_bounded_base64(
    value: &str,
    minimum: usize,
    maximum: usize,
) -> Result<Vec<u8>, StoreError> {
    let value = value.trim();
    if value.len() > maximum.saturating_mul(2) {
        return Err(vault_error("connector credential envelope is invalid"));
    }
    let decoded = general_purpose::STANDARD
        .decode(value)
        .map_err(|_| vault_error("connector credential envelope is invalid"))?;
    if decoded.len() < minimum || decoded.len() > maximum {
        return Err(vault_error("connector credential envelope is invalid"));
    }
    Ok(decoded)
}

fn decode_fields(plaintext: &[u8]) -> Result<CredentialFields, StoreError> {
    let decoded: CredentialPlaintext = serde_json::from_slice(plaintext)
        .map_err(|_| vault_error("connector credential fields are invalid"))?;
    let fields = CredentialFields(decoded.fields);
    if fields.0.is_empty() || fields.0.len() > MAX_CREDENTIAL_FIELDS {
        return Err(vault_error("connector credential fields are invalid"));
    }
    for (field, value) in &fields.0 {
        if !valid_reference_part(field)
            || field.len() > MAX_CREDENTIAL_FIELD_BYTES
            || value.len() > MAX_CREDENTIAL_VALUE_BYTES
        {
            return Err(vault_error("connector credential fields are invalid"));
        }
    }
    Ok(fields)
}

fn credential_aad(record: &CredentialVaultRecord) -> Vec<u8> {
    [
        record.id.trim(),
        record.tenant_id.trim(),
        record.source_id.trim(),
        record.runtime_id.trim(),
        record.key_id.trim(),
    ]
    .join("\0")
    .into_bytes()
}

fn valid_reference_part(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn vault_error(message: &str) -> StoreError {
    StoreError::Conflict(message.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn go_compatible_vault_envelope_opens_and_is_scope_bound() {
        let key = ConnectorVaultKey::parse("test-vault-key").unwrap();
        let record = CredentialVaultRecord {
            id: "cred_vector".to_owned(),
            tenant_id: "tenant-a".to_owned(),
            source_id: "github".to_owned(),
            runtime_id: "runtime-a".to_owned(),
            key_id: key.key_id.clone(),
            sealed: include_bytes!("../testdata/go_connector_vault_vector.json").to_vec(),
        };
        let fields = key.open(&record).unwrap();
        assert_eq!(fields.get("token"), Some("secret-token"));

        let mut wrong_scope = record;
        wrong_scope.tenant_id = "tenant-b".to_owned();
        assert!(key.open(&wrong_scope).is_err());
    }

    #[test]
    fn envelope_errors_never_include_ciphertext_or_plaintext() {
        let key = ConnectorVaultKey::parse("test-vault-key").unwrap();
        let record = CredentialVaultRecord {
            id: "cred_vector".to_owned(),
            tenant_id: "tenant-a".to_owned(),
            source_id: "github".to_owned(),
            runtime_id: "runtime-a".to_owned(),
            key_id: key.key_id.clone(),
            sealed: br#"{"algorithm":"AES-256-GCM","nonce":"AAAAAAAAAAAAAAAA","ciphertext":"c2VjcmV0LXRva2Vu"}"#.to_vec(),
        };
        let error = match key.open(&record) {
            Ok(_) => panic!("malformed connector credential unexpectedly opened"),
            Err(error) => error.to_string(),
        };
        assert!(!error.contains("secret-token"));
        assert!(!error.contains("c2VjcmV0"));
    }
}
