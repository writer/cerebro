use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::MigratorError;

pub(crate) fn canonical_digest<T: Serialize>(value: &T) -> Result<String, MigratorError> {
    let canonical = serde_jcs::to_vec(value)
        .map_err(|error| MigratorError::Canonicalization(error.to_string()))?;
    Ok(bytes_digest(&canonical))
}

pub(crate) fn bytes_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(7 + digest.len() * 2);
    encoded.push_str("sha256:");
    append_hex(&mut encoded, digest.as_slice());
    encoded
}

fn append_hex(encoded: &mut String, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
}
