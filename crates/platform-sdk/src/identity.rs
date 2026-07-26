use std::{fmt, fmt::Write as _};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::SdkError;

const MAX_ID_BYTES: usize = 256;

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct OpaqueId(String);

impl OpaqueId {
    pub fn parse(value: impl Into<String>) -> Result<Self, SdkError> {
        let value = value.into();
        if value.is_empty() {
            return Err(SdkError::Empty("platform id"));
        }
        if value.trim() != value
            || value.len() > MAX_ID_BYTES
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:/".contains(&byte))
        {
            return Err(SdkError::Invalid("platform id"));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for OpaqueId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

macro_rules! typed_id {
    ($name:ident) => {
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(OpaqueId);

        impl $name {
            pub fn parse(value: impl Into<String>) -> Result<Self, SdkError> {
                Ok(Self(OpaqueId::parse(value)?))
            }

            pub fn as_str(&self) -> &str {
                self.0.as_str()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, formatter)
            }
        }
    };
}

typed_id!(ActionOperationId);
typed_id!(AssertionDefinitionId);
typed_id!(IncidentSnapshotId);
typed_id!(PluginId);
typed_id!(SimulationId);
typed_id!(SubscriptionId);
typed_id!(ViewId);

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ContentDigest(String);

impl ContentDigest {
    pub fn parse(value: impl Into<String>) -> Result<Self, SdkError> {
        let value = value.into();
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(SdkError::Invalid("content digest"));
        }
        Ok(Self(value))
    }

    pub fn of_bytes(value: impl AsRef<[u8]>) -> Self {
        let digest = Sha256::digest(value.as_ref());
        let mut encoded = String::with_capacity(64);
        for byte in digest {
            write!(&mut encoded, "{byte:02x}").expect("writing to a string cannot fail");
        }
        Self(encoded)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ContentDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::{ContentDigest, OpaqueId};

    #[test]
    fn ids_reject_whitespace_and_unbounded_values() {
        assert!(OpaqueId::parse("valid-id").is_ok());
        assert!(OpaqueId::parse(" invalid").is_err());
        assert!(OpaqueId::parse("invalid?").is_err());
        assert!(OpaqueId::parse("x".repeat(257)).is_err());
    }

    #[test]
    fn content_digests_are_canonical_lowercase_sha256() {
        let digest = ContentDigest::of_bytes("cerebro");
        assert_eq!(digest.as_str().len(), 64);
        assert!(ContentDigest::parse(digest.to_string()).is_ok());
        assert!(ContentDigest::parse("A".repeat(64)).is_err());
    }
}
