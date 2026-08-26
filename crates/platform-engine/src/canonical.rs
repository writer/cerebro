use cerebro_platform_sdk::{ContentDigest, SdkError};
use serde::Serialize;

pub(crate) fn digest<T: Serialize>(value: &T) -> Result<ContentDigest, SdkError> {
    serde_json::to_vec(value)
        .map(ContentDigest::of_bytes)
        .map_err(|error| SdkError::Backend(format!("canonical serialization failed: {error}")))
}

#[cfg(test)]
mod tests {
    use super::digest;

    #[test]
    fn digest_is_deterministic_and_sensitive_to_serialized_values() {
        let first = digest(&("field", 1_u8)).unwrap();
        let repeat = digest(&("field", 1_u8)).unwrap();
        let changed = digest(&("field", 2_u8)).unwrap();

        assert_eq!(first, repeat);
        assert_ne!(first, changed);
    }
}
