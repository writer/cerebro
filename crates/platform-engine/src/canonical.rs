use cerebro_platform_sdk::{ContentDigest, SdkError};
use serde::Serialize;

pub(crate) fn digest<T: Serialize>(value: &T) -> Result<ContentDigest, SdkError> {
    serde_json::to_vec(value)
        .map(ContentDigest::of_bytes)
        .map_err(|error| SdkError::Backend(format!("canonical serialization failed: {error}")))
}
