//! Typed provider response object.

use serde::Deserialize;

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub(super) struct ServiceAccountKeyWire {
    pub(super) name: String,
    #[serde(rename = "privateKeyType")]
    pub(super) _private_key_type: String,
    #[serde(rename = "keyAlgorithm")]
    pub(super) _key_algorithm: String,
    pub(super) valid_after_time: String,
    #[serde(rename = "validBeforeTime")]
    pub(super) _valid_before_time: String,
    #[serde(rename = "keyOrigin")]
    pub(super) _key_origin: String,
    #[serde(rename = "keyType")]
    pub(super) _key_type: String,
    pub(super) disabled: bool,
}
