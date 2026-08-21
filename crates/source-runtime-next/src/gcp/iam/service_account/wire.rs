//! Typed provider response object.

use serde::Deserialize;

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub(super) struct ServiceAccountWire {
    pub(super) name: String,
    #[serde(rename = "projectId")]
    pub(super) _project_id: String,
    pub(super) unique_id: String,
    pub(super) email: String,
    pub(super) display_name: String,
    #[serde(rename = "description")]
    pub(super) _description: String,
    pub(super) disabled: bool,
    #[serde(rename = "oauth2ClientId")]
    pub(super) _oauth2_client_id: String,
}
