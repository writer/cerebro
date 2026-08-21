use super::*;
use serde_json::{Value, json};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub(super) const DISCOVER_SERVICE_ACCOUNT_FIXTURE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../sources/gcp/testdata/discover_service_account.json"
));
pub(super) const READ_SERVICE_ACCOUNT_FIXTURE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../sources/gcp/testdata/read_service_account.json"
));
pub(super) const DISCOVER_SERVICE_ACCOUNT_KEY_FIXTURE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../sources/gcp/testdata/discover_service_account_key.json"
));
pub(super) const READ_SERVICE_ACCOUNT_KEY_FIXTURE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../sources/gcp/testdata/read_service_account_key.json"
));
pub(super) const SERVICE_ACCOUNT_EMAIL: &str = "sa@writer-prod.iam.gserviceaccount.com";
pub(super) const TENANT_ID: &str = "writer-prod";
pub(super) const OBSERVED_AT: &str = "2026-04-23T02:03:04.123456789+01:00";
pub(super) const SERVICE_ACCOUNT_NAME: &str =
    "projects/writer-prod/serviceAccounts/sa@writer-prod.iam.gserviceaccount.com";
pub(super) const SERVICE_ACCOUNT_RESPONSE: &[u8] = br#"{
        "accounts":[{
            "name":"projects/writer-prod/serviceAccounts/sa@writer-prod.iam.gserviceaccount.com",
            "email":"sa@writer-prod.iam.gserviceaccount.com",
            "uniqueId":"sa-1",
            "displayName":"Prod SA"
        }],
        "nextPageToken":"accounts-2"
    }"#;
pub(super) const SERVICE_ACCOUNT_KEY_RESPONSE: &[u8] = br#"{
        "keys":[{
            "name":"projects/writer-prod/serviceAccounts/sa@writer-prod.iam.gserviceaccount.com/keys/key-1",
            "keyType":"USER_MANAGED",
            "validAfterTime":"2026-04-23T00:00:00Z"
        }],
        "nextPageToken":"keys-2"
    }"#;

pub(super) fn observed_at() -> OffsetDateTime {
    OffsetDateTime::parse(OBSERVED_AT, &Rfc3339).unwrap()
}

pub(super) fn account_kernel() -> GcpIamKernel {
    GcpIamKernel::new(
        "https://iam.googleapis.com",
        TENANT_ID,
        "writer-prod",
        GcpIamFamily::ServiceAccount,
        GcpIamFilters::default(),
        None,
    )
    .unwrap()
}

pub(super) fn key_kernel() -> GcpIamKernel {
    GcpIamKernel::new(
        "https://iam.googleapis.com",
        TENANT_ID,
        "writer-prod",
        GcpIamFamily::ServiceAccountKey,
        GcpIamFilters {
            service_account_email: Some(SERVICE_ACCOUNT_EMAIL.to_owned()),
        },
        None,
    )
    .unwrap()
}

mod failure;
mod request;
mod service_account;
mod service_account_key;
