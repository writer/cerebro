use super::*;
use serde_json::{Value, json};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

const TENANT_ID: &str = "tenant";
const ACCOUNT_SID: &str = "AC123";
const OBSERVED_AT: &str = "2026-06-02T03:04:05.123456789+01:00";
const ACCOUNTS_FIXTURE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../sources/twilio/testdata/read_accounts.json"
));

fn observed_at() -> OffsetDateTime {
    OffsetDateTime::parse(OBSERVED_AT, &Rfc3339).unwrap()
}

fn kernel(family: TwilioFamily) -> TwilioKernel {
    TwilioKernel::new(
        None,
        TENANT_ID,
        family,
        TwilioFilters {
            account_sid: (family == TwilioFamily::Keys).then(|| ACCOUNT_SID.to_owned()),
        },
        None,
    )
    .unwrap()
}

mod accounts;
mod audit_events;
mod failure;
mod keys;
mod request;
