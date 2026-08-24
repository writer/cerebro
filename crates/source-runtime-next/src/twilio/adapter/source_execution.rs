//! Canonical source-execution edge for Twilio accounts.
//!
//! This file intentionally defines no wire messages. It compiles against the
//! shared `source_execution` API and is selected only by the closed dispatcher.

use std::convert::TryFrom;

use serde_json::Value;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::source_execution::{
    SourceExecutionAdapter, SourceExecutionError, SourceExecutionPlanV1,
    SourceWorkerDecodeRequestV1, SourceWorkerDecodeResultV1, SourceWorkerExecutionContextV1,
    SourceWorkerHttpExecutionV2, SourceWorkerHttpRequestV1, SourceWorkerPlanEnvelopeV2,
    SourceWorkerPlanRequestV1, SourceWorkerRecordV1, canonical_http_execution_digest,
    canonical_plan_digest, canonical_request_intent_digest, canonical_result_digest,
    validate_and_deduplicate_records, validate_cursor, validate_execution_context,
    validate_runtime_metadata, validate_safe_receipt,
};

use super::{TwilioAccountsAdapter, TwilioAccountsAdapterError};
use crate::twilio::{TwilioError, TwilioFamily, normalize::event_id};

const PLAN_ID: &str = "source-plan-v1:twilio:accounts";
const EVENT_KIND: &str = "twilio.accounts";
const SCHEMA_REF: &str = "twilio/accounts/v1";
const RECORD_SELECTOR: &str = "data";
const ID_FIELD: &str = "id";
const REQUIRED_ATTRIBUTES: [&str; 3] = ["tenant_id", "source_event_id", "user_id"];
const REQUIRED_PAYLOAD_FIELDS: [&str; 1] = ["id"];

/// Registry value for the accounts-first Twilio source adapter.
pub(crate) static TWILIO_ACCOUNTS_SOURCE_EXECUTION_ADAPTER: TwilioAccountsSourceExecutionAdapter =
    TwilioAccountsSourceExecutionAdapter;

/// Stateless canonical edge. Trusted execution scope arrives on every call.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct TwilioAccountsSourceExecutionAdapter;

impl TwilioAccountsSourceExecutionAdapter {
    pub(crate) fn compiled_plan(&self) -> SourceExecutionPlanV1 {
        let mut plan = SourceExecutionPlanV1 {
            plan_id: PLAN_ID.to_owned(),
            source_id: TwilioAccountsAdapter::source_id().to_owned(),
            family_id: TwilioAccountsAdapter::family_id().to_owned(),
            provider_kernel: TwilioAccountsAdapter::provider_kernel().to_owned(),
            method: "GET".to_owned(),
            origin: TwilioAccountsAdapter::default_origin().to_owned(),
            path: TwilioAccountsAdapter::path().to_owned(),
            record_selector: RECORD_SELECTOR.to_owned(),
            id_field: ID_FIELD.to_owned(),
            singleton_fallback_id: String::new(),
            max_response_bytes: TwilioAccountsAdapter::max_response_bytes(),
            event_kind: EVENT_KIND.to_owned(),
            schema_ref: SCHEMA_REF.to_owned(),
            required_attributes: REQUIRED_ATTRIBUTES.map(str::to_owned).to_vec(),
            required_payload_fields: REQUIRED_PAYLOAD_FIELDS.map(str::to_owned).to_vec(),
            plan_digest_sha256: String::new(),
        };
        plan.plan_digest_sha256 = canonical_plan_digest(&plan);
        plan
    }
}

impl SourceExecutionAdapter for TwilioAccountsSourceExecutionAdapter {
    fn source_id(&self) -> &'static str {
        TwilioAccountsAdapter::source_id()
    }

    fn family_id(&self) -> &'static str {
        TwilioAccountsAdapter::family_id()
    }

    fn provider_kernel(&self) -> &'static str {
        TwilioAccountsAdapter::provider_kernel()
    }

    fn validate_record_identity(
        &self,
        context: &SourceWorkerExecutionContextV1,
        record: &SourceWorkerRecordV1,
    ) -> Result<(), SourceExecutionError> {
        let expected = event_id(
            &context.tenant_id,
            TwilioAccountsAdapter::default_origin(),
            TwilioAccountsAdapter::path(),
            TwilioFamily::Accounts,
            &record.provider_id,
        );
        if record.event_id != expected {
            return Err(SourceExecutionError::TenantMismatch);
        }
        Ok(())
    }

    fn plan(
        &self,
        request: &SourceWorkerPlanRequestV1,
    ) -> Result<SourceWorkerHttpRequestV1, SourceExecutionError> {
        let (plan, context) =
            validated_plan_context(request.plan.as_ref(), request.context.as_ref())?;
        let adapter = TwilioAccountsAdapter::new(&plan.origin, &context.tenant_id)
            .map_err(map_provider_error)?;
        let provider_request = adapter
            .plan(optional_cursor(&context.prior_cursor))
            .map_err(map_provider_error)?;
        if provider_request.url().path() != plan.path
            || provider_request.url().origin().unicode_serialization() != plan.origin
            || provider_request.authorization_scheme() != TwilioAccountsAdapter::credential_scheme()
        {
            return Err(SourceExecutionError::InvalidPlan);
        }

        let mut output = SourceWorkerHttpRequestV1 {
            plan_id: plan.plan_id.clone(),
            method: plan.method.clone(),
            url: provider_request.url().to_string(),
            accept: provider_request.accept().to_owned(),
            max_response_bytes: plan.max_response_bytes,
            plan_digest_sha256: plan.plan_digest_sha256.clone(),
            request_intent_digest: String::new(),
        };
        output.request_intent_digest = canonical_request_intent_digest(plan, context, &output);
        Ok(output)
    }

    fn plan_v2(
        &self,
        envelope: &SourceWorkerPlanEnvelopeV2,
    ) -> Result<SourceWorkerHttpExecutionV2, SourceExecutionError> {
        let request = envelope
            .request
            .as_ref()
            .ok_or(SourceExecutionError::InvalidPlan)?;
        let plan = request
            .plan
            .as_ref()
            .ok_or(SourceExecutionError::InvalidPlan)?;
        let context = request
            .context
            .as_ref()
            .ok_or(SourceExecutionError::MissingExecutionIdentity)?;
        let metadata = envelope
            .metadata
            .as_ref()
            .ok_or(SourceExecutionError::MissingExecutionIdentity)?;
        validate_runtime_metadata(metadata)?;
        let planned = self.plan(request)?;
        let mut execution = SourceWorkerHttpExecutionV2 {
            request: Some(planned),
            body: Vec::new(),
            declared_headers: Default::default(),
            execution_intent_digest_sha256: String::new(),
            credential_operation: TwilioAccountsAdapter::credential_operation().to_owned(),
            allowed_origin: plan.origin.clone(),
        };
        execution.execution_intent_digest_sha256 =
            canonical_http_execution_digest(plan, context, metadata, &execution);
        Ok(execution)
    }

    fn decode(
        &self,
        request: &SourceWorkerDecodeRequestV1,
    ) -> Result<SourceWorkerDecodeResultV1, SourceExecutionError> {
        let (plan, context) =
            validated_plan_context(request.plan.as_ref(), request.context.as_ref())?;
        if request.logical_page_id != context.logical_page_id
            || request.request_intent_digest.trim().is_empty()
        {
            return Err(SourceExecutionError::MissingExecutionIdentity);
        }
        let planned = <Self as SourceExecutionAdapter>::plan(
            self,
            &SourceWorkerPlanRequestV1 {
                plan: Some(plan.clone()),
                context: Some(context.clone()),
            },
        )?;
        if planned.request_intent_digest != request.request_intent_digest {
            return Err(SourceExecutionError::InvalidDigest);
        }
        if request.response_body.len() as u64 > plan.max_response_bytes {
            return Err(SourceExecutionError::ResponseTooLarge);
        }
        let receipt = request
            .receipt
            .as_ref()
            .ok_or(SourceExecutionError::MissingExecutionIdentity)?;
        if receipt.credential_operation != TwilioAccountsAdapter::credential_operation() {
            return Err(SourceExecutionError::MissingExecutionIdentity);
        }
        validate_safe_receipt(
            receipt,
            plan,
            context,
            &request.response_body,
            request.status_code,
            &request.request_intent_digest,
        )?;

        let observed_at = observed_at(context)?;
        let adapter = TwilioAccountsAdapter::new(&plan.origin, &context.tenant_id)
            .map_err(map_provider_error)?;
        let page = adapter
            .decode(
                optional_cursor(&context.prior_cursor),
                request.status_code,
                &request.response_body,
                observed_at,
            )
            .map_err(map_provider_error)?;
        let next_cursor = page.next_cursor.unwrap_or_default();
        validate_cursor(&next_cursor)?;

        let mut records = Vec::with_capacity(page.records.len());
        for record in page.records {
            if record.tenant_id != context.tenant_id
                || record.fields.get("tenant_id") != Some(&context.tenant_id)
            {
                return Err(SourceExecutionError::TenantMismatch);
            }
            require_contract_fields(plan, &record.fields, &record.payload)?;
            let occurred_at_unix_millis = occurred_at_unix_millis(&record.occurred_at)?;
            let payload_json = serde_json::to_vec(&record.payload)
                .map_err(|_| SourceExecutionError::InternalRuntime)?;
            records.push(SourceWorkerRecordV1 {
                provider_id: record.provider_id,
                attributes: record.fields.into_iter().collect(),
                payload_json,
                event_id: record.event_id,
                occurred_at_unix_millis,
            });
        }
        let records = validate_and_deduplicate_records(records)?;
        let result_digest_sha256 = canonical_result_digest(receipt, &next_cursor, &records)?;

        Ok(SourceWorkerDecodeResultV1 {
            plan_id: plan.plan_id.clone(),
            plan_digest_sha256: plan.plan_digest_sha256.clone(),
            logical_page_id: context.logical_page_id.clone(),
            request_intent_digest: request.request_intent_digest.clone(),
            records,
            next_cursor,
            result_digest_sha256,
            tenant_id: context.tenant_id.clone(),
            runtime_id: context.runtime_id.clone(),
            runtime_generation: context.runtime_generation,
            lease_generation: context.lease_generation,
            observed_at_unix_millis: context.observed_at_unix_millis,
        })
    }
}

fn validated_plan_context<'a>(
    plan: Option<&'a SourceExecutionPlanV1>,
    context: Option<&'a SourceWorkerExecutionContextV1>,
) -> Result<
    (
        &'a SourceExecutionPlanV1,
        &'a SourceWorkerExecutionContextV1,
    ),
    SourceExecutionError,
> {
    let plan = plan.ok_or(SourceExecutionError::InvalidPlan)?;
    validate_accounts_plan(plan)?;
    let context = context.ok_or(SourceExecutionError::InvalidExecutionContext)?;
    validate_execution_context(context)?;
    Ok((plan, context))
}

fn validate_accounts_plan(plan: &SourceExecutionPlanV1) -> Result<(), SourceExecutionError> {
    let exact = plan == &TWILIO_ACCOUNTS_SOURCE_EXECUTION_ADAPTER.compiled_plan();
    if exact {
        Ok(())
    } else {
        Err(SourceExecutionError::InvalidPlan)
    }
}

fn require_contract_fields(
    plan: &SourceExecutionPlanV1,
    attributes: &std::collections::BTreeMap<String, String>,
    payload: &Value,
) -> Result<(), SourceExecutionError> {
    if plan.required_attributes.iter().any(|required| {
        attributes
            .get(required)
            .is_none_or(|value| value.trim().is_empty())
    }) || plan
        .required_payload_fields
        .iter()
        .any(|required| payload.get(required).is_none_or(Value::is_null))
    {
        return Err(SourceExecutionError::EventContractRejected);
    }
    Ok(())
}

fn optional_cursor(cursor: &str) -> Option<&str> {
    (!cursor.is_empty()).then_some(cursor)
}

fn observed_at(
    context: &SourceWorkerExecutionContextV1,
) -> Result<OffsetDateTime, SourceExecutionError> {
    let nanos = i128::from(context.observed_at_unix_millis)
        .checked_mul(1_000_000)
        .ok_or(SourceExecutionError::InvalidExecutionContext)?;
    OffsetDateTime::from_unix_timestamp_nanos(nanos)
        .map_err(|_| SourceExecutionError::InvalidExecutionContext)
}

fn occurred_at_unix_millis(value: &str) -> Result<i64, SourceExecutionError> {
    let occurred_at = OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| SourceExecutionError::InvalidProviderRecord)?;
    i64::try_from(occurred_at.unix_timestamp_nanos() / 1_000_000)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(SourceExecutionError::MissingStableIdentity)
}

fn map_provider_error(error: TwilioAccountsAdapterError) -> SourceExecutionError {
    match error {
        TwilioAccountsAdapterError::AuthenticationRejected => {
            SourceExecutionError::AuthenticationRejected
        }
        TwilioAccountsAdapterError::RequiredScopeMissing => {
            SourceExecutionError::RequiredProviderScopeMissing
        }
        TwilioAccountsAdapterError::ProviderTimeout => SourceExecutionError::ProviderTimeout,
        TwilioAccountsAdapterError::RateLimited => SourceExecutionError::ProviderRateLimit,
        TwilioAccountsAdapterError::ProviderUnavailable
        | TwilioAccountsAdapterError::UnexpectedStatus(_) => {
            SourceExecutionError::UnexpectedProviderStatus
        }
        TwilioAccountsAdapterError::Kernel(TwilioError::InvalidCursor) => {
            SourceExecutionError::InvalidCursor
        }
        TwilioAccountsAdapterError::Kernel(TwilioError::ResponseTooLarge) => {
            SourceExecutionError::ResponseTooLarge
        }
        TwilioAccountsAdapterError::Kernel(TwilioError::TooManyRecords) => {
            SourceExecutionError::ResultTooLarge
        }
        TwilioAccountsAdapterError::Kernel(TwilioError::MissingProviderIdentity)
        | TwilioAccountsAdapterError::Kernel(TwilioError::InvalidEventIdentity) => {
            SourceExecutionError::MissingStableIdentity
        }
        TwilioAccountsAdapterError::Kernel(TwilioError::ConflictingProviderIdentity) => {
            SourceExecutionError::DuplicateConflict
        }
        TwilioAccountsAdapterError::Kernel(TwilioError::InvalidResponse) => {
            SourceExecutionError::MalformedResponse
        }
        TwilioAccountsAdapterError::Kernel(
            TwilioError::MissingRequiredPayloadField(_) | TwilioError::MissingRequiredAttribute(_),
        ) => SourceExecutionError::InvalidProviderRecord,
        TwilioAccountsAdapterError::Kernel(
            TwilioError::InvalidBaseUrl
            | TwilioError::InvalidFamily
            | TwilioError::MissingTenantId
            | TwilioError::MissingAccountSid
            | TwilioError::InvalidPageSize
            | TwilioError::RequestScopeMismatch,
        ) => SourceExecutionError::InvalidPlan,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source_execution::{SourceWorkerSafeReceiptV1, response_digest};

    const ACCOUNTS_PAGE: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../sources/twilio/testdata/source_worker_accounts_page.json"
    ));

    fn context(prior_cursor: &str) -> SourceWorkerExecutionContextV1 {
        SourceWorkerExecutionContextV1 {
            tenant_id: "trusted-tenant".to_owned(),
            runtime_id: "twilio-accounts-runtime".to_owned(),
            logical_page_id: "accounts-page-1".to_owned(),
            prior_cursor: prior_cursor.to_owned(),
            runtime_generation: 7,
            lease_generation: 11,
            observed_at_unix_millis: 1_780_372_800_000,
        }
    }

    fn exact_plan() -> SourceExecutionPlanV1 {
        TWILIO_ACCOUNTS_SOURCE_EXECUTION_ADAPTER.compiled_plan()
    }

    fn decode_request(status_code: u32) -> SourceWorkerDecodeRequestV1 {
        let plan = exact_plan();
        let execution = context("accounts-page-1");
        let intent = TWILIO_ACCOUNTS_SOURCE_EXECUTION_ADAPTER
            .plan(&SourceWorkerPlanRequestV1 {
                plan: Some(plan.clone()),
                context: Some(execution.clone()),
            })
            .unwrap()
            .request_intent_digest;
        let receipt = SourceWorkerSafeReceiptV1 {
            plan_digest_sha256: plan.plan_digest_sha256.clone(),
            logical_page_id: execution.logical_page_id.clone(),
            request_intent_digest: intent.clone(),
            runtime_generation: execution.runtime_generation,
            lease_generation: execution.lease_generation,
            credential_operation: TwilioAccountsAdapter::credential_operation().to_owned(),
            status_code,
            response_bytes: ACCOUNTS_PAGE.len() as u64,
            response_sha256: response_digest(ACCOUNTS_PAGE),
            tenant_id: execution.tenant_id.clone(),
            runtime_id: execution.runtime_id.clone(),
            observed_at_unix_millis: execution.observed_at_unix_millis,
        };
        SourceWorkerDecodeRequestV1 {
            plan: Some(plan),
            status_code,
            response_body: ACCOUNTS_PAGE.to_vec(),
            logical_page_id: execution.logical_page_id.clone(),
            request_intent_digest: intent,
            receipt: Some(receipt),
            context: Some(execution),
        }
    }

    #[test]
    fn canonical_edge_plans_credential_free_request_and_decodes_fixture() {
        let request = SourceWorkerPlanRequestV1 {
            plan: Some(exact_plan()),
            context: Some(context("accounts-page-1")),
        };
        let planned = TWILIO_ACCOUNTS_SOURCE_EXECUTION_ADAPTER
            .plan(&request)
            .unwrap();
        assert_eq!(
            planned.url,
            "https://api.twilio.com/2010-04-01/Accounts.json?limit=100&cursor=accounts-page-1"
        );
        assert!(!planned.url.contains("credential"));
        assert!(!planned.url.contains("token"));
        assert_eq!(planned.request_intent_digest.len(), 64);

        let result = TWILIO_ACCOUNTS_SOURCE_EXECUTION_ADAPTER
            .decode(&decode_request(200))
            .unwrap();
        assert_eq!(result.next_cursor, "accounts-page-2");
        assert_eq!(result.records.len(), 1);
        let record = &result.records[0];
        assert_eq!(record.provider_id, "record-1");
        assert_eq!(record.attributes["tenant_id"], "trusted-tenant");
        assert_eq!(
            record.event_id,
            "twilio-trusted-tenant-a92380b4993d-accounts-record-1"
        );
        assert_eq!(record.occurred_at_unix_millis, 1_780_272_000_000);
        assert_eq!(result.tenant_id, "trusted-tenant");
        assert_eq!(result.result_digest_sha256.len(), 64);
        TWILIO_ACCOUNTS_SOURCE_EXECUTION_ADAPTER
            .validate_record_identity(&context("accounts-page-1"), record)
            .unwrap();
    }

    #[test]
    fn canonical_edge_rejects_provider_status_and_identity_drift() {
        assert_eq!(
            TWILIO_ACCOUNTS_SOURCE_EXECUTION_ADAPTER
                .decode(&decode_request(429))
                .unwrap_err(),
            SourceExecutionError::ProviderRateLimit
        );

        let result = TWILIO_ACCOUNTS_SOURCE_EXECUTION_ADAPTER
            .decode(&decode_request(200))
            .unwrap();
        let mut record = result.records[0].clone();
        record.event_id = "twilio-provider-controlled-tenant-record-1".to_owned();
        assert_eq!(
            TWILIO_ACCOUNTS_SOURCE_EXECUTION_ADAPTER
                .validate_record_identity(&context("accounts-page-1"), &record),
            Err(SourceExecutionError::TenantMismatch)
        );
    }
}
