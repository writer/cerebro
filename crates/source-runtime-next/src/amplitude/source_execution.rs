//! Amplitude SCIM bridge for the closed source-execution protocol.
//!
//! The adapters receive authenticated tenant context, public SCIM selectors,
//! and bounded provider response bytes. The trusted host retains credential
//! redemption, Bearer authentication, origin-constrained network I/O, durable
//! append, projection, and checkpoint ownership.

use std::collections::HashMap;

use serde_json::Value;

use crate::source_execution::{
    SourceExecutionAdapter, SourceExecutionError, SourceExecutionPlanV1,
    SourceWorkerDecodeEnvelopeV2, SourceWorkerDecodeRequestV1, SourceWorkerDecodeResultV1,
    SourceWorkerExecutionContextV1, SourceWorkerHttpExecutionV2, SourceWorkerHttpRequestV1,
    SourceWorkerPlanEnvelopeV2, SourceWorkerPlanRequestV1, SourceWorkerRecordV1,
    SourceWorkerRuntimeMetadataV2, canonical_http_execution_digest, canonical_plan_digest,
    canonical_request_intent_digest, canonical_result_digest, tenant_scoped_event_id,
    validate_and_deduplicate_records, validate_execution_context, validate_runtime_metadata,
};

use super::{AmplitudeError, AmplitudeFamily, AmplitudeKernel};

const SOURCE_ID: &str = "amplitude";
const DEFAULT_BASE_URL: &str = "https://core.amplitude.com";
const METHOD: &str = "GET";
const RECORD_SELECTOR: &str = "$.Resources[*]";
const ID_FIELD: &str = "id";
const MAX_RESPONSE_BYTES: u64 = 8 << 20;

/// Credential-free adapter for one Amplitude SCIM family.
#[derive(Clone, Copy, Debug)]
pub(crate) struct AmplitudeSourceExecutionAdapter {
    family: AmplitudeFamily,
}

/// Provider-local adapter set. Shared dispatcher registration and authority
/// promotion are intentionally separate delivery steps.
pub(crate) static AMPLITUDE_SOURCE_EXECUTION_ADAPTERS: [AmplitudeSourceExecutionAdapter; 2] = [
    AmplitudeSourceExecutionAdapter::new(AmplitudeFamily::Users),
    AmplitudeSourceExecutionAdapter::new(AmplitudeFamily::Groups),
];

impl AmplitudeSourceExecutionAdapter {
    const fn new(family: AmplitudeFamily) -> Self {
        Self { family }
    }

    pub(crate) fn compiled_plan(&self) -> SourceExecutionPlanV1 {
        let family_id = self.family.as_str();
        let mut plan = SourceExecutionPlanV1 {
            plan_id: format!("source-plan-v1:{SOURCE_ID}:{family_id}"),
            source_id: SOURCE_ID.to_owned(),
            family_id: family_id.to_owned(),
            provider_kernel: self.family.provider_kind().to_owned(),
            method: METHOD.to_owned(),
            origin: DEFAULT_BASE_URL.to_owned(),
            path: family_path(self.family).to_owned(),
            record_selector: RECORD_SELECTOR.to_owned(),
            id_field: ID_FIELD.to_owned(),
            singleton_fallback_id: String::new(),
            max_response_bytes: MAX_RESPONSE_BYTES,
            event_kind: self.family.provider_kind().to_owned(),
            schema_ref: schema_ref(self.family).to_owned(),
            required_attributes: required_attributes(self.family)
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            required_payload_fields: vec!["id".to_owned()],
            plan_digest_sha256: String::new(),
        };
        plan.plan_digest_sha256 = canonical_plan_digest(&plan);
        plan
    }

    fn validate_plan(&self, plan: &SourceExecutionPlanV1) -> Result<(), SourceExecutionError> {
        if plan != &self.compiled_plan() {
            return Err(SourceExecutionError::InvalidPlan);
        }
        Ok(())
    }

    fn kernel(
        &self,
        context: &SourceWorkerExecutionContextV1,
        metadata: &SourceWorkerRuntimeMetadataV2,
    ) -> Result<(AmplitudeKernel, String), SourceExecutionError> {
        validate_execution_context(context)?;
        validate_runtime_metadata(metadata)?;
        if public_value(&metadata.public_config, "family")
            .is_some_and(|value| value != self.family.as_str())
        {
            return Err(SourceExecutionError::MissingConfiguration);
        }
        let base_url =
            public_value(&metadata.public_config, "base_url").unwrap_or(DEFAULT_BASE_URL);
        let page_size = public_value(&metadata.public_config, "per_page")
            .map(|value| {
                value
                    .parse::<usize>()
                    .map_err(|_| SourceExecutionError::MissingConfiguration)
            })
            .transpose()?;
        let kernel = AmplitudeKernel::new(base_url, self.family, page_size).map_err(map_error)?;
        let allowed_origin = kernel
            .plan(None)
            .map_err(map_error)?
            .url()
            .origin()
            .ascii_serialization();
        Ok((kernel, allowed_origin))
    }
}

impl SourceExecutionAdapter for AmplitudeSourceExecutionAdapter {
    fn source_id(&self) -> &'static str {
        SOURCE_ID
    }

    fn family_id(&self) -> &'static str {
        self.family.as_str()
    }

    fn provider_kernel(&self) -> &'static str {
        self.family.provider_kind()
    }

    fn validate_record_identity(
        &self,
        context: &SourceWorkerExecutionContextV1,
        record: &SourceWorkerRecordV1,
    ) -> Result<(), SourceExecutionError> {
        let expected_event_id = tenant_scoped_event_id(
            SOURCE_ID,
            self.family.as_str(),
            &context.tenant_id,
            &record.provider_id,
        )?;
        if record.event_id != expected_event_id
            || record.attributes.get("tenant_id") != Some(&context.tenant_id)
            || record.attributes.get("source_event_id") != Some(&record.provider_id)
            || record.attributes.get("family").map(String::as_str) != Some(self.family.as_str())
        {
            return Err(SourceExecutionError::TenantMismatch);
        }
        match self.family {
            AmplitudeFamily::Users => {
                if record
                    .attributes
                    .get("user_id")
                    .is_none_or(|value| value.trim().is_empty())
                {
                    return Err(SourceExecutionError::EventContractRejected);
                }
            }
            AmplitudeFamily::Groups => {
                if record.attributes.get("group_id") != Some(&record.provider_id)
                    || record
                        .attributes
                        .get("group_name")
                        .is_none_or(|value| value.trim().is_empty())
                {
                    return Err(SourceExecutionError::EventContractRejected);
                }
            }
        }
        Ok(())
    }

    fn plan(
        &self,
        _request: &SourceWorkerPlanRequestV1,
    ) -> Result<SourceWorkerHttpRequestV1, SourceExecutionError> {
        Err(SourceExecutionError::InvalidPlan)
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
        self.validate_plan(plan)?;
        let (kernel, allowed_origin) = self.kernel(context, metadata)?;
        let provider_request = kernel
            .plan(optional(&context.prior_cursor))
            .map_err(map_error)?;
        if provider_request.url().path() != plan.path
            || provider_request.authorization_scheme() != "Bearer"
            || !provider_request.url().username().is_empty()
            || provider_request.url().password().is_some()
        {
            return Err(SourceExecutionError::InvalidPlan);
        }
        let mut planned = SourceWorkerHttpRequestV1 {
            plan_id: plan.plan_id.clone(),
            method: METHOD.to_owned(),
            url: provider_request.url().to_string(),
            accept: provider_request.accept().to_owned(),
            max_response_bytes: MAX_RESPONSE_BYTES,
            plan_digest_sha256: plan.plan_digest_sha256.clone(),
            request_intent_digest: String::new(),
        };
        planned.request_intent_digest = canonical_request_intent_digest(plan, context, &planned);
        let mut execution = SourceWorkerHttpExecutionV2 {
            request: Some(planned),
            body: Vec::new(),
            declared_headers: HashMap::new(),
            execution_intent_digest_sha256: String::new(),
            credential_operation: "source.bearer".to_owned(),
            allowed_origin,
        };
        execution.execution_intent_digest_sha256 =
            canonical_http_execution_digest(plan, context, metadata, &execution);
        Ok(execution)
    }

    fn decode(
        &self,
        _request: &SourceWorkerDecodeRequestV1,
    ) -> Result<SourceWorkerDecodeResultV1, SourceExecutionError> {
        Err(SourceExecutionError::InvalidPlan)
    }

    fn decode_v2(
        &self,
        envelope: &SourceWorkerDecodeEnvelopeV2,
    ) -> Result<SourceWorkerDecodeResultV1, SourceExecutionError> {
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
        let receipt = request
            .receipt
            .as_ref()
            .ok_or(SourceExecutionError::MissingExecutionIdentity)?;
        let metadata = envelope
            .metadata
            .as_ref()
            .ok_or(SourceExecutionError::MissingExecutionIdentity)?;
        self.validate_plan(plan)?;
        let (kernel, _) = self.kernel(context, metadata)?;
        let provider_request = kernel
            .plan(optional(&context.prior_cursor))
            .map_err(map_error)?;
        let page = match request.status_code {
            200 => kernel
                .decode(&provider_request, &request.response_body)
                .map_err(map_error)?,
            401 => return Err(SourceExecutionError::AuthenticationRejected),
            403 => return Err(SourceExecutionError::RequiredProviderScopeMissing),
            429 => return Err(SourceExecutionError::ProviderRateLimit),
            _ => return Err(SourceExecutionError::UnexpectedProviderStatus),
        };
        let next_cursor = page.next_cursor.unwrap_or_default();
        let records = page
            .records
            .into_iter()
            .map(|record| {
                if record.family != self.family.as_str()
                    || record.provider_kind != plan.event_kind
                    || record.provider_id.trim().is_empty()
                {
                    return Err(SourceExecutionError::InvalidProviderRecord);
                }
                let provider_id = record.provider_id;
                let mut attributes = record.fields.into_iter().collect::<HashMap<_, _>>();
                attributes.insert("tenant_id".to_owned(), context.tenant_id.clone());
                attributes.insert("source_event_id".to_owned(), provider_id.clone());
                attributes.insert("external_id".to_owned(), provider_id.clone());
                attributes.insert("family".to_owned(), self.family.as_str().to_owned());
                attributes.insert("provider".to_owned(), SOURCE_ID.to_owned());
                attributes.insert("source_provider".to_owned(), SOURCE_ID.to_owned());
                attributes.insert("source_system".to_owned(), SOURCE_ID.to_owned());
                let event_id = tenant_scoped_event_id(
                    SOURCE_ID,
                    self.family.as_str(),
                    &context.tenant_id,
                    &provider_id,
                )?;
                Ok(SourceWorkerRecordV1 {
                    provider_id,
                    event_id,
                    occurred_at_unix_millis: context.observed_at_unix_millis,
                    attributes,
                    payload_json: serde_json::to_vec(&sanitize_payload(record.payload))
                        .map_err(|_| SourceExecutionError::InternalRuntime)?,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let records = validate_and_deduplicate_records(records)?;
        for record in &records {
            self.validate_record_identity(context, record)?;
        }
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

const fn family_path(family: AmplitudeFamily) -> &'static str {
    match family {
        AmplitudeFamily::Users => "/scim/1/Users",
        AmplitudeFamily::Groups => "/scim/1/Groups",
    }
}

const fn schema_ref(family: AmplitudeFamily) -> &'static str {
    match family {
        AmplitudeFamily::Users => "amplitude/users/v1",
        AmplitudeFamily::Groups => "amplitude/groups/v1",
    }
}

const fn required_attributes(family: AmplitudeFamily) -> &'static [&'static str] {
    match family {
        AmplitudeFamily::Users => &["tenant_id", "source_event_id", "user_id"],
        AmplitudeFamily::Groups => &["tenant_id", "source_event_id", "group_id", "group_name"],
    }
}

fn public_value<'a>(config: &'a HashMap<String, String>, key: &str) -> Option<&'a str> {
    config
        .get(key)
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn optional(value: &str) -> Option<&str> {
    (!value.is_empty()).then_some(value)
}

fn sanitize_payload(value: Value) -> Value {
    match value {
        Value::Object(object) => Value::Object(
            object
                .into_iter()
                .filter(|(key, _)| !restricted_payload_field(key))
                .map(|(key, value)| (key, sanitize_payload(value)))
                .collect(),
        ),
        Value::Array(values) => Value::Array(values.into_iter().map(sanitize_payload).collect()),
        other => other,
    }
}

fn restricted_payload_field(key: &str) -> bool {
    let normalized = key
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect::<String>();
    matches!(
        normalized.as_str(),
        "token"
            | "accesstoken"
            | "refreshtoken"
            | "sessiontoken"
            | "apikey"
            | "apitoken"
            | "authorization"
            | "cookie"
            | "setcookie"
            | "password"
            | "passcode"
            | "secret"
            | "clientsecret"
            | "privatekey"
            | "tenant"
            | "tenantid"
            | "runtimeid"
            | "sourceruntimeid"
    )
}

fn map_error(error: AmplitudeError) -> SourceExecutionError {
    match error {
        AmplitudeError::InvalidBaseUrl | AmplitudeError::InvalidPageSize => {
            SourceExecutionError::MissingConfiguration
        }
        AmplitudeError::InvalidFamily => SourceExecutionError::UnknownAdapter,
        AmplitudeError::InvalidCursor => SourceExecutionError::InvalidCursor,
        AmplitudeError::InvalidResponse => SourceExecutionError::MalformedResponse,
        AmplitudeError::MissingIdentity => SourceExecutionError::MissingStableIdentity,
        AmplitudeError::RequestScopeMismatch => SourceExecutionError::InvalidPlan,
    }
}
