use std::{collections::HashMap, sync::LazyLock};

use reqwest::Url;
use serde_json::Value;

use crate::source_execution::{
    SourceExecutionAdapter, SourceExecutionError, SourceExecutionPlanV1,
    SourceWorkerDecodeEnvelopeV2, SourceWorkerDecodeRequestV1, SourceWorkerDecodeResultV1,
    SourceWorkerExecutionContextV1, SourceWorkerHttpExecutionV2, SourceWorkerHttpRequestV1,
    SourceWorkerPlanEnvelopeV2, SourceWorkerPlanRequestV1, SourceWorkerRecordV1,
    SourceWorkerRuntimeMetadataV2, canonical_http_execution_digest, canonical_plan_digest,
    canonical_request_intent_digest, canonical_result_digest, validate_and_deduplicate_records,
    validate_cursor, validate_execution_context, validate_runtime_metadata,
};

use super::{
    catalog::{Family, Pagination, SOURCES, Source},
    normalize::{expected_event_id, normalize_records, scalar_at},
};

const MAX_RESPONSE_BYTES: u64 = 8 * 1024 * 1024;

/// Credential-free adapter for one exact catalog-defined AI provider family.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PortableAiSourceExecutionAdapter {
    pub(super) source: &'static Source,
    pub(super) family: &'static Family,
}

impl PortableAiSourceExecutionAdapter {
    fn new(source: &'static Source, family: &'static Family) -> Self {
        Self { source, family }
    }

    pub(crate) fn compiled_plan(&self) -> SourceExecutionPlanV1 {
        let mut plan = SourceExecutionPlanV1 {
            plan_id: format!("source-plan-v1:{}:{}", self.source.id, self.family.id),
            source_id: self.source.id.clone(),
            family_id: self.family.id.clone(),
            provider_kernel: self.family.kernel.clone(),
            method: self.family.method.clone(),
            origin: self.source.origin_template.clone(),
            path: self.family.path.clone(),
            record_selector: self.family.record_selector.clone(),
            id_field: self.family.id_paths.join("|"),
            singleton_fallback_id: String::new(),
            max_response_bytes: MAX_RESPONSE_BYTES,
            event_kind: self.family.kind.clone(),
            schema_ref: self.family.schema_ref.clone(),
            required_attributes: self.family.required_attributes.clone(),
            required_payload_fields: self.family.required_payload_fields.clone(),
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

    fn rendered_origin(
        &self,
        metadata: &SourceWorkerRuntimeMetadataV2,
    ) -> Result<String, SourceExecutionError> {
        let mut origin = self.source.origin_template.clone();
        for key in &self.source.required_config {
            let value = public_value(&metadata.public_config, key)
                .ok_or(SourceExecutionError::MissingConfiguration)?;
            let placeholder = format!("${{config.{key}}}");
            if origin.contains(&placeholder) {
                if !safe_dns_label(value) {
                    return Err(SourceExecutionError::MissingConfiguration);
                }
                origin = origin.replace(&placeholder, value);
            }
        }
        if origin.contains("${config.") {
            return Err(SourceExecutionError::MissingConfiguration);
        }
        let parsed = Url::parse(&origin).map_err(|_| SourceExecutionError::MissingConfiguration)?;
        if parsed.scheme() != "https"
            || parsed.username() != ""
            || parsed.password().is_some()
            || parsed.port().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || parsed.host_str().is_none()
        {
            return Err(SourceExecutionError::MissingConfiguration);
        }
        if self.source.id == "google_vertex_ai"
            && !parsed
                .host_str()
                .is_some_and(|host| host.ends_with("-aiplatform.googleapis.com"))
        {
            return Err(SourceExecutionError::EgressDenied);
        }
        if public_value(&metadata.public_config, "base_url")
            .is_some_and(|base_url| base_url.trim_end_matches('/') != origin.trim_end_matches('/'))
        {
            return Err(SourceExecutionError::MissingConfiguration);
        }
        Ok(origin)
    }

    fn rendered_path(
        &self,
        metadata: &SourceWorkerRuntimeMetadataV2,
    ) -> Result<String, SourceExecutionError> {
        let mut path = self.family.path.clone();
        for key in &self.source.required_config {
            let placeholder = format!("${{config.{key}}}");
            if path.contains(&placeholder) {
                let value = public_value(&metadata.public_config, key)
                    .ok_or(SourceExecutionError::MissingConfiguration)?;
                path = path.replace(&placeholder, &path_component(value)?);
            }
        }
        if !path.starts_with('/') || path.contains("${config.") {
            return Err(SourceExecutionError::MissingConfiguration);
        }
        Ok(path)
    }

    fn request_url(
        &self,
        context: &SourceWorkerExecutionContextV1,
        metadata: &SourceWorkerRuntimeMetadataV2,
    ) -> Result<(String, String), SourceExecutionError> {
        validate_execution_context(context)?;
        validate_runtime_metadata(metadata)?;
        if public_value(&metadata.public_config, "family")
            .is_some_and(|family| family != self.family.id.as_str())
        {
            return Err(SourceExecutionError::MissingConfiguration);
        }
        for key in &self.source.required_config {
            public_value(&metadata.public_config, key)
                .ok_or(SourceExecutionError::MissingConfiguration)?;
        }
        let origin = self.rendered_origin(metadata)?;
        let mut url = match &self.family.pagination {
            Pagination::NextUrl { .. } | Pagination::Link { .. }
                if !context.prior_cursor.is_empty() =>
            {
                validate_cursor(&context.prior_cursor)?;
                validated_continuation(&origin, &context.prior_cursor)?
            }
            _ => Url::parse(&format!(
                "{}{}",
                origin.trim_end_matches('/'),
                self.rendered_path(metadata)?
            ))
            .map_err(|_| SourceExecutionError::InvalidPlan)?,
        };
        if context.prior_cursor.is_empty() {
            let mut query = url.query_pairs_mut();
            for (key, value) in &self.family.static_query {
                query.append_pair(key, value);
            }
            for (parameter, config_key) in &self.family.config_query {
                let value = public_value(&metadata.public_config, config_key)
                    .ok_or(SourceExecutionError::MissingConfiguration)?;
                query.append_pair(parameter, value);
            }
            match &self.family.pagination {
                Pagination::Cursor {
                    page_size_parameter,
                    page_size,
                    ..
                }
                | Pagination::Link {
                    page_size_parameter,
                    page_size,
                    ..
                } => {
                    if let Some(parameter) = page_size_parameter {
                        query.append_pair(parameter, &page_size.to_string());
                    }
                }
                Pagination::None | Pagination::NextUrl { .. } => {}
            }
        }
        if let Pagination::Cursor { parameter, .. } = &self.family.pagination {
            if !context.prior_cursor.is_empty() {
                validate_cursor(&context.prior_cursor)?;
                url.query_pairs_mut()
                    .append_pair(parameter, &context.prior_cursor);
            }
        } else if matches!(&self.family.pagination, Pagination::None)
            && !context.prior_cursor.is_empty()
        {
            return Err(SourceExecutionError::InvalidCursor);
        }
        Ok((origin, url.to_string()))
    }

    fn next_cursor(
        &self,
        body: &[u8],
        headers: &HashMap<String, String>,
        origin: &str,
    ) -> Result<String, SourceExecutionError> {
        let document: Value =
            serde_json::from_slice(body).map_err(|_| SourceExecutionError::MalformedResponse)?;
        let cursor = match &self.family.pagination {
            Pagination::None => None,
            Pagination::Cursor { json_path, .. } => scalar_at(&document, &[json_path.clone()]),
            Pagination::NextUrl { json_path } => scalar_at(&document, &[json_path.clone()]),
            Pagination::Link { header, .. } => response_header(headers, header).and_then(link_next),
        };
        let Some(cursor) = cursor else {
            return Ok(String::new());
        };
        validate_cursor(&cursor)?;
        if matches!(
            &self.family.pagination,
            Pagination::NextUrl { .. } | Pagination::Link { .. }
        ) {
            validated_continuation(origin, &cursor)?;
        }
        Ok(cursor)
    }

    fn validate_identity(
        &self,
        context: &SourceWorkerExecutionContextV1,
        record: &SourceWorkerRecordV1,
    ) -> Result<(), SourceExecutionError> {
        if record.event_id
            != expected_event_id(
                &context.tenant_id,
                &self.source.id,
                &self.family.id,
                &record.provider_id,
            )
            || record.attributes.get("tenant_id") != Some(&context.tenant_id)
            || record.attributes.get("source_event_id") != Some(&record.provider_id)
            || record.attributes.get("family") != Some(&self.family.id)
            || record.attributes.get("provider") != Some(&self.source.id)
            || record.attributes.get("source_provider") != Some(&self.source.id)
        {
            return Err(SourceExecutionError::TenantMismatch);
        }
        Ok(())
    }
}

impl SourceExecutionAdapter for PortableAiSourceExecutionAdapter {
    fn source_id(&self) -> &'static str {
        &self.source.id
    }

    fn family_id(&self) -> &'static str {
        &self.family.id
    }

    fn provider_kernel(&self) -> &'static str {
        &self.family.kernel
    }

    fn validate_record_identity(
        &self,
        context: &SourceWorkerExecutionContextV1,
        record: &SourceWorkerRecordV1,
    ) -> Result<(), SourceExecutionError> {
        self.validate_identity(context, record)
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
        let (origin, url) = self.request_url(context, metadata)?;
        let mut planned = SourceWorkerHttpRequestV1 {
            plan_id: plan.plan_id.clone(),
            method: plan.method.clone(),
            url,
            accept: "application/json".to_owned(),
            max_response_bytes: plan.max_response_bytes,
            plan_digest_sha256: plan.plan_digest_sha256.clone(),
            request_intent_digest: String::new(),
        };
        planned.request_intent_digest = canonical_request_intent_digest(plan, context, &planned);
        let mut execution = SourceWorkerHttpExecutionV2 {
            request: Some(planned),
            body: Vec::new(),
            declared_headers: HashMap::new(),
            execution_intent_digest_sha256: String::new(),
            credential_operation: self.source.auth.host_operation().to_owned(),
            allowed_origin: origin,
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
        match request.status_code {
            200..=299 => {}
            401 => return Err(SourceExecutionError::AuthenticationRejected),
            403 => return Err(SourceExecutionError::RequiredProviderScopeMissing),
            429 => return Err(SourceExecutionError::ProviderRateLimit),
            _ => return Err(SourceExecutionError::UnexpectedProviderStatus),
        }
        let origin = self.rendered_origin(metadata)?;
        let records = normalize_records(
            self.source,
            self.family,
            &context.tenant_id,
            &request.response_body,
            context.observed_at_unix_millis,
        )?;
        let records = validate_and_deduplicate_records(records)?;
        let next_cursor =
            self.next_cursor(&request.response_body, &envelope.response_headers, &origin)?;
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

pub(crate) static PORTABLE_AI_SOURCE_EXECUTION_ADAPTERS: LazyLock<
    Vec<PortableAiSourceExecutionAdapter>,
> = LazyLock::new(|| {
    SOURCES
        .iter()
        .flat_map(|source| {
            source
                .families
                .iter()
                .map(|family| PortableAiSourceExecutionAdapter::new(source, family))
        })
        .collect()
});

fn public_value<'a>(config: &'a HashMap<String, String>, key: &str) -> Option<&'a str> {
    config
        .get(key)
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn safe_dns_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && !value.starts_with('-')
        && !value.ends_with('-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn path_component(value: &str) -> Result<String, SourceExecutionError> {
    if value.is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
        return Err(SourceExecutionError::MissingConfiguration);
    }
    Ok(value
        .bytes()
        .flat_map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                vec![char::from(byte)]
            }
            _ => format!("%{byte:02X}").chars().collect(),
        })
        .collect())
}

fn validated_continuation(origin: &str, value: &str) -> Result<Url, SourceExecutionError> {
    let origin = Url::parse(origin).map_err(|_| SourceExecutionError::InvalidPlan)?;
    let continuation = Url::parse(value).map_err(|_| SourceExecutionError::InvalidCursor)?;
    let prefix = origin.path().trim_end_matches('/');
    if continuation.scheme() != origin.scheme()
        || continuation.host_str() != origin.host_str()
        || continuation.port_or_known_default() != origin.port_or_known_default()
        || continuation.username() != ""
        || continuation.password().is_some()
        || continuation.fragment().is_some()
        || (!prefix.is_empty()
            && continuation.path() != prefix
            && !continuation.path().starts_with(&format!("{prefix}/")))
    {
        return Err(SourceExecutionError::EgressDenied);
    }
    Ok(continuation)
}

fn response_header<'a>(headers: &'a HashMap<String, String>, name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.trim())
        .filter(|value| !value.is_empty())
}

fn link_next(value: &str) -> Option<String> {
    value.split(',').find_map(|part| {
        let part = part.trim();
        let (target, parameters) = part.split_once('>')?;
        if !parameters.split(';').any(|parameter| {
            parameter.trim().eq_ignore_ascii_case("rel=\"next\"")
                || parameter.trim().eq_ignore_ascii_case("rel=next")
        }) {
            return None;
        }
        target
            .trim()
            .strip_prefix('<')
            .map(str::to_owned)
            .filter(|target| !target.is_empty())
    })
}
