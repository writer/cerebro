use crate::AzureAuthenticationMethodsPolicyKernel;

use super::{
    contract::{
        AUTHORIZATION_POLICY_FALLBACK_ID, AUTHORIZATION_POLICY_FAMILY, AUTHORIZATION_POLICY_KERNEL,
        AUTHORIZATION_POLICY_KIND, AUTHORIZATION_POLICY_PATH, AUTHORIZATION_POLICY_SCHEMA,
        AZURE_SOURCE_ID, GRAPH_ORIGIN, MAX_RESPONSE_BYTES, canonical_plan_digest,
        canonical_request_intent_digest, canonical_result_digest, validate_and_deduplicate_records,
        validate_execution_context, validate_plan, validate_safe_receipt,
    },
    dispatcher::SourceExecutionAdapter,
    error::SourceExecutionError,
    wire::{
        SourceExecutionPlanV1, SourceWorkerDecodeRequestV1, SourceWorkerDecodeResultV1,
        SourceWorkerExecutionContextV1, SourceWorkerHttpRequestV1, SourceWorkerPlanRequestV1,
        SourceWorkerRecordV1,
    },
};

pub(super) struct AzureAuthorizationPolicyAdapter;

impl AzureAuthorizationPolicyAdapter {
    pub(super) fn compiled_plan(&self) -> SourceExecutionPlanV1 {
        let mut plan = SourceExecutionPlanV1 {
            plan_id: "source-plan-v1:azure:authorization_policy".to_owned(),
            source_id: AZURE_SOURCE_ID.to_owned(),
            family_id: AUTHORIZATION_POLICY_FAMILY.to_owned(),
            provider_kernel: AUTHORIZATION_POLICY_KERNEL.to_owned(),
            method: "GET".to_owned(),
            origin: GRAPH_ORIGIN.to_owned(),
            path: AUTHORIZATION_POLICY_PATH.to_owned(),
            record_selector: "$".to_owned(),
            id_field: "id".to_owned(),
            singleton_fallback_id: AUTHORIZATION_POLICY_FALLBACK_ID.to_owned(),
            max_response_bytes: MAX_RESPONSE_BYTES,
            event_kind: AUTHORIZATION_POLICY_KIND.to_owned(),
            schema_ref: AUTHORIZATION_POLICY_SCHEMA.to_owned(),
            required_attributes: vec![
                "family".to_owned(),
                "resource_id".to_owned(),
                "resource_name".to_owned(),
                "resource_provider".to_owned(),
                "resource_type".to_owned(),
            ],
            required_payload_fields: vec!["id".to_owned()],
            plan_digest_sha256: String::new(),
        };
        plan.plan_digest_sha256 = canonical_plan_digest(&plan);
        plan
    }
}

impl SourceExecutionAdapter for AzureAuthorizationPolicyAdapter {
    fn source_id(&self) -> &'static str {
        AZURE_SOURCE_ID
    }

    fn family_id(&self) -> &'static str {
        AUTHORIZATION_POLICY_FAMILY
    }

    fn provider_kernel(&self) -> &'static str {
        AUTHORIZATION_POLICY_KERNEL
    }

    fn validate_record_identity(
        &self,
        _context: &SourceWorkerExecutionContextV1,
        record: &SourceWorkerRecordV1,
    ) -> Result<(), SourceExecutionError> {
        let expected = format!("azure-authorization-policy-{}", record.provider_id);
        if record.event_id != expected {
            return Err(SourceExecutionError::TenantMismatch);
        }
        Ok(())
    }

    fn plan(
        &self,
        request: &SourceWorkerPlanRequestV1,
    ) -> Result<SourceWorkerHttpRequestV1, SourceExecutionError> {
        let plan = request
            .plan
            .as_ref()
            .ok_or(SourceExecutionError::InvalidPlan)?;
        let context = request
            .context
            .as_ref()
            .ok_or(SourceExecutionError::MissingExecutionIdentity)?;
        validate_plan(plan)?;
        validate_execution_context(context)?;
        if !context.prior_cursor.is_empty() {
            return Err(SourceExecutionError::InvalidCursor);
        }

        let kernel = AzureAuthenticationMethodsPolicyKernel::new(&plan.origin)
            .map_err(|_| SourceExecutionError::InvalidPlan)?;
        let provider_request = kernel
            .plan_authorization_policy()
            .map_err(|_| SourceExecutionError::InvalidPlan)?;
        if provider_request.url().path() != plan.path || provider_request.url().query().is_some() {
            return Err(SourceExecutionError::InvalidPlan);
        }
        let mut result = SourceWorkerHttpRequestV1 {
            plan_id: plan.plan_id.clone(),
            method: plan.method.clone(),
            url: provider_request.url().to_string(),
            accept: provider_request.accept().to_owned(),
            max_response_bytes: plan.max_response_bytes,
            plan_digest_sha256: plan.plan_digest_sha256.clone(),
            request_intent_digest: String::new(),
        };
        result.request_intent_digest = canonical_request_intent_digest(plan, context, &result);
        Ok(result)
    }

    fn decode(
        &self,
        request: &SourceWorkerDecodeRequestV1,
    ) -> Result<SourceWorkerDecodeResultV1, SourceExecutionError> {
        let plan = request
            .plan
            .as_ref()
            .ok_or(SourceExecutionError::InvalidPlan)?;
        let context = request
            .context
            .as_ref()
            .ok_or(SourceExecutionError::MissingExecutionIdentity)?;
        validate_plan(plan)?;
        validate_execution_context(context)?;
        if !context.prior_cursor.is_empty() {
            return Err(SourceExecutionError::InvalidCursor);
        }
        if request.status_code != 200 {
            return Err(SourceExecutionError::UnexpectedProviderStatus);
        }
        if request.response_body.len() as u64 > plan.max_response_bytes {
            return Err(SourceExecutionError::ResponseTooLarge);
        }
        if request.logical_page_id != context.logical_page_id {
            return Err(SourceExecutionError::MissingExecutionIdentity);
        }
        let receipt = request
            .receipt
            .as_ref()
            .ok_or(SourceExecutionError::MissingExecutionIdentity)?;
        validate_safe_receipt(
            receipt,
            plan,
            context,
            &request.response_body,
            request.status_code,
            &request.request_intent_digest,
        )?;
        let expected_intent = self
            .plan(&SourceWorkerPlanRequestV1 {
                plan: Some(plan.clone()),
                context: Some(context.clone()),
            })?
            .request_intent_digest;
        if request.request_intent_digest != expected_intent {
            return Err(SourceExecutionError::InvalidDigest);
        }

        let kernel = AzureAuthenticationMethodsPolicyKernel::new(&plan.origin)
            .map_err(|_| SourceExecutionError::InvalidPlan)?;
        let provider_request = kernel
            .plan_authorization_policy()
            .map_err(|_| SourceExecutionError::InvalidPlan)?;
        let page = kernel
            .decode_authorization_policy(&provider_request, &request.response_body)
            .map_err(|_| SourceExecutionError::MalformedResponse)?;
        if page.next_cursor.is_some() || page.records.len() != 1 {
            return Err(SourceExecutionError::MalformedResponse);
        }

        let provider_record = page
            .records
            .into_iter()
            .next()
            .ok_or(SourceExecutionError::MalformedResponse)?;
        let mut attributes = provider_record.fields;
        attributes.insert("family".to_owned(), provider_record.family);
        attributes.insert(
            "resource_id".to_owned(),
            provider_record.provider_id.clone(),
        );
        let payload_json = serde_json::to_vec(&provider_record.payload)
            .map_err(|_| SourceExecutionError::InternalRuntime)?;
        if plan.required_attributes.iter().any(|required| {
            attributes
                .get(required)
                .is_none_or(|value| value.trim().is_empty())
        }) || plan.required_payload_fields.iter().any(|required| {
            provider_record
                .payload
                .get(required)
                .is_none_or(serde_json::Value::is_null)
        }) {
            return Err(SourceExecutionError::InvalidProviderRecord);
        }

        let event_id = format!("azure-authorization-policy-{}", provider_record.provider_id);
        let records = validate_and_deduplicate_records(vec![SourceWorkerRecordV1 {
            provider_id: provider_record.provider_id,
            attributes: attributes.into_iter().collect(),
            payload_json,
            event_id,
            occurred_at_unix_millis: context.observed_at_unix_millis,
        }])?;
        let result_digest_sha256 = canonical_result_digest(receipt, "", &records)?;

        Ok(SourceWorkerDecodeResultV1 {
            plan_id: plan.plan_id.clone(),
            plan_digest_sha256: plan.plan_digest_sha256.clone(),
            logical_page_id: context.logical_page_id.clone(),
            request_intent_digest: request.request_intent_digest.clone(),
            records,
            next_cursor: String::new(),
            result_digest_sha256,
            tenant_id: context.tenant_id.clone(),
            runtime_id: context.runtime_id.clone(),
            runtime_generation: context.runtime_generation,
            lease_generation: context.lease_generation,
            observed_at_unix_millis: context.observed_at_unix_millis,
        })
    }
}
