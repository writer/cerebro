use std::collections::HashMap;

use serde_json::Value;

use crate::source_execution::{
    SourceExecutionAdapter, SourceExecutionDispatcher, SourceExecutionError,
    SourceExecutionSelectionRequestV1, SourceWorkerDecodeEnvelopeV2, SourceWorkerDecodeRequestV1,
    SourceWorkerExecutionContextV1, SourceWorkerPlanEnvelopeV2, SourceWorkerPlanRequestV1,
    SourceWorkerRuntimeMetadataV2, SourceWorkerSafeReceiptV1, response_digest,
};

use super::catalog::{ANTHROPIC_SOURCE_EXECUTION_ADAPTERS, DEFAULT_BASE_URL};
use crate::anthropic::{AnthropicAuthentication, AnthropicFamily};

const OBSERVED_AT_MILLIS: i64 = 1_780_272_000_000;

fn context(cursor: &str, page: u32) -> SourceWorkerExecutionContextV1 {
    SourceWorkerExecutionContextV1 {
        tenant_id: "tenant".to_owned(),
        runtime_id: "anthropic-runtime".to_owned(),
        logical_page_id: format!("source-page-v2:anthropic-{page}"),
        prior_cursor: cursor.to_owned(),
        runtime_generation: 7,
        lease_generation: 11,
        observed_at_unix_millis: OBSERVED_AT_MILLIS,
    }
}

fn metadata(family: AnthropicFamily) -> SourceWorkerRuntimeMetadataV2 {
    let mut public_config = HashMap::from([
        ("family".to_owned(), family.as_str().to_owned()),
        ("per_page".to_owned(), "2".to_owned()),
    ]);
    for parameter in family.path_parameters() {
        public_config.insert((*parameter).to_owned(), format!("{parameter}-1"));
    }
    SourceWorkerRuntimeMetadataV2 {
        public_config,
        prior_terminal_watermark_unix_millis: 0,
        prior_checkpoint: String::new(),
    }
}

fn adapter(family: AnthropicFamily) -> &'static super::AnthropicSourceExecutionAdapter {
    ANTHROPIC_SOURCE_EXECUTION_ADAPTERS
        .iter()
        .find(|adapter| adapter.family() == family)
        .expect("Anthropic adapter")
}

#[test]
fn provider_local_catalog_compiles_every_anthropic_family_without_authority() {
    assert_eq!(
        ANTHROPIC_SOURCE_EXECUTION_ADAPTERS.len(),
        AnthropicFamily::ALL.len()
    );
    for family in AnthropicFamily::ALL {
        let adapter = adapter(family);
        let plan = adapter.compiled_plan();
        assert_eq!(plan.source_id, "anthropic");
        assert_eq!(plan.family_id, family.as_str());
        assert_eq!(plan.provider_kernel, family.as_str());
        assert_eq!(plan.origin, DEFAULT_BASE_URL);
        assert_eq!(plan.path, format!("/v1{}", family.path()));
        assert_eq!(plan.id_field, family.id_paths().join("|"));
        assert_eq!(plan.event_kind, family.provider_kind());
        assert_eq!(plan.schema_ref, family.schema_ref());
        assert!(plan.required_attributes.contains(&"external_id".to_owned()));
        assert!(plan.required_attributes.contains(&"family".to_owned()));

        assert_eq!(
            SourceExecutionDispatcher.compile_plan(&SourceExecutionSelectionRequestV1 {
                source_id: "anthropic".to_owned(),
                family_id: family.as_str().to_owned(),
            }),
            Err(SourceExecutionError::UnknownAdapter),
            "{} must remain outside shared authority",
            family.as_str()
        );
    }
}

#[test]
fn every_family_plans_one_origin_restricted_credential_free_request() {
    for family in AnthropicFamily::ALL {
        let adapter = adapter(family);
        let plan = adapter.compiled_plan();
        let mut metadata = metadata(family);
        if family
            .query_parameters()
            .iter()
            .any(|(_, name)| *name == "models")
        {
            metadata
                .public_config
                .insert("models".to_owned(), "model-a,model-b".to_owned());
        }
        let execution = adapter
            .plan_v2(&SourceWorkerPlanEnvelopeV2 {
                request: Some(SourceWorkerPlanRequestV1 {
                    plan: Some(plan),
                    context: Some(context("", 1)),
                }),
                metadata: Some(metadata),
            })
            .unwrap_or_else(|error| panic!("{} plan: {error}", family.as_str()));
        assert_eq!(execution.allowed_origin, "https://api.anthropic.com");
        assert!(execution.body.is_empty());
        assert_eq!(
            execution.declared_headers.get("anthropic-version"),
            Some(&"2023-06-01".to_owned())
        );
        assert_eq!(
            execution.credential_operation,
            match family.authentication() {
                AnthropicAuthentication::AdminKeyOrOrgAdminBearer => {
                    "anthropic.admin_x_api_key"
                }
                AnthropicAuthentication::OrgAdminBearer => "anthropic.org_admin_bearer",
                AnthropicAuthentication::ComplianceAccessKey => {
                    "anthropic.compliance_x_api_key"
                }
            }
        );
        let request = execution.request.expect("planned request");
        assert_eq!(request.method, "GET");
        assert!(request.url.starts_with(DEFAULT_BASE_URL));
        let url = reqwest::Url::parse(&request.url).expect("planned URL");
        assert!(url.username().is_empty());
        assert!(url.password().is_none());
        assert!(url.query_pairs().all(|(key, _)| !matches!(
            key.as_ref(),
            "api_key" | "api_token" | "access_token" | "token"
        )));
    }
}

#[test]
fn auth_model_is_explicit_and_family_scoped() {
    let user = adapter(AnthropicFamily::User);
    let user_plan = user.compiled_plan();
    let mut bearer = metadata(AnthropicFamily::User);
    bearer
        .public_config
        .insert("auth_model".to_owned(), "bearer_token".to_owned());
    let execution = user
        .plan_v2(&SourceWorkerPlanEnvelopeV2 {
            request: Some(SourceWorkerPlanRequestV1 {
                plan: Some(user_plan),
                context: Some(context("", 1)),
            }),
            metadata: Some(bearer),
        })
        .unwrap();
    assert_eq!(execution.credential_operation, "anthropic.org_admin_bearer");

    let compliance = adapter(AnthropicFamily::ComplianceActivity);
    let mut invalid = metadata(AnthropicFamily::ComplianceActivity);
    invalid
        .public_config
        .insert("auth_model".to_owned(), "bearer_token".to_owned());
    assert_eq!(
        compliance.plan_v2(&SourceWorkerPlanEnvelopeV2 {
            request: Some(SourceWorkerPlanRequestV1 {
                plan: Some(compliance.compiled_plan()),
                context: Some(context("", 1)),
            }),
            metadata: Some(invalid),
        }),
        Err(SourceExecutionError::MissingConfiguration)
    );
}

#[test]
fn user_decode_preserves_cursor_identity_and_provider_failures() {
    let adapter = adapter(AnthropicFamily::User);
    let plan = adapter.compiled_plan();
    let context = context("", 1);
    let metadata = metadata(AnthropicFamily::User);
    let execution = adapter
        .plan_v2(&SourceWorkerPlanEnvelopeV2 {
            request: Some(SourceWorkerPlanRequestV1 {
                plan: Some(plan.clone()),
                context: Some(context.clone()),
            }),
            metadata: Some(metadata.clone()),
        })
        .unwrap();
    let planned = execution.request.as_ref().unwrap();
    let body = br#"{"data":[{"id":"user_1","email":"person@example.test","role":"admin","status":"active"}],"has_more":true,"last_id":"user_1"}"#;
    let receipt = SourceWorkerSafeReceiptV1 {
        plan_digest_sha256: plan.plan_digest_sha256.clone(),
        logical_page_id: context.logical_page_id.clone(),
        request_intent_digest: planned.request_intent_digest.clone(),
        runtime_generation: context.runtime_generation,
        lease_generation: context.lease_generation,
        credential_operation: execution.credential_operation.clone(),
        status_code: 200,
        response_bytes: body.len() as u64,
        response_sha256: response_digest(body),
        tenant_id: context.tenant_id.clone(),
        runtime_id: context.runtime_id.clone(),
        observed_at_unix_millis: context.observed_at_unix_millis,
    };
    let result = adapter
        .decode_v2(&SourceWorkerDecodeEnvelopeV2 {
            request: Some(SourceWorkerDecodeRequestV1 {
                plan: Some(plan.clone()),
                status_code: 200,
                response_body: body.to_vec(),
                logical_page_id: context.logical_page_id.clone(),
                request_intent_digest: planned.request_intent_digest.clone(),
                receipt: Some(receipt),
                context: Some(context.clone()),
            }),
            metadata: Some(metadata.clone()),
            response_headers: HashMap::new(),
            response_headers_sha256: String::new(),
            execution_intent_digest_sha256: execution.execution_intent_digest_sha256,
        })
        .unwrap();
    assert_eq!(result.next_cursor, "user_1");
    assert_eq!(result.records.len(), 1);
    let record = &result.records[0];
    assert_eq!(record.provider_id, "user_1");
    assert_eq!(record.attributes["user_id"], "user_1");
    assert_eq!(record.attributes["source_provider"], "anthropic");
    adapter
        .validate_record_identity_v2(&context, record, &metadata)
        .unwrap();
    let payload: Value = serde_json::from_slice(&record.payload_json).unwrap();
    assert_eq!(payload["id"], "user_1");

    for (status, expected) in [
        (401, SourceExecutionError::AuthenticationRejected),
        (403, SourceExecutionError::RequiredProviderScopeMissing),
        (429, SourceExecutionError::ProviderRateLimit),
        (503, SourceExecutionError::UnexpectedProviderStatus),
    ] {
        let receipt = SourceWorkerSafeReceiptV1 {
            plan_digest_sha256: plan.plan_digest_sha256.clone(),
            logical_page_id: context.logical_page_id.clone(),
            request_intent_digest: planned.request_intent_digest.clone(),
            runtime_generation: context.runtime_generation,
            lease_generation: context.lease_generation,
            credential_operation: execution.credential_operation.clone(),
            status_code: status,
            response_bytes: 2,
            response_sha256: response_digest(b"{}"),
            tenant_id: context.tenant_id.clone(),
            runtime_id: context.runtime_id.clone(),
            observed_at_unix_millis: context.observed_at_unix_millis,
        };
        assert_eq!(
            adapter.decode_v2(&SourceWorkerDecodeEnvelopeV2 {
                request: Some(SourceWorkerDecodeRequestV1 {
                    plan: Some(plan.clone()),
                    status_code: status,
                    response_body: b"{}".to_vec(),
                    logical_page_id: context.logical_page_id.clone(),
                    request_intent_digest: planned.request_intent_digest.clone(),
                    receipt: Some(receipt),
                    context: Some(context.clone()),
                }),
                metadata: Some(metadata.clone()),
                response_headers: HashMap::new(),
                response_headers_sha256: String::new(),
                execution_intent_digest_sha256: String::new(),
            }),
            Err(expected)
        );
    }
}

#[test]
fn base_url_family_path_scope_and_identity_fail_closed() {
    let user = adapter(AnthropicFamily::User);
    let mut wrong_origin = metadata(AnthropicFamily::User);
    wrong_origin.public_config.insert(
        "base_url".to_owned(),
        "https://example.invalid/v1".to_owned(),
    );
    assert_eq!(
        user.plan_v2(&SourceWorkerPlanEnvelopeV2 {
            request: Some(SourceWorkerPlanRequestV1 {
                plan: Some(user.compiled_plan()),
                context: Some(context("", 1)),
            }),
            metadata: Some(wrong_origin),
        }),
        Err(SourceExecutionError::MissingConfiguration)
    );

    let member = adapter(AnthropicFamily::WorkspaceMember);
    let missing_scope = SourceWorkerRuntimeMetadataV2 {
        public_config: HashMap::from([("family".to_owned(), "workspace_member".to_owned())]),
        prior_terminal_watermark_unix_millis: 0,
        prior_checkpoint: String::new(),
    };
    assert_eq!(
        member.plan_v2(&SourceWorkerPlanEnvelopeV2 {
            request: Some(SourceWorkerPlanRequestV1 {
                plan: Some(member.compiled_plan()),
                context: Some(context("", 1)),
            }),
            metadata: Some(missing_scope),
        }),
        Err(SourceExecutionError::MissingConfiguration)
    );
}
