use prost::Message;

use super::{
    contract::{
        AUTHORIZATION_POLICY_FALLBACK_ID, AUTHORIZATION_POLICY_FAMILY, AUTHORIZATION_POLICY_KERNEL,
        AUTHORIZATION_POLICY_KIND, AUTHORIZATION_POLICY_PATH, AUTHORIZATION_POLICY_SCHEMA,
        AZURE_SOURCE_ID, MAX_RESPONSE_BYTES, plan_digest,
    },
    decode,
    error::WorkerError,
    plan,
    wire::{
        SourceExecutionPlanV1, SourceWorkerDecodeRequestV1, SourceWorkerDecodeResultV1,
        SourceWorkerHttpRequestV1,
    },
};

const GO_LIVE_TEST_RESPONSE: &[u8] = br#"{
    "id":"authorizationPolicy",
    "allowEmailVerifiedUsersToJoinOrganization":false,
    "allowInvitesFrom":"adminsAndGuestInviters",
    "allowedToSignUpEmailBasedSubscriptions":false,
    "allowedToUseSSPR":true,
    "blockMsolPowerShell":true,
    "defaultUserRolePermissions":{
        "allowedToCreateApps":false,
        "allowedToCreateSecurityGroups":false,
        "allowedToReadBitlockerKeysForOwnedDevice":true,
        "permissionGrantPoliciesAssigned":["ManagePermissionGrantsForSelf.microsoft-user-default-low"]
    }
}"#;

fn exact_plan() -> SourceExecutionPlanV1 {
    let mut plan = SourceExecutionPlanV1 {
        plan_id: "source-plan-v1:azure:authorization_policy".to_owned(),
        source_id: AZURE_SOURCE_ID.to_owned(),
        family_id: AUTHORIZATION_POLICY_FAMILY.to_owned(),
        provider_kernel: AUTHORIZATION_POLICY_KERNEL.to_owned(),
        method: "GET".to_owned(),
        origin: "https://graph.microsoft.com".to_owned(),
        path: AUTHORIZATION_POLICY_PATH.to_owned(),
        record_selector: "$".to_owned(),
        id_field: "id".to_owned(),
        singleton_fallback_id: AUTHORIZATION_POLICY_FALLBACK_ID.to_owned(),
        max_response_bytes: MAX_RESPONSE_BYTES,
        event_kind: AUTHORIZATION_POLICY_KIND.to_owned(),
        schema_ref: AUTHORIZATION_POLICY_SCHEMA.to_owned(),
        required_attributes: vec![
            "resource_id".to_owned(),
            "resource_name".to_owned(),
            "resource_provider".to_owned(),
            "resource_type".to_owned(),
        ],
        required_payload_fields: Vec::new(),
        plan_digest_sha256: String::new(),
    };
    plan.plan_digest_sha256 = plan_digest(&plan);
    plan
}

#[test]
fn plans_exact_credential_free_request() {
    let output = plan(&exact_plan().encode_to_vec()).unwrap();
    let request = SourceWorkerHttpRequestV1::decode(output.as_slice()).unwrap();
    assert_eq!(request.method, "GET");
    assert_eq!(
        request.url,
        "https://graph.microsoft.com/v1.0/policies/authorizationPolicy"
    );
    assert_eq!(request.accept, "application/json");
    assert_eq!(request.max_response_bytes, MAX_RESPONSE_BYTES);
    assert!(!output.windows(6).any(|window| window == b"Bearer"));
}

#[test]
fn decodes_exact_go_response_and_binds_execution_identity() {
    let plan = exact_plan();
    let output = decode(
        &SourceWorkerDecodeRequestV1 {
            plan: Some(plan.clone()),
            status_code: 200,
            response_body: GO_LIVE_TEST_RESPONSE.to_vec(),
            logical_page_id: "page-sha256".to_owned(),
            request_intent_digest: "intent-sha256".to_owned(),
        }
        .encode_to_vec(),
    )
    .unwrap();
    let result = SourceWorkerDecodeResultV1::decode(output.as_slice()).unwrap();
    assert_eq!(result.plan_digest_sha256, plan.plan_digest_sha256);
    assert_eq!(result.logical_page_id, "page-sha256");
    assert_eq!(result.request_intent_digest, "intent-sha256");
    assert_eq!(result.next_cursor, "");
    assert_eq!(result.records.len(), 1);
    let record = &result.records[0];
    assert_eq!(record.provider_id, "authorizationPolicy");
    assert_eq!(
        record.attributes.get("resource_id").map(String::as_str),
        Some("authorizationPolicy")
    );
    assert_eq!(
        record
            .attributes
            .get("default_user_can_read_bitlocker")
            .map(String::as_str),
        Some("true")
    );
    assert_eq!(result.result_digest_sha256.len(), 64);
}

#[test]
fn rejects_tampered_plan_status_oversize_and_missing_identity() {
    let mut tampered = exact_plan();
    tampered.path = "/v1.0/users".to_owned();
    assert_eq!(
        plan(&tampered.encode_to_vec()),
        Err(WorkerError::InvalidPlan)
    );

    let base = SourceWorkerDecodeRequestV1 {
        plan: Some(exact_plan()),
        status_code: 500,
        response_body: b"{}".to_vec(),
        logical_page_id: "page".to_owned(),
        request_intent_digest: "intent".to_owned(),
    };
    assert_eq!(
        decode(&base.encode_to_vec()),
        Err(WorkerError::UnsupportedStatus)
    );
    let mut oversize = base.clone();
    oversize.status_code = 200;
    oversize.response_body = vec![b' '; (MAX_RESPONSE_BYTES + 1) as usize];
    assert_eq!(
        decode(&oversize.encode_to_vec()),
        Err(WorkerError::ResponseTooLarge)
    );
    let mut missing_identity = base;
    missing_identity.status_code = 200;
    missing_identity.logical_page_id.clear();
    assert_eq!(
        decode(&missing_identity.encode_to_vec()),
        Err(WorkerError::MissingExecutionIdentity)
    );
}
