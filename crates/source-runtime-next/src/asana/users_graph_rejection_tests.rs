use cerebro_organizational_model::{CollectionId, CollectionReceipt, SourceRuntimeId, TenantId};

use crate::asana_users_graph_batch;

use super::{AsanaError, users_test_support as support};

#[test]
fn asana_users_graph_input_rejects_tenant_scope_and_result_tampering() {
    let output = support::decoded_page("tenant-a", "", 1, support::USERS_PAGE_1);
    assert_eq!(
        asana_users_graph_batch(
            support::collection_receipt("tenant-b", "asana-users-wrong-tenant"),
            &output,
        ),
        Err(AsanaError::EventContractRejection)
    );
    let wrong_scope = CollectionReceipt::incremental(
        TenantId::parse("tenant-a").unwrap(),
        SourceRuntimeId::parse("asana-users-runtime").unwrap(),
        CollectionId::parse("asana-users-wrong-scope").unwrap(),
        "asana.projects",
        support::OBSERVED_AT_MILLIS,
    )
    .unwrap();
    assert_eq!(
        asana_users_graph_batch(wrong_scope, &output),
        Err(AsanaError::EventContractRejection)
    );

    let mut tampered = output;
    tampered.result.as_mut().unwrap().records[0]
        .attributes
        .insert("user_id".to_owned(), "other-user".to_owned());
    reseal_result(&mut tampered);
    assert_eq!(
        asana_users_graph_batch(
            support::collection_receipt("tenant-a", "asana-users-tampered"),
            &tampered,
        ),
        Err(AsanaError::EventContractRejection)
    );

    let mut credential_shaped = support::decoded_page("tenant-a", "", 1, support::USERS_PAGE_1);
    let record = &mut credential_shaped.result.as_mut().unwrap().records[0];
    let mut payload: serde_json::Value = serde_json::from_slice(&record.payload_json).unwrap();
    payload["profile"] = serde_json::json!({"access_token": "secret-sentinel"});
    record.payload_json = serde_json::to_vec(&payload).unwrap();
    reseal_result(&mut credential_shaped);
    assert_eq!(
        asana_users_graph_batch(
            support::collection_receipt("tenant-a", "asana-users-credential-shaped"),
            &credential_shaped,
        ),
        Err(AsanaError::CredentialMaterial)
    );
}

fn reseal_result(output: &mut crate::source_execution::SourceWorkerDecodeOutputV2) {
    let recomputed_digest = crate::source_execution::canonical_result_digest(
        output.receipt.as_ref().unwrap(),
        &output.result.as_ref().unwrap().next_cursor,
        &output.result.as_ref().unwrap().records,
    )
    .unwrap();
    output.result.as_mut().unwrap().result_digest_sha256 = recomputed_digest;
}
