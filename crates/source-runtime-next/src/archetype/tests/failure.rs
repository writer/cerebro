use super::*;
use crate::archetype::adapter::{MAX_ENRICHMENT_RECORDS, MAX_RESPONSE_BYTES};

#[test]
fn observation_fallback_is_deterministic_and_tenant_is_context_bound() {
    let kernel = kernel(ArchetypeFamily::Scan);
    let request = kernel.plan_scans(None).unwrap();
    let page = kernel
        .decode_scans(
            &request,
            br#"[{"id":1,"repository_id":7,"status":"completed","tenant_id":"provider-tenant","api_token":"must-not-flow"}]"#,
        )
        .unwrap();
    let first = kernel
        .scan_record(
            &request,
            &page.scans[0],
            None,
            VulnerabilityCollectionState::NotRequested,
            "2026-08-19T19:00:00-07:00",
        )
        .unwrap();
    let second = kernel
        .scan_record(
            &request,
            &page.scans[0],
            None,
            VulnerabilityCollectionState::NotRequested,
            OBSERVED_AT,
        )
        .unwrap();
    assert_eq!(first.occurred_at, OBSERVED_AT);
    assert_eq!(first.occurred_at, second.occurred_at);
    assert_eq!(first.tenant_id, TENANT_ID);
    assert!(first.payload.get("tenant_id").is_none());
    assert!(first.payload.get("api_token").is_none());
    assert!(!request.url().as_str().contains("must-not-flow"));
    assert!(!ArchetypeKernel::requires_credentials());
}

#[test]
fn invalid_first_provider_timestamp_uses_observation_in_go_precedence_order() {
    let kernel = kernel(ArchetypeFamily::Scan);
    let request = kernel.plan_scans(None).unwrap();
    let page = kernel
        .decode_scans(
            &request,
            br#"[{"id":1,"repository_id":7,"status":"completed","completed_at":"invalid","started_at":"2026-08-20T01:00:00Z"}]"#,
        )
        .unwrap();
    assert_eq!(page.scans[0].occurred_at, None);
    let record = kernel
        .scan_record(
            &request,
            &page.scans[0],
            None,
            VulnerabilityCollectionState::NotRequested,
            OBSERVED_AT,
        )
        .unwrap();
    assert_eq!(record.occurred_at, OBSERVED_AT);
}

#[test]
fn enrichment_timestamps_use_scan_then_explicit_observation_fallback() {
    let kernel = kernel(ArchetypeFamily::Vulnerability);
    let scans = kernel.plan_scans(None).unwrap();
    let scan = kernel
        .decode_scans(
            &scans,
            br#"[{"id":9,"repository_id":7,"status":"completed"}]"#,
        )
        .unwrap()
        .scans
        .remove(0);

    let vulnerabilities = kernel.plan_vulnerabilities(scan.id).unwrap();
    let vulnerability = kernel
        .decode_vulnerabilities(
            &vulnerabilities,
            br#"[{"id":1,"scan_id":9,"file_path":"app.py","category":"ssrf","severity":"high","created_at":"invalid"}]"#,
            &scan,
            None,
            OBSERVED_AT,
        )
        .unwrap()
        .remove(0);
    assert_eq!(vulnerability.occurred_at, OBSERVED_AT);

    let knowledge = kernel.plan_knowledge(scan.repository_id).unwrap();
    let library_note = kernel
        .decode_knowledge(
            &knowledge,
            br#"{"entries":[{"slug":"fallback","title":"title","summary":"summary","owner":"WriterInternal","repository_name":"Archetype"}]}"#,
            &scan,
            None,
            OBSERVED_AT,
        )
        .unwrap()
        .remove(0);
    assert_eq!(library_note.occurred_at, OBSERVED_AT);
}

#[test]
fn materialization_requires_trusted_tenant_and_valid_observation_time() {
    let unbound = ArchetypeKernel::new(
        "https://archetype.example.test",
        None,
        ArchetypeFamily::Scan,
        None,
    )
    .unwrap();
    let request = unbound.plan_scans(None).unwrap();
    let page = unbound
        .decode_scans(
            &request,
            br#"[{"id":1,"repository_id":7,"status":"completed"}]"#,
        )
        .unwrap();
    assert_eq!(
        unbound
            .scan_record(
                &request,
                &page.scans[0],
                None,
                VulnerabilityCollectionState::NotRequested,
                OBSERVED_AT,
            )
            .unwrap_err(),
        ArchetypeError::MissingTenantId
    );

    let bound = unbound.bind_tenant(TENANT_ID).unwrap();
    assert_eq!(
        bound
            .scan_record(
                &request,
                &page.scans[0],
                None,
                VulnerabilityCollectionState::NotRequested,
                "not-a-time",
            )
            .unwrap_err(),
        ArchetypeError::InvalidObservedAt
    );
}

#[test]
fn response_and_record_rejections_are_bounded_and_body_free() {
    let kernel = kernel(ArchetypeFamily::Vulnerability);
    let scans = kernel.plan_scans(None).unwrap();
    assert_eq!(
        kernel
            .decode_scans(&scans, &vec![b' '; MAX_RESPONSE_BYTES + 1])
            .unwrap_err(),
        ArchetypeError::ResponseTooLarge
    );

    let scan = scan(&kernel);
    let knowledge = kernel.plan_knowledge(scan.repository_id).unwrap();
    let entries = (0..=MAX_ENRICHMENT_RECORDS)
        .map(|index| {
            serde_json::json!({
                "slug": format!("note-{index}"),
                "title": "title",
                "summary": "summary",
                "owner": "WriterInternal",
                "repository_name": "Archetype"
            })
        })
        .collect::<Vec<_>>();
    let body = serde_json::to_vec(&serde_json::json!({"entries": entries})).unwrap();
    assert_eq!(
        kernel
            .decode_knowledge(&knowledge, &body, &scan, None, OBSERVED_AT)
            .unwrap_err(),
        ArchetypeError::TooManyRecords
    );

    let marker = "must-not-appear-in-error";
    let error = kernel.decode_scans(&scans, marker.as_bytes()).unwrap_err();
    assert_eq!(error, ArchetypeError::InvalidResponse);
    assert!(!error.to_string().contains(marker));
}

#[test]
fn identical_duplicates_collapse_and_conflicts_fail_closed() {
    let kernel = kernel(ArchetypeFamily::Vulnerability);
    let scans = kernel.plan_scans(None).unwrap();
    let identical = br#"[
        {"id":9,"repository_id":7,"status":"completed"},
        {"id":9,"repository_id":7,"status":"completed"}
    ]"#;
    assert_eq!(
        kernel.decode_scans(&scans, identical).unwrap().scans.len(),
        1
    );
    let conflicting = br#"[
        {"id":9,"repository_id":7,"status":"completed"},
        {"id":9,"repository_id":7,"status":"running"}
    ]"#;
    assert_eq!(
        kernel.decode_scans(&scans, conflicting).unwrap_err(),
        ArchetypeError::DuplicateRecordIdentity
    );

    let scan = scan(&kernel);
    let vulnerabilities = kernel.plan_vulnerabilities(scan.id).unwrap();
    let duplicate_vulnerability = br#"[
        {"id":1,"scan_id":9,"file_path":"app.py","category":"ssrf","severity":"high"},
        {"id":1,"scan_id":9,"file_path":"app.py","category":"ssrf","severity":"high"}
    ]"#;
    assert_eq!(
        kernel
            .decode_vulnerabilities(
                &vulnerabilities,
                duplicate_vulnerability,
                &scan,
                None,
                OBSERVED_AT,
            )
            .unwrap()
            .len(),
        1
    );
    let conflicting_vulnerability = br#"[
        {"id":1,"scan_id":9,"file_path":"app.py","category":"ssrf","severity":"high"},
        {"id":1,"scan_id":9,"file_path":"app.py","category":"ssrf","severity":"critical"}
    ]"#;
    assert_eq!(
        kernel
            .decode_vulnerabilities(
                &vulnerabilities,
                conflicting_vulnerability,
                &scan,
                None,
                OBSERVED_AT,
            )
            .unwrap_err(),
        ArchetypeError::DuplicateRecordIdentity
    );

    let repositories = kernel.plan_repositories().unwrap();
    let duplicate_repository = br#"[
        {"id":7,"owner":"WriterInternal","name":"Archetype"},
        {"id":7,"owner":"WriterInternal","name":"Archetype"}
    ]"#;
    assert_eq!(
        kernel
            .decode_repositories(&repositories, duplicate_repository)
            .unwrap()
            .len(),
        1
    );
    let conflicting_repository = br#"[
        {"id":7,"owner":"WriterInternal","name":"Archetype"},
        {"id":7,"owner":"Other","name":"Archetype"}
    ]"#;
    assert_eq!(
        kernel
            .decode_repositories(&repositories, conflicting_repository)
            .unwrap_err(),
        ArchetypeError::DuplicateRecordIdentity
    );

    let knowledge = kernel.plan_knowledge(scan.repository_id).unwrap();
    let duplicate_note = br#"{"entries":[
        {"slug":"one","title":"title","summary":"summary","owner":"WriterInternal","repository_name":"Archetype"},
        {"slug":"one","title":"title","summary":"summary","owner":"WriterInternal","repository_name":"Archetype"}
    ]}"#;
    assert_eq!(
        kernel
            .decode_knowledge(&knowledge, duplicate_note, &scan, None, OBSERVED_AT)
            .unwrap()
            .len(),
        1
    );
    let conflicting_note = br#"{"entries":[
        {"slug":"one","title":"title","summary":"summary","owner":"WriterInternal","repository_name":"Archetype"},
        {"slug":"one","title":"different","summary":"summary","owner":"WriterInternal","repository_name":"Archetype"}
    ]}"#;
    assert_eq!(
        kernel
            .decode_knowledge(&knowledge, conflicting_note, &scan, None, OBSERVED_AT)
            .unwrap_err(),
        ArchetypeError::DuplicateRecordIdentity
    );
}

#[test]
fn library_note_required_payload_fields_fail_closed() {
    let kernel = kernel(ArchetypeFamily::Vulnerability);
    let scan = scan(&kernel);
    let request = kernel.plan_knowledge(scan.repository_id).unwrap();
    for missing in ["title", "summary"] {
        let mut entry = serde_json::json!({
            "slug": "required-fields",
            "title": "title",
            "summary": "summary",
            "owner": "WriterInternal",
            "repository_name": "Archetype"
        });
        entry[missing] = serde_json::Value::String(" ".to_owned());
        let body = serde_json::to_vec(&serde_json::json!({"entries": [entry]})).unwrap();
        assert_eq!(
            kernel
                .decode_knowledge(&request, &body, &scan, None, OBSERVED_AT)
                .unwrap_err(),
            ArchetypeError::InvalidResponse,
            "required payload field {missing}"
        );
    }
}

#[test]
fn library_note_metadata_rejects_credential_shaped_fields_without_echoing_values() {
    let kernel = kernel(ArchetypeFamily::Vulnerability);
    let scan = scan(&kernel);
    let request = kernel.plan_knowledge(scan.repository_id).unwrap();
    let marker = "must-not-flow-through-library-note";
    let body = serde_json::to_vec(&serde_json::json!({
        "entries": [{
            "slug": "credential-shaped-metadata",
            "title": "title",
            "summary": "summary",
            "owner": "WriterInternal",
            "repository_name": "Archetype",
            "metadata": {"nested": {"apiToken": marker}}
        }]
    }))
    .unwrap();
    let error = kernel
        .decode_knowledge(&request, &body, &scan, None, OBSERVED_AT)
        .unwrap_err();
    assert_eq!(error, ArchetypeError::SecretFieldRejected);
    assert!(!error.to_string().contains(marker));
}
