use super::*;

#[test]
fn provider_local_adapter_matches_go_event_semantics() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/go_parity.json")).unwrap();
    let kernel = ArchetypeKernel::new(
        "https://archetype.example.test",
        None,
        ArchetypeFamily::Vulnerability,
        None,
    )
    .unwrap()
    .bind_tenant(fixture["tenant_id"].as_str().unwrap())
    .unwrap();
    let observed_at = fixture["observed_at"].as_str().unwrap();

    let scan_request = kernel.plan_scans(None).unwrap();
    let scan_body = serde_json::to_vec(&fixture["scans"]).unwrap();
    let page = kernel.decode_scans(&scan_request, &scan_body).unwrap();
    let repository_request = kernel.plan_repositories().unwrap();
    let repository_body = serde_json::to_vec(&fixture["repositories"]).unwrap();
    let repositories = kernel
        .decode_repositories(&repository_request, &repository_body)
        .unwrap();
    let scan = &page.scans[0];
    let repository = repositories.get(&scan.repository_id).unwrap();

    let scan_record = kernel
        .scan_record(
            &scan_request,
            scan,
            Some(repository),
            VulnerabilityCollectionState::Complete,
            observed_at,
        )
        .unwrap();
    assert_record(&scan_record, &fixture["expected"]["scan"]);

    let vulnerability_request = kernel.plan_vulnerabilities(scan.id).unwrap();
    let vulnerability_body = serde_json::to_vec(&fixture["vulnerabilities"]).unwrap();
    let vulnerability_records = kernel
        .decode_vulnerabilities(
            &vulnerability_request,
            &vulnerability_body,
            scan,
            Some(repository),
            observed_at,
        )
        .unwrap();
    assert_record(
        &vulnerability_records[0],
        &fixture["expected"]["vulnerability"],
    );

    let knowledge_request = kernel.plan_knowledge(scan.repository_id).unwrap();
    let knowledge_body = serde_json::to_vec(&fixture["knowledge"]).unwrap();
    let library_records = kernel
        .decode_knowledge(
            &knowledge_request,
            &knowledge_body,
            scan,
            Some(repository),
            observed_at,
        )
        .unwrap();
    assert_record(&library_records[0], &fixture["expected"]["library_note"]);
}

fn assert_record(record: &ArchetypeRecord, expected: &serde_json::Value) {
    assert_eq!(record.tenant_id, TENANT_ID);
    assert_eq!(record.source_id, "archetype");
    assert_eq!(record.family, expected_string(expected, "family"));
    assert_eq!(
        record.provider_kind,
        expected_string(expected, "provider_kind")
    );
    assert_eq!(record.schema_ref, expected_string(expected, "schema_ref"));
    assert_eq!(record.provider_id, expected_string(expected, "event_id"));
    assert_eq!(record.event_id, expected_string(expected, "event_id"));
    assert_eq!(
        record.request_kind,
        expected_string(expected, "request_kind")
    );
    assert_eq!(
        record.request_path,
        expected_string(expected, "request_path")
    );
    assert_eq!(record.occurred_at, expected_string(expected, "occurred_at"));
    assert_eq!(
        serde_json::to_value(&record.fields).unwrap(),
        expected["fields"]
    );
    assert_eq!(record.payload, expected["payload"]);
}

fn expected_string<'a>(expected: &'a serde_json::Value, field: &str) -> &'a str {
    expected[field].as_str().unwrap()
}
