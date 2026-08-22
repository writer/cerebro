use super::*;

#[test]
fn plans_the_go_pull_routes_without_credentials() {
    let kernel = ArchetypeKernel::new(
        "https://archetype.example.test",
        Some("/api/v1/"),
        ArchetypeFamily::Vulnerability,
        Some(16),
    )
    .unwrap();
    let scans = kernel.plan_scans(Some(106)).unwrap();
    assert_eq!(scans.url().path(), "/api/v1/scans");
    assert_eq!(scans.url().query(), Some("limit=100&before_id=106"));
    assert_eq!(scans.authorization_scheme(), "Bearer");
    assert_eq!(scans.accept(), "application/json");
    assert!(!ArchetypeKernel::requires_credentials());
    assert_eq!(kernel.fanout_concurrency(), 16);
    assert_eq!(
        kernel.plan_repositories().unwrap().url().path(),
        "/api/v1/repositories"
    );
    assert_eq!(
        kernel.plan_vulnerabilities(9).unwrap().url().path(),
        "/api/v1/scans/9/vulnerabilities"
    );
    assert_eq!(
        kernel.plan_knowledge(7).unwrap().url().path(),
        "/api/v1/repositories/7/knowledge"
    );
}

#[test]
fn request_provenance_rejects_family_path_and_query_drift() {
    let kernel = kernel(ArchetypeFamily::Vulnerability);
    let scan = scan(&kernel);

    let mut wrong_family = kernel.plan_scans(None).unwrap();
    wrong_family.family = ArchetypeFamily::Scan;
    assert_eq!(
        kernel.decode_scans(&wrong_family, b"[]").unwrap_err(),
        ArchetypeError::RequestScopeMismatch
    );

    let mut wrong_query = kernel.plan_scans(None).unwrap();
    wrong_query.url.set_query(Some("limit=99"));
    assert_eq!(
        kernel.decode_scans(&wrong_query, b"[]").unwrap_err(),
        ArchetypeError::RequestScopeMismatch
    );

    let mut extra_query = kernel.plan_vulnerabilities(scan.id).unwrap();
    extra_query.url.set_query(Some("token=not-a-credential"));
    assert_eq!(
        kernel
            .decode_vulnerabilities(&extra_query, b"[]", &scan, None, OBSERVED_AT)
            .unwrap_err(),
        ArchetypeError::RequestScopeMismatch
    );
}

#[test]
fn cursor_inputs_are_positive_and_go_int64_round_trippable() {
    let kernel = kernel(ArchetypeFamily::Scan);
    for invalid in [0, (i64::MAX as u64) + 1] {
        assert_eq!(
            kernel.plan_scans(Some(invalid)).unwrap_err(),
            ArchetypeError::InvalidScopedId
        );
    }
    let request = kernel.plan_scans(Some(i64::MAX as u64)).unwrap();
    assert_eq!(
        request.url().query(),
        Some("limit=100&before_id=9223372036854775807")
    );
}

#[test]
fn scan_materialization_is_bound_to_the_exact_collection_request() {
    let kernel = kernel(ArchetypeFamily::Scan);
    let first_request = kernel.plan_scans(None).unwrap();
    let scan = kernel
        .decode_scans(
            &first_request,
            br#"[{"id":1,"repository_id":7,"status":"completed"}]"#,
        )
        .unwrap()
        .scans
        .remove(0);
    let continuation_request = kernel.plan_scans(Some(2)).unwrap();
    assert_eq!(
        kernel
            .scan_record(
                &continuation_request,
                &scan,
                None,
                VulnerabilityCollectionState::NotRequested,
                OBSERVED_AT,
            )
            .unwrap_err(),
        ArchetypeError::RequestScopeMismatch
    );
}

#[test]
fn rejects_invalid_configuration_and_cross_kernel_requests() {
    assert_eq!(
        ArchetypeKernel::new(
            "http://archetype.example.test",
            None,
            ArchetypeFamily::Scan,
            None,
        )
        .unwrap_err(),
        ArchetypeError::InvalidBaseUrl
    );
    assert_eq!(
        ArchetypeKernel::new(
            "https://archetype.example.test",
            Some("api/v1"),
            ArchetypeFamily::Scan,
            None,
        )
        .unwrap_err(),
        ArchetypeError::InvalidApiPrefix
    );
    assert_eq!(
        ArchetypeKernel::new(
            "https://archetype.example.test",
            Some("/api/%2e%2e/private"),
            ArchetypeFamily::Scan,
            None,
        )
        .unwrap_err(),
        ArchetypeError::InvalidApiPrefix
    );
    assert_eq!(
        ArchetypeKernel::new(
            "https://archetype.example.test",
            None,
            ArchetypeFamily::Scan,
            Some(17),
        )
        .unwrap_err(),
        ArchetypeError::InvalidFanoutConcurrency
    );
    let scan_kernel = kernel(ArchetypeFamily::Scan);
    assert_eq!(
        scan_kernel.plan_vulnerabilities(1).unwrap_err(),
        ArchetypeError::UnsupportedEnrichment
    );
    let other = ArchetypeKernel::new(
        "https://other.example.test",
        None,
        ArchetypeFamily::Scan,
        None,
    )
    .unwrap();
    let request = other.plan_scans(None).unwrap();
    assert_eq!(
        scan_kernel.decode_scans(&request, b"[]").unwrap_err(),
        ArchetypeError::RequestScopeMismatch
    );
}
