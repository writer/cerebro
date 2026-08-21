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
