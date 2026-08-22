use super::{PARITY_FIXTURE, PROVIDER_FIXTURE, kernel, linode, observed_at};

#[test]
fn parity_fixture_matches_go_identity_attributes_payload_and_time() {
    let kernel = kernel();
    let page = kernel
        .decode(&kernel.plan(None).unwrap(), PARITY_FIXTURE, observed_at())
        .unwrap();
    assert_eq!(page.next_cursor.as_deref(), Some("2"));
    assert_eq!(page.total_results, 101);
    assert_eq!(page.records.len(), 1);
    let record = &page.records[0];
    assert_eq!(record.family, "issue");
    assert_eq!(record.provider_kind, "linode.issue");
    assert_eq!(record.schema_ref, "linode/issue/v1");
    assert_eq!(record.tenant_id, "tenant");
    assert_eq!(record.provider_id, "823");
    assert_eq!(record.event_id, "linode-tenant-c9ca572ccbf1-issue-823");
    assert_eq!(record.occurred_at, "2026-06-01T00:00:00Z");
    for (name, value) in [
        ("external_id", "823"),
        ("finding_id", "823"),
        ("record_class", "finding"),
        ("resource_urn", "urn:cerebro:tenant:linode_issue:823"),
        ("severity", "medium"),
        ("source_event_id", "823"),
        ("status", "open"),
        ("tenant_id", "tenant"),
    ] {
        assert_eq!(record.fields.get(name).map(String::as_str), Some(value));
    }
    assert_eq!(record.payload["id"], 823);
    assert_eq!(record.payload["tenant_id"], "tenant");
}

#[test]
fn official_provider_shape_is_rejected_at_the_catalog_boundary() {
    let kernel = kernel();
    assert_eq!(
        kernel
            .decode(&kernel.plan(None).unwrap(), PROVIDER_FIXTURE, observed_at())
            .unwrap_err(),
        linode::LinodeError::MissingRequiredAttribute("resource_urn")
    );
}

#[test]
fn authenticated_tenant_overrides_untrusted_provider_tenant() {
    let body = br#"{
        "data":[{
            "id":823,
            "resource_urn":"urn:cerebro:tenant:linode_issue:823",
            "severity":"medium",
            "status":"open",
            "tenant_id":"other-tenant",
            "metadata":{"tenant_id":"another-tenant"}
        }],
        "page":1,
        "pages":1,
        "results":1
    }"#;
    let kernel = kernel();
    let page = kernel
        .decode(&kernel.plan(None).unwrap(), body, observed_at())
        .unwrap();
    assert_eq!(page.records[0].tenant_id, "tenant");
    assert_eq!(page.records[0].fields["tenant_id"], "tenant");
}
